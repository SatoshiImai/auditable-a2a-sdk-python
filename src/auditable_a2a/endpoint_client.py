"""The Server Agent's side of the audit endpoint (§6), as an a-MCP `AuditTransport`.

One submission is outstanding at a time and each POST is bounded (§6.8). The HTTP client is injected as a `Post`;
`auditable_a2a.httpx_post` provides one.
"""

import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, Literal

import anyio
from auditable_mcp import (
    SPEC_VERSION,
    WIRE,
    AttemptResponse,
    AuditCapability,
    NegotiationResult,
    SessionNumbering,
    negotiate,
    unavailable,
)
from pydantic import TypeAdapter, ValidationError

from auditable_a2a.models import AuthenticationInfo, Countersign, Level, SessionPosition
from auditable_a2a.self_ledger import JournalEntry, SelfLedgerError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS: Final = 10.0

Post = Callable[[str, dict[str, str], bytes], Awaitable[tuple[int, bytes]]]
"""POST `body` to `url` with `headers`, following no redirect; return the status and the body.

It raises when nothing was answered (`OSError` by convention; any exception is read so). The client bounds the
wait itself.
"""

Journal = Callable[[JournalEntry], Awaitable[None]]
"""Write an entry to the Server Agent's own ledger (§5.5); it raises `SelfLedgerError` when it was not written."""

_RESPONSE: Final = TypeAdapter(AttemptResponse)


@dataclass(frozen=True)
class RecordFailure:
    """Why the last attempt or position request was not answered as it should have been (§7.3)."""

    http_status: int | None = None
    """The HTTP status the endpoint answered with, when it answered (`httpStatus`)."""
    host_reason: str | None = None
    """The `reason` the audit host gave with a `reject` or `unavailable` (`hostReason`)."""
    attempt_id: str | None = None
    """The `id` of the attempt the failure is about (`attemptId`); None for a position request."""
    # end class


class AuditEndpointClient:
    """The Server Agent's client of one session's audit endpoint (§6)."""

    def __init__(
        self,
        *,
        url: str,
        authentication: AuthenticationInfo,
        task_id: str,
        level: Level,
        countersign: Countersign,
        post: Post,
        token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        journal: Journal | None = None,
        numbering: SessionNumbering | None = None,
    ) -> None:
        """Bind the client to one session's endpoint and credentials.

        Args:
            url: The audit endpoint (§7.1).
            authentication: The credentials issued for the session.
            task_id: The Task every submission carries (§6.1).
            level: The session's level (§4.3), for `negotiate`.
            countersign: The session's countersignature setting, for `negotiate`.
            post: The HTTP POST, which follows no redirect.
            token: The endpoint's token, when the Client declared one.
            timeout: The bound on each POST, in seconds (§6.8).
            journal: Writes to the Server Agent's own ledger, for a Task it may resume (§5.5).
            numbering: The session's `signer_seq` numbering, for a session resumed after a restart (a-MCP
                §7.4). a-MCP's `AmcpSession` numbers with it when present.
        """
        self._url = url
        self._authentication = authentication
        self._token = token
        self._task_id = task_id
        self._host = AuditCapability.model_validate(
            {'spec_version': SPEC_VERSION, 'level': level, 'attempt': 'request', 'countersign': countersign}
        )
        self._post_once = post
        self._timeout = timeout
        self._lock = anyio.Lock()
        self._owed: list[dict[str, object]] = []
        self._last_failure: RecordFailure | None = None
        # Per event id, so a hold names its own submission's failure (§7.3); an attempt and its outcome share an id.
        self._attempt_failures: dict[str, RecordFailure] = {}
        self._outcome_failures: dict[str, RecordFailure] = {}
        self._outcomes: set[str] = set()
        self._journal = journal
        # Shared with a-MCP's `AmcpSession`, so an outcome the Task emits itself joins the same `signer_seq` sequence.
        self.numbering = numbering if numbering is not None else SessionNumbering()
        self._sent_attempts: dict[str, dict[str, object]] = {}
        # end def

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """The comparison a-MCP's tool side makes, against the session negotiated in A2A (§4.3)."""
        return negotiate(self._host, offered)
        # end def

    @property
    def last_failure(self) -> RecordFailure | None:
        """Why the last attempt or position request failed, or None after one that succeeded (§7.3)."""
        return self._last_failure
        # end def

    def attempt_failure_of(self, event_id: str) -> RecordFailure | None:
        """Why the attempt `event_id` was not recorded, or None once it was accepted."""
        return self._attempt_failures.get(event_id)
        # end def

    def outcome_failure_of(self, event_id: str) -> RecordFailure | None:
        """Why the outcome of `event_id` was last not acknowledged, or None once it was."""
        return self._outcome_failures.get(event_id)
        # end def

    def sent_attempt(self, event_id: str) -> dict[str, object] | None:
        """The attempt `event_id` as it was handed to the transport, or None if it never was."""
        return self._sent_attempts.get(event_id)
        # end def

    def has_outcome(self, event_id: str) -> bool:
        """Whether the outcome of `event_id` was sent, and is acknowledged or owed (§6.4)."""
        return event_id in self._outcomes
        # end def

    @property
    def owed(self) -> list[dict[str, object]]:
        """The outcomes not yet acknowledged, in the order they were emitted (§6.4)."""
        return list(self._owed)
        # end def

    def replace_credentials(self, authentication: AuthenticationInfo, token: str | None = None) -> None:
        """Replace the endpoint's credentials, as `auditCredentials` or a renewal does (§5.7)."""
        self._authentication = authentication
        self._token = token
        # end def

    async def send_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Send an attempt and read its answer; anything but a valid Attempt Response is `unavailable` (§6.2)."""
        async with self._lock:
            await self._write({'entry': 'sent', 'event': event})
            return await self._attempt(event)
            # end async with
        # end def

    async def send_outcome(self, event: dict[str, object]) -> None:
        """Send an outcome; one not acknowledged is kept owed and resent by `flush` (§6.4)."""
        async with self._lock:
            await self._write({'entry': 'sent', 'event': event})
            self._outcomes.add(str(event['id']))
            await self._outcome(event)
            # end async with
        # end def

    async def resend_attempt(self, event: dict[str, object]) -> AttemptResponse:
        """Resend, byte for byte, an attempt the own ledger already holds as sent (§5.5 step 2)."""
        async with self._lock:
            return await self._attempt(event)
            # end async with
        # end def

    async def resend_outcome(self, event: dict[str, object]) -> None:
        """Resend, byte for byte, an outcome the own ledger already holds as sent (§5.5 step 2)."""
        async with self._lock:
            await self._outcome(event)
            # end async with
        # end def

    async def flush(self) -> int:
        """Resend every owed outcome, byte for byte; return how many are still owed (§6.4)."""
        async with self._lock:
            while self._owed:
                event = self._owed[0]
                if not await self._deliver(event):
                    break
                    # end if
                self._owed.pop(0)
                await self._acknowledged(event)
                # end while
            return len(self._owed)
            # end async with
        # end def

    async def position(self) -> SessionPosition | Literal['refused'] | None:
        """Ask for the session's last position (§6.5): the position, 'refused' on 403, or None."""
        async with self._lock:
            status, body = await self._post({'position': True})
            if status == 403:
                return 'refused'
                # end if
            if status != 200:
                self._last_failure = RecordFailure(http_status=status)
                return None
                # end if
            try:
                return SessionPosition.model_validate(body, context=WIRE)
            except ValidationError:
                return None
                # end try
            # end async with
        # end def

    async def close(self) -> bool:
        """Close the session (§6.7); True once the endpoint acknowledged it."""
        async with self._lock:
            await self._write({'entry': 'close'})
            status, _ = await self._post({'close': True})
            return status is not None and 200 <= status < 300
            # end async with
        # end def

    async def _write(self, entry: JournalEntry) -> None:
        """Write to the own ledger, when the client has one."""
        if self._journal is not None:
            await self._journal(entry)
            # end if
        # end def

    async def _attempt(self, event: dict[str, object]) -> AttemptResponse:
        """POST an attempt and read its answer."""
        attempt_id = str(event['id'])
        self._sent_attempts[attempt_id] = event
        status, body = await self._post({'event': event})
        if status != 200:
            self._fail(attempt_id, RecordFailure(http_status=status, attempt_id=attempt_id))
            return unavailable()
            # end if
        try:
            response = _RESPONSE.validate_python(body, context=WIRE)
        except ValidationError:
            self._fail(attempt_id, RecordFailure(http_status=200, attempt_id=attempt_id))
            return unavailable()
            # end try
        # Written before it is acted on; a failed write is a fault, which a-MCP turns into an abort.
        await self._write({'entry': 'response', 'id': str(event['id']), 'response': response.to_wire()})
        if response.status == 'accept':
            self._last_failure = None
            self._attempt_failures.pop(attempt_id, None)
        else:
            self._fail(attempt_id, RecordFailure(host_reason=getattr(response, 'reason', None), attempt_id=attempt_id))
            # end if
        return response
        # end def

    async def _outcome(self, event: dict[str, object]) -> None:
        """POST an outcome, owed from before it is sent until it is acknowledged, whatever stops the send."""
        self._owed.append(event)
        if await self._deliver(event):
            self._owed.remove(event)
            await self._acknowledged(event)
            # end if
        # end def

    async def _acknowledged(self, event: dict[str, object]) -> None:
        """Write that an outcome was acknowledged."""
        try:
            await self._write({'entry': 'acked', 'id': str(event['id'])})
        except SelfLedgerError:
            # Delivered either way; a resumption resends it, and the host answers it as a repeat (§6.4).
            logger.exception('an acknowledged outcome was not written to the own ledger')
            # end try
        # end def

    async def _deliver(self, event: dict[str, object]) -> bool:
        """POST an outcome; True when acknowledged. It does not touch `last_failure`, which is the attempt's."""
        status, _ = await self._post({'event': event})
        event_id = str(event['id'])
        delivered = status is not None and 200 <= status < 300
        if delivered:
            self._outcome_failures.pop(event_id, None)
        else:
            self._outcome_failures[event_id] = RecordFailure(http_status=status, attempt_id=event_id)
            # end if
        return delivered
        # end def

    def _fail(self, attempt_id: str, failure: RecordFailure) -> None:
        """Keep why an attempt was not recorded, as the last failure and as the attempt's."""
        self._last_failure = failure
        self._attempt_failures[attempt_id] = failure
        # end def

    async def _post(self, kind: dict[str, object]) -> tuple[int | None, object]:
        """One POST, bounded; status None when nothing was answered in time."""
        body = {'taskId': self._task_id, **({} if self._token is None else {'token': self._token}), **kind}
        headers = {
            'authorization': f'{self._authentication.scheme} {self._authentication.credentials}',
            'content-type': 'application/json',
        }
        raw: bytes = b''
        status: int | None = None
        with anyio.move_on_after(self._timeout):
            try:
                status, raw = await self._post_once(self._url, headers, json.dumps(body).encode('utf-8'))
            except Exception:
                # Nothing was answered: a failure to record (§6.2, §6.4). A cancellation is not caught.
                logger.warning('the audit endpoint did not answer', exc_info=True)
                status = None
                # end try
            # end with
        if status is None:
            return None, None
            # end if
        try:
            return status, (json.loads(raw) if raw else None)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return status, None
            # end try
        # end def

    # end class
