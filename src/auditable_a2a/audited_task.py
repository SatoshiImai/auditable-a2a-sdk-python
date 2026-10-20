"""One audit-negotiated Task, on the Server Agent (§5, §8): a-MCP's `AmcpSession` over the Task's endpoint."""

import logging
import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import TracebackType
from typing import Any

import anyio
from auditable_mcp import (
    AmcpAbortedError,
    AmcpSession,
    AuditedAction,
    Deps,
    EventSigner,
    SessionNumbering,
    SystemDeps,
)

from auditable_a2a.endpoint_client import DEFAULT_TIMEOUT_SECONDS, AuditEndpointClient, Journal, Post, RecordFailure
from auditable_a2a.execution_report import AUDIT_SESSION_KIND, EXECUTION_REPORT_ACTION_TYPE, Execution
from auditable_a2a.host_keys import FetchHostKeys, HostKeysVerifier
from auditable_a2a.models import (
    ABORT_REASONS,
    HOST_REASONS,
    AuditRequest,
    AuditSession,
    AuditStatus,
    AuthenticationInfo,
    Countersign,
)
from auditable_a2a.self_ledger import JournalEntry, SelfLedger, SelfLedgerError

logger = logging.getLogger(__name__)


class TerminalBound(StrEnum):
    """The ends a Task's terminal state may be reached by with records still owed (§5.4)."""

    CANCEL = 'cancel'
    HOLD_TIMEOUT = 'hold-timeout'
    EXPIRY = 'expiry'
    NOT_RESUMING = 'not-resuming'
    KEY_REVOKED = 'key-revoked'
    # end class


_SIGNATURE_FIELDS = ('signature', 'key_id', 'signer_seq')


class SessionExpiredError(Exception):
    """The session has expired (§5.3): the Server Agent does not continue the Task, and fails it."""

    def __init__(self, expires_at: str) -> None:
        """Name the expiry."""
        super().__init__(f'the audit session expired at {expires_at}; the Task is not continued (§5.3)')
        self.expires_at = expires_at
        # end def

    # end class


@dataclass
class _Unresolved:
    """What the Task holds of one accepted attempt until its outcome is sent or an execution report is accepted."""

    disposed: bool = False
    reported: bool = False
    # end class


def _instant(timestamp: str) -> datetime:
    """Parse a UTC timestamp with a `Z` suffix."""
    return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    # end def


async def _begins_with_session(self_ledger: SelfLedger) -> bool:
    """Whether the own ledger already holds its session entry; False when it cannot be read."""
    try:
        entries = await self_ledger.entries()
    except SelfLedgerError:
        return False
        # end try
    return bool(entries) and entries[0].get('entry') == 'session'
    # end def


class TrackedAction:
    """a-MCP's `AuditedAction`, held outstanding until it is resolved, and written ahead into the own ledger."""

    def __init__(
        self,
        task: 'AuditedTask',
        action: AuditedAction,
        *,
        refuse_after_expiry: bool,
        is_report: bool,
        is_record: bool = False,
    ) -> None:
        """Wrap the action; `is_record` for a record that is not an access (§8.1)."""
        self._task = task
        self._action = action
        self._refuse_after_expiry = refuse_after_expiry
        self._is_report = is_report
        self._is_record = is_record
        self._state: _Unresolved | None = None
        # end def

    @property
    def id(self) -> str:
        """The event id the operation's attempt and outcome share."""
        return self._action.id
        # end def

    async def __aenter__(self) -> AuditedAction:
        """Record the attempt (§8.3); held outstanding once it is accepted.

        Raises:
            SessionExpiredError: The session has expired; nothing is sent (§5.3).
            AmcpAbortedError: The record could not be made; the access is not performed.
            SelfLedgerError: It could not be written that the access is about to be performed, so it is not.
                The accept stays unresolved; resolve it with `report_execution(id, 'not-performed')`, or a
                resumption reports it (§5.5).
        """
        task = self._task
        if self._refuse_after_expiry:
            task._refuse_after_expiry()
            # end if
        task._pending += 1
        try:
            # Written before the attempt is sent, so a resumption that finds it accepted completes it with
            # `success` rather than reporting it as an access (§8.1, §5.5). Counted as on its way from here, so
            # `finish` does not close under it (§6.7).
            if self._is_record and task._journal is not None:
                await task._journal({'entry': 'record', 'id': self._action.id})
                # end if
            entered = await self._action.__aenter__()
        except AmcpAbortedError as error:
            task._aborted_attempts[error] = self._action.id
            raise
        except BaseException:
            # An attempt that reached the transport may have been sealed: give it up with its aborted outcome
            # (§8.3, a-MCP §7.2).
            attempt = task._client.sent_attempt(self._action.id)
            if attempt is not None:
                with anyio.CancelScope(shield=True):
                    try:
                        await task._emit_outcome(attempt, 'aborted', 'host-unavailable')
                    except SelfLedgerError:
                        # Not written, so not sent: the attempt stays for a resumption to resolve (§5.5).
                        task._unresolved[self._action.id] = _Unresolved(disposed=True)
                        logger.exception('the aborted outcome of %s was not written to the own ledger', self._action.id)
                        # end try
                    # end with
                # end if
            raise
        finally:
            task._pending -= 1
            # end try
        self._state = _Unresolved()
        task._unresolved[self._action.id] = self._state
        performs = not self._is_report and not self._is_record
        if performs:
            task._accepted.add(self._action.id)
            # end if
        # Not performed unless it is written that it is about to be (§5.5). A report or a record performs nothing.
        if task._self_ledger is not None and performs:
            await task._self_ledger.write({'entry': 'performing', 'id': self._action.id})
            # end if
        return entered
        # end def

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        """Record the outcome, unless an execution report resolved the access; never suppress the body's error."""
        state = self._state
        if state is None or state.disposed:
            return
            # end if
        state.disposed = True
        # An access resolved by an execution report has no outcome (§8.6).
        if state.reported:
            return
            # end if
        task = self._task
        # Shielded, so a cancelled body still records how it ended; each POST is bounded already (§6.8).
        with anyio.CancelScope(shield=True):
            try:
                await self._resolve(exc_type, exc, tb)
            finally:
                if task._client.has_outcome(self._action.id):
                    task._unresolved.pop(self._action.id, None)
                else:
                    # Not sent: the attempt stays unresolved, which keeps the Task from ending without it (§5.4).
                    logger.error('the outcome of %s was not sent; the access stays unresolved', self._action.id)
                    # end if
                # end try
            # end with
        # end def

    async def _resolve(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        """Write how the access resolved, then send its outcome.

        A record that is not an access ends `success` whatever its body did: it describes what already happened
        (§8.1), and the body's error still propagates.
        """
        task = self._task
        if self._is_record:
            exc_type, exc, tb = None, None, None
            # end if
        if task._self_ledger is not None:
            outcome = 'failed' if exc_type is not None else 'success'
            try:
                await task._self_ledger.write({'entry': 'resolved', 'id': self._action.id, 'outcome': outcome})
            except SelfLedgerError:
                # The outcome's own entry says the same; raising would replace the body's exception.
                logger.exception('how an access resolved was not written to the own ledger')
                # end try
            # end if
        try:
            await self._action.__aexit__(exc_type, exc, tb)
        except SelfLedgerError:
            # Not written, so not sent: the access stays unresolved. Raising would replace the body's exception.
            logger.exception('the outcome of %s was not written to the own ledger', self._action.id)
            # end try
        # end def

    # end class


class AuditedTask:
    """The audit of one Task on the Server Agent (§5, §8)."""

    def __init__(
        self,
        *,
        task_id: str,
        request: AuditRequest,
        post: Post,
        signer: EventSigner | None = None,
        host_key_snapshot: Mapping[str, Any] | None = None,
        fetch_host_keys: FetchHostKeys | None = None,
        deps: Deps | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        self_ledger: SelfLedger | None = None,
        resumed_at: int | None = None,
    ) -> None:
        """Bind the Task to its audit endpoint and a-MCP session.

        Args:
            task_id: The Task's id, which every submission carries (§6.1).
            request: The validated `auditRequest` the Task was negotiated with (§4.3, §7.1).
            post: The HTTP POST (`AuditEndpointClient`).
            signer: Under Level 2, the signer of the Server Agent's attestation key (§10.2).
            host_key_snapshot: Under `countersign: "host"`, the JWKS fetched from `request.hostKeys`.
            fetch_host_keys: Under `countersign: "host"`, fetches `request.hostKeys` again when an accept names a
                `kid` the snapshot does not hold (§10.2); `httpx_fetch_host_keys` is one.
            deps: a-MCP's clock and id source.
            timeout: The bound on each POST, in seconds (§6.8).
            self_ledger: The Task's partition of the Server Agent's own ledger, for a Task it may resume (§5.5).
            resumed_at: Set by `resume_task` for a Task restored from its own ledger: the session entry is
                there, and the next event takes this `signer_seq` (a-MCP §7.4).

        Raises:
            ValueError: `countersign: "host"` without the host's key snapshot and the means to fetch it again,
                which §8.3 and §10.2 need, or a snapshot that is not a conforming registry.
        """
        countersigned = request.countersign == Countersign.HOST
        if countersigned and (request.hostKeys is None or host_key_snapshot is None or fetch_host_keys is None):
            raise ValueError(
                "a countersigned session verifies against the audit host's keys, fetched again when they rotate "
                '(§8.3, §10.2)'
            )
            # end if
        endpoint = request.auditEndpoint
        self._journal: Journal | None = (
            None
            if self_ledger is None
            else self._journal_of(self_ledger, task_id, request, signer, host_key_snapshot, resumed_at is not None)
        )
        self._client = AuditEndpointClient(
            url=endpoint.url,
            authentication=endpoint.authentication,
            task_id=task_id,
            level=request.level,
            countersign=request.countersign,
            post=post,
            token=endpoint.token,
            timeout=timeout,
            journal=self._journal,
            numbering=None if resumed_at is None else SessionNumbering(resumed_at),
        )
        self._request = request
        self._self_ledger = self_ledger
        self._deps: Deps = deps or SystemDeps()
        self._signer = signer
        self._pending = 0
        self._unresolved: dict[str, _Unresolved] = {}
        self._accepted: set[str] = set()
        self._reported: set[str] = set()
        self._reporting: set[str] = set()
        self._aborted_attempts: weakref.WeakKeyDictionary[AmcpAbortedError, str] = weakref.WeakKeyDictionary()
        verifier = (
            HostKeysVerifier(str(request.hostKeys), host_key_snapshot or {}, fetch_host_keys) if countersigned else None
        )
        # Polluted Stop is REQUIRED at both levels (§8.3).
        self._session = AmcpSession(
            self._client,
            request.sessionId,
            signer=signer,
            deps=self._deps,
            polluted_stop=True,
            countersignature_verifier=verifier,
            require_countersign=countersigned,
        )
        # end def

    @staticmethod
    def _journal_of(
        self_ledger: SelfLedger,
        task_id: str,
        request: AuditRequest,
        signer: EventSigner | None,
        host_key_snapshot: Mapping[str, Any] | None,
        session_written: bool,
    ) -> Journal:
        """The journal that writes the session entry first, once, ahead of any other entry (§5.5 step 1)."""
        written = session_written

        async def journal(entry: JournalEntry) -> None:
            nonlocal written
            if not written:
                journaled = request.to_wire()
                journaled['auditEndpoint'] = {'url': request.auditEndpoint.url}
                try:
                    await self_ledger.write(
                        {
                            'entry': 'session',
                            'taskId': task_id,
                            'request': journaled,
                            **({} if signer is None else {'keyId': signer.key_id}),
                            **({} if host_key_snapshot is None else {'hostKeySnapshot': dict(host_key_snapshot)}),
                        }
                    )
                except SelfLedgerError:
                    # The append may have landed before it failed; a second session entry would make the ledger
                    # one that cannot be restored (§5.5).
                    if not await _begins_with_session(self_ledger):
                        raise
                        # end if
                    # end try
                written = True
                # end if
            await self_ledger.write(entry)
            # end def

        return journal
        # end def

    @property
    def client(self) -> AuditEndpointClient:
        """The endpoint client, for the position check and the close (§5.5, §6.5, §6.7)."""
        return self._client
        # end def

    @property
    def audit_session(self) -> AuditSession:
        """What the Server Agent places in `Task.metadata[URI].auditSession` (§7.2)."""
        return AuditSession(
            sessionId=self._request.sessionId, level=self._request.level, countersign=self._request.countersign
        )
        # end def

    def action(
        self,
        action_type: str,
        target_resource: dict[str, object],
        *,
        mutates: bool,
        egress: bool,
        disclose: dict[str, object] | None = None,
        commit: object | None = None,
        commit_salted: dict[str, object] | None = None,
    ) -> TrackedAction:
        """Record an access before performing it (§8.1, §8.3); use as `async with`.

        The outcome is `success` when the body completes and `failed` when it raises; an action resolved with
        `report_execution` sends none.

        Raises:
            AmcpAbortedError: On entering, the record could not be made: do not perform the access, and hold the
                Task with `status_of` as its `auditStatus` (§8.4).
            SessionExpiredError: On entering, the session has expired: do not continue the Task (§5.3).
        """
        return self._tracked(
            action_type,
            target_resource,
            mutates=mutates,
            egress=egress,
            disclose=disclose,
            commit=commit,
            commit_salted=commit_salted,
            refuse_after_expiry=True,
        )
        # end def

    def record(
        self,
        action_type: str,
        target_resource: dict[str, object],
        *,
        disclose: dict[str, object] | None = None,
        commit: object | None = None,
        commit_salted: dict[str, object] | None = None,
    ) -> TrackedAction:
        """Record a transition, a question or an answer: a record that is not an access (§8.1); use as `async with`.

        The attempt has `mutates` and `egress` both `false`. Do not go past what it describes until it is
        accepted, which entering waits for. Its outcome is `success` however the body ends, and a resumption
        completes an accepted one with `success` rather than reporting on it (§5.5).

        Raises:
            ValueError: `action_type` is the execution report's, which a record is not (§8.1).
            AmcpAbortedError: On entering, the record could not be made: do not go past it, and hold the Task
                with `status_of` as its `auditStatus` (§8.4).
            SessionExpiredError: On entering, the session has expired: do not continue the Task (§5.3).
            SelfLedgerError: On entering, it could not be written that this is a record; nothing was sent.
        """
        if action_type == EXECUTION_REPORT_ACTION_TYPE:
            raise ValueError(f'a record that is not an access does not use the action_type {action_type}')
            # end if
        return self._tracked(
            action_type,
            target_resource,
            mutates=False,
            egress=False,
            disclose=disclose,
            commit=commit,
            commit_salted=commit_salted,
            refuse_after_expiry=True,
            is_record=True,
        )
        # end def

    def _tracked(
        self,
        action_type: str,
        target_resource: dict[str, object],
        *,
        mutates: bool,
        egress: bool,
        disclose: dict[str, object] | None = None,
        commit: object | None = None,
        commit_salted: dict[str, object] | None = None,
        refuse_after_expiry: bool,
        is_record: bool = False,
    ) -> TrackedAction:
        """a-MCP's `action`, tracked until it is resolved."""
        action = self._session.action(
            action_type,
            target_resource,
            mutates=mutates,
            egress=egress,
            disclose=disclose,
            commit=commit,
            commit_salted=commit_salted,
        )
        return TrackedAction(
            self,
            action,
            refuse_after_expiry=refuse_after_expiry,
            is_report=action_type == EXECUTION_REPORT_ACTION_TYPE,
            is_record=is_record,
        )
        # end def

    async def report_execution(self, attempt_id: str, execution: Execution | str) -> None:
        """Send an execution report for an accepted attempt this Task will not resolve with an outcome (§8.6).

        The action it names sends no outcome when it exits. It is sent after the session's end or expiry too (§5.4).

        Raises:
            ValueError: `execution` is not one of §8.6's values; or `attempt_id` is not an access this Task had
                accepted, has an outcome, or has a report accepted or on its way: a second report, or one on
                anything else, is a finding against the Server Agent (§8.6, §11).
            AmcpAbortedError: The report could not be recorded; send it again later (§8.6).
        """
        execution = Execution(execution)
        if attempt_id in self._reported or attempt_id in self._reporting:
            raise ValueError(f'an execution report on {attempt_id} was already accepted or is on its way (§8.6)')
            # end if
        if attempt_id not in self._accepted:
            raise ValueError(f'{attempt_id} is not an access this Task had accepted (§8.6)')
            # end if
        if self._client.has_outcome(attempt_id):
            raise ValueError(f'{attempt_id} has its outcome, so it is not reported on (§8.6)')
            # end if
        self._reporting.add(attempt_id)
        state = self._unresolved.get(attempt_id)
        # Set before the report is sent, so an action exiting meanwhile does not also send its outcome.
        if state is not None:
            state.reported = True
            # end if
        try:
            async with self._tracked(
                EXECUTION_REPORT_ACTION_TYPE,
                {'kind': AUDIT_SESSION_KIND, 'ref': self._request.sessionId},
                mutates=False,
                egress=False,
                disclose={'attemptId': attempt_id, 'execution': str(execution)},
                refuse_after_expiry=False,
            ):
                self._reported.add(attempt_id)
                self._unresolved.pop(attempt_id, None)
                # end async with
        except BaseException:
            # Not accepted: an action that has not exited yet sends its outcome after all.
            if state is not None and attempt_id not in self._reported:
                state.reported = False
                # end if
            raise
        finally:
            self._reporting.discard(attempt_id)
            # end try
        # end def

    async def _emit_outcome(self, attempt: Mapping[str, object], outcome: str, reason: str | None = None) -> bool:
        """Send the outcome of `attempt` this Task builds itself, numbered in the session's sequence (a-MCP §7.4).

        Returns:
            Whether it was acknowledged; otherwise it is owed (§6.4).
        """
        event = {k: v for k, v in attempt.items() if k not in _SIGNATURE_FIELDS}
        event['ts'] = self._deps.now()
        event['outcome'] = outcome
        if reason is not None:
            event['reason'] = reason
            # end if
        if self._signer is None:
            await self._client.send_outcome(event)
        else:
            numbering = self._client.numbering
            async with numbering.lock:
                signer_seq = numbering.next_signer_seq
                await self._client.send_outcome(await self._signer.sign(event, signer_seq))
                numbering.next_signer_seq = signer_seq + 1
                # end async with
            # end if
        return all(str(owed['id']) != str(attempt['id']) for owed in self._client.owed)
        # end def

    def _restore_accepts(self, accepted: set[str], reported: set[str]) -> None:
        """What a resumption restored from the own ledger: the accesses accepted, and those already reported."""
        self._accepted.update(accepted)
        self._reported.update(reported)
        # end def

    def status_of(self, error: AmcpAbortedError, attempt_id: str | None = None) -> AuditStatus:
        """The `auditStatus` of a hold for the attempt `error` aborted, or for `attempt_id` (§7.3, §8.4)."""
        reason = error.reason if error.reason in ABORT_REASONS else 'host-unavailable'
        event_id = attempt_id if attempt_id is not None else self._aborted_attempts.get(error)
        failure = None if event_id is None else self._client.attempt_failure_of(event_id)
        return self._status(reason, failure, event_id)
        # end def

    def held_status(self) -> AuditStatus | None:
        """The `auditStatus` of a hold for the earliest outcome owed, or None when none is (§7.3, §8.4)."""
        owed = self._client.owed
        if not owed:
            return None
            # end if
        event_id = str(owed[0]['id'])
        return self._status('host-unavailable', self._client.outcome_failure_of(event_id), event_id)
        # end def

    @staticmethod
    def _status(reason: str, failure: RecordFailure | None, attempt_id: str | None) -> AuditStatus:
        """An `auditStatus` from the failure of the submission it is about."""
        host_reason = None if failure is None else failure.host_reason
        http_status = None if failure is None else failure.http_status
        return AuditStatus.model_validate(
            {
                'reason': reason,
                **({'hostReason': host_reason} if host_reason in HOST_REASONS else {}),
                **({'httpStatus': http_status} if http_status not in (None, 200) else {}),
                **({'attemptId': attempt_id} if attempt_id is not None else {}),
            }
        )
        # end def

    def _refuse_after_expiry(self) -> None:
        """§5.3: no access after the session's expiry."""
        if _instant(self._deps.now()) >= _instant(self._request.expiresAt):
            raise SessionExpiredError(self._request.expiresAt)
            # end if
        # end def

    def replace_credentials(self, authentication: AuthenticationInfo, token: str | None = None) -> None:
        """Replace the endpoint's credentials from an `auditCredentials` the Client sent (§5.7)."""
        self._client.replace_credentials(authentication, token)
        # end def

    def may_end(self, bound: TerminalBound | None = None) -> bool:
        """Whether the Task may move to a terminal state: nothing is outstanding (§5.4), or `bound` is given.

        `bound` states that one of §5.4's bounds has passed; it is not checked.
        """
        return bound is not None or self._nothing_outstanding()
        # end def

    async def finish(self) -> bool:
        """Resend the owed outcomes, then close the session when nothing is outstanding (§5.4, §6.7).

        Returns:
            True once the close is acknowledged; False while something is outstanding or the close was not
            acknowledged.
        """
        # Checked first too: the resend would queue behind an attempt on its way.
        if not self._nothing_unresolved():
            return False
            # end if
        await self._client.flush()
        if not self._nothing_outstanding():
            return False
            # end if
        return await self._client.close()
        # end def

    def _nothing_unresolved(self) -> bool:
        """No attempt on its way, no accept unresolved."""
        return self._pending == 0 and not self._unresolved
        # end def

    def _nothing_outstanding(self) -> bool:
        """No attempt on its way, no accept unresolved, no outcome owed."""
        return self._nothing_unresolved() and not self._client.owed
        # end def

    # end class
