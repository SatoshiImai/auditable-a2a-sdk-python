"""The Client's audit host (§5, §6): a-MCP's `AuditHost` with the session this extension defines.

The a-MCP session is never closed: this layer refuses what a session's end refuses (§5.4) before a-MCP sees it.
A session's state changes only once its new state is stored.
"""

import base64
import copy
import logging
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

import anyio
from auditable_mcp import (
    SPEC_VERSION,
    WIRE,
    AttemptResponse,
    AuditCapability,
    AuditHost,
    CanonicalizationError,
    Countersigner,
    KeyRole,
    LedgerRepository,
    OpenSession,
    OutcomeDisposition,
    RejectReason,
    SealedRecord,
    accept,
    canonicalize,
    reject,
    unavailable,
)
from auditable_mcp.clock import Clock, SystemClock
from auditable_mcp.l2 import KeyRegistryVerifier
from pydantic import ValidationError

from auditable_a2a.execution_report import EXECUTION_REPORT_ACTION_TYPE, is_execution_report
from auditable_a2a.keys import registry_from_jwks
from auditable_a2a.models import EXTENSION_URI, AuditSubmission, AuthenticationInfo, Countersign, Level, SealedPosition
from auditable_a2a.session_store import (
    EndCause,
    IssuedCredential,
    SessionAnomaly,
    SessionEnd,
    SessionState,
    SessionStore,
    SessionStoreError,
)

logger = logging.getLogger(__name__)

_BEARER: Final = 'Bearer'
_CREDENTIAL_BYTES: Final = 32


IssuedAuthentication = AuthenticationInfo
"""A credential this host issued, to place in `auditRequest` (§7.1) or `auditCredentials` (§7.4) as it is."""


@dataclass(frozen=True)
class SubmissionAnswer:
    """The answer to one submission, for a binding to write as an HTTP response (§6)."""

    status: int
    body: object | None = None
    # end class


def _b64url(raw: bytes) -> str:
    """Encode base64url without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
    # end def


def _instant(timestamp: str) -> datetime:
    """Parse an a-MCP UTC timestamp with a `Z` suffix."""
    return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    # end def


class A2aAuditHost:
    """The Client's audit host for one partition (§5, §6).

    One host validates at one level and countersigns or not; a Client that delegates at both levels runs one for each.
    """

    def __init__(
        self,
        host: AuditHost,
        level: Level,
        countersign: Countersign,
        *,
        store: SessionStore,
        clock: Clock,
        random: Callable[[int], bytes],
        countersigner_key_id: str | None = None,
    ) -> None:
        """Bind the a-MCP host and this layer's state; use `create` or `resume` to build one."""
        self._host = host
        self._countersigner_key_id = countersigner_key_id
        self._level = level
        self._countersign = countersign
        self._store = store
        self._clock = clock
        self._random = random
        self._states: dict[str, SessionState] = {}
        self._verifiers: dict[str, KeyRegistryVerifier] = {}
        self._credentials: dict[str, str] = {}
        # Anomalies a-MCP recorded for a session, held until a stored state carries them (§6.3).
        self._unstored_anomalies: dict[str, list[SessionAnomaly]] = {}
        self._records: dict[str, list[SealedRecord]] = {}
        self._indexed = 0
        self._last_seq: int | None = None
        # One submission at a time, so what a-MCP records in memory while answering it is stored before the answer.
        self._lock = anyio.Lock()
        # end def

    @staticmethod
    def _capability(level: Level, countersign: Countersign) -> AuditCapability:
        """The a-MCP capability of a partition at this level and countersignature setting."""
        return AuditCapability.model_validate(
            {'spec_version': SPEC_VERSION, 'level': level, 'attempt': 'request', 'countersign': countersign}
        )
        # end def

    @classmethod
    def create(
        cls,
        partition: str,
        level: Level,
        countersign: Countersign,
        *,
        store: SessionStore,
        repository: LedgerRepository | None = None,
        countersigner: Countersigner | None = None,
        log_id: str | None = None,
        clock: Clock | None = None,
        random: Callable[[int], bytes] = secrets.token_bytes,
    ) -> 'A2aAuditHost':
        """Start a host for `partition` with no sessions yet."""
        holder: list[A2aAuditHost] = []
        verifier = _SessionVerifier(holder)
        host = AuditHost(
            partition,
            cls._capability(level, countersign),
            verifier=verifier if level == Level.L2 else None,
            countersigner=countersigner,
            log_id=log_id,
            repository=repository,
            clock=clock,
        )
        self = cls(
            host,
            level,
            countersign,
            store=store,
            clock=clock or SystemClock(),
            random=random,
            countersigner_key_id=None if countersigner is None else countersigner.key_id,
        )
        holder.append(self)
        return self
        # end def

    @classmethod
    async def resume(
        cls,
        partition: str,
        level: Level,
        countersign: Countersign,
        *,
        store: SessionStore,
        repository: LedgerRepository,
        countersigner: Countersigner | None = None,
        log_id: str | None = None,
        clock: Clock | None = None,
        random: Callable[[int], bytes] = secrets.token_bytes,
    ) -> 'A2aAuditHost':
        """Restart a host from its ledger and its session store (§5.6).

        Ended sessions are restored open in a-MCP too, so what is still owed to them is sealed (§5.4).
        """
        states = await store.all()
        holder: list[A2aAuditHost] = []
        verifier = _SessionVerifier(holder)
        host = await AuditHost.resume(
            partition,
            cls._capability(level, countersign),
            repository=repository,
            verifier=verifier if level == Level.L2 else None,
            countersigner=countersigner,
            log_id=log_id,
            clock=clock,
            open_sessions=[OpenSession(state.session_id, state.signers) for state in states],
        )
        self = cls(
            host,
            level,
            countersign,
            store=store,
            clock=clock or SystemClock(),
            random=random,
            countersigner_key_id=None if countersigner is None else countersigner.key_id,
        )
        holder.append(self)
        for state in states:
            self._remember(state)
            # end for
        for record in await repository.read_all(partition):
            self._index(record)
            # end for
        return self
        # end def

    async def open_session(
        self,
        *,
        delegate: str,
        expires_at: str,
        attestation_keys: str | None = None,
        key_snapshot: Mapping[str, Any] | None = None,
        host_keys: str | None = None,
        version: str = EXTENSION_URI,
    ) -> tuple[str, IssuedAuthentication]:
        """Open a session for a delegation and issue its first credential (§5.1).

        Args:
            delegate: The URL of the Agent Card the Client delegates to.
            expires_at: When the session expires (§5.3).
            attestation_keys: Under Level 2, the delegate's `attestationKeys` URL.
            key_snapshot: Under Level 2, the JWKS fetched from it, after the Client verified the
                delegate's Agent Card signature (§5.1).
            host_keys: Under `countersign: "host"`, where this host publishes its countersignature keys.
            version: The version the session is opened for (§4.1); this host implements only `EXTENSION_URI`.

        Returns:
            The session id and the credential to send in `auditRequest`.

        Raises:
            ValueError: A version this host does not implement, Level 2 without a key snapshot, `host`
                without `host_keys`, a countersigning key not named under `host_keys` (§7.1), or a snapshot that is
                not a conforming registry (§10.2).
            SessionStoreError: The session was not stored.
        """
        async with self._lock:
            if version != EXTENSION_URI:
                raise ValueError(f'this audit host implements {EXTENSION_URI}, not {version} (§4.1)')
                # end if
            if self._level == Level.L2 and (attestation_keys is None or key_snapshot is None):
                raise ValueError("a Level-2 session records the delegate's attestationKeys and their snapshot (§5.1)")
                # end if
            if self._countersign == Countersign.HOST and host_keys is None:
                raise ValueError('a countersigning audit host names its keys in hostKeys (§7.1)')
                # end if
            if (
                host_keys is not None
                and self._countersigner_key_id is not None
                and not self._countersigner_key_id.startswith(f'{host_keys}#')
            ):
                # A delegate resolves a receipt's host_key_id at hostKeys, as `{hostKeys}#{kid}`: a key named any
                # other way is never found there, and every countersignature reads as invalid.
                named = self._countersigner_key_id
                raise ValueError(f'the countersigning key is named {named}, not under {host_keys}# (§7.1, §10.2)')
                # end if
            state = SessionState(
                session_id=self._host.open_session(),
                version=version,
                delegate=delegate,
                level=self._level,
                countersign=self._countersign,
                expires_at=expires_at,
                host_keys=host_keys,
                attestation_keys=attestation_keys,
                key_snapshot=None if key_snapshot is None else dict(key_snapshot),
            )
            if attestation_keys is not None and key_snapshot is not None:
                registry = registry_from_jwks(attestation_keys, key_snapshot, KeyRole.TOOL)
                self._verifiers[state.session_id] = KeyRegistryVerifier(registry)
                # end if
            authentication = self._new_credential()
            state.credentials.append(IssuedCredential(authentication.scheme, authentication.credentials))
            await self._store.put(state)
            self._remember(state)
            return state.session_id, authentication
            # end async with
        # end def

    async def issue_credentials(self, session_id: str) -> IssuedAuthentication:
        """Issue a further credential for the session, for rotation or replacement (§5.7).

        Raises:
            KeyError: No such session at this host.
            SessionStoreError: The credential was not stored, so it is not issued.
        """
        async with self._lock:
            authentication = self._new_credential()

            def add(draft: SessionState) -> None:
                draft.credentials.append(IssuedCredential(authentication.scheme, authentication.credentials))
                # end def

            await self._update(session_id, add)
            return authentication
            # end async with
        # end def

    async def end_session(self, session_id: str) -> None:
        """End the session on the Client's notice that its Task ended or its cancellation succeeded (§5.4).

        A session already ended keeps its first end.

        Raises:
            KeyError: No such session at this host.
            SessionStoreError: The end was not stored.
        """
        async with self._lock:
            await self._end(session_id, EndCause.CLIENT_NOTICE)
            # end async with
        # end def

    async def sweep(self) -> list[str]:
        """End every session whose expiry has passed (§5.3), with the expiry as the time of its end.

        Call it periodically: otherwise a session ends only on its first submission after its expiry.

        Returns:
            The ids of the sessions it ended.
        """
        async with self._lock:
            return [session_id for session_id in list(self._states) if await self._end_if_expired(session_id)]
            # end async with
        # end def

    async def purge(self, session_id: str) -> None:
        """Forget an ended session under the host's retention policy (§5.4); its records stay in the ledger.

        Raises:
            KeyError: No such session at this host.
            ValueError: The session has not ended.
        """
        async with self._lock:
            state = self._state(session_id)
            if state.end is None:
                raise ValueError(f'session {session_id} has not ended, so it is not purged (§5.4)')
                # end if
            await self._store.delete(session_id)
            for credential in state.credentials:
                self._credentials.pop(credential.credentials, None)
                # end for
            del self._states[session_id]
            self._verifiers.pop(session_id, None)
            self._records.pop(session_id, None)
            self._unstored_anomalies.pop(session_id, None)
            # end async with
        # end def

    def session(self, session_id: str) -> SessionState | None:
        """A copy of the session's state as this host keeps it, or None."""
        state = self._states.get(session_id)
        return None if state is None else copy.deepcopy(state)
        # end def

    def records(self) -> list[SealedRecord]:
        """The records this process sealed; after `resume`, the earlier ones are in the repository."""
        return self._host.records()
        # end def

    def digest(self) -> str:
        """The partition's tail digest."""
        return self._host.digest()
        # end def

    def anomalies(self) -> list[SessionAnomaly]:
        """The anomaly set, as each session keeps it durably: a-MCP's records and this layer's (§5.4, §6.6)."""
        return [anomaly for state in self._states.values() for anomaly in state.anomalies]
        # end def

    async def handle(self, body: object, authorization: str | None) -> SubmissionAnswer:
        """Answer one submission received at the audit endpoint (§6).

        Args:
            body: The parsed JSON body.
            authorization: The `Authorization` header, or None.

        Returns:
            The status and body to answer with.

        Raises:
            SessionStoreError: A session's state could not be stored before the submission was answered;
                nothing it would have stood on was recorded.
        """
        async with self._lock:
            before = len(self._host.anomalies())
            answer, session_id = await self._answer(body, authorization)
            self._sync()
            if session_id is None:
                return answer
                # end if
            recorded = [SessionAnomaly(a.id, a.kind, a.detail) for a in self._host.anomalies()[before:]]
            held = self._unstored_anomalies.setdefault(session_id, [])
            # A resend of a submission whose answer was 503 records its anomaly again; it is kept once.
            held.extend(a for a in recorded if all((k.id, k.kind) != (a.id, a.kind) for k in held))
            signers = self._host.signer_tracker(session_id) if self._level == Level.L2 else None
            if not self._unstored_anomalies[session_id] and signers == self._state(session_id).signers:
                return answer
                # end if

            def keep(draft: SessionState) -> None:
                if signers is not None:
                    draft.signers = signers
                    # end if
                # end def

            try:
                # §6.3: a refused outcome is acknowledged only once it is durably recorded; §5.6: so is a decision.
                await self._update(session_id, keep)
            except SessionStoreError:
                # §6.2: an attempt is answered with an Attempt Response; one sealed is then aborted, as unanswered.
                if isinstance(body, dict) and isinstance(body.get('event'), dict):
                    if body['event'].get('outcome') == 'attempted':
                        return SubmissionAnswer(200, unavailable().to_wire())
                        # end if
                    # end if
                return SubmissionAnswer(503, {'error': 'the session state could not be stored; send it again (§6.3)'})
                # end try
            return answer
            # end async with
        # end def

    async def _answer(self, body: object, authorization: str | None) -> tuple[SubmissionAnswer, str | None]:
        """Answer a submission; the caller holds the lock."""
        try:
            submission = AuditSubmission.model_validate(body, context=WIRE)
        except ValidationError:
            return SubmissionAnswer(400, {'error': 'not an AuditSubmission (§6.1)'}), None
            # end try
        session_id = await self._authenticate(authorization, submission)
        if session_id is None:
            return SubmissionAnswer(401, {'error': 'credentials not recognised (§6.6)'}), None
            # end if
        await self._end_if_expired(session_id)
        if submission.position is True:
            return self._answer_position(session_id, submission), session_id
            # end if
        if submission.close is True:
            return await self._answer_close(session_id, submission), session_id
            # end if
        event = dict(submission.event or {})
        if event.get('outcome') == 'attempted':
            return await self._answer_attempt(session_id, submission, event), session_id
            # end if
        return await self._answer_outcome(session_id, submission, event), session_id
        # end def

    async def _authenticate(self, authorization: str | None, submission: AuditSubmission) -> str | None:
        """§6.6: the session a submission arrives on is the one its credentials were issued for."""
        if authorization is None or ' ' not in authorization:
            return None
            # end if
        # This host issues no token, so any token is one it does not recognise.
        if submission.token is not None:
            return None
            # end if
        scheme, credentials = authorization.split(' ', 1)
        session_id = self._credentials.get(credentials)
        state = None if session_id is None else self._states.get(session_id)
        if state is None:
            return None
            # end if
        index = next(
            (
                i
                for i, entry in enumerate(state.credentials)
                if entry.scheme.lower() == scheme.lower() and entry.credentials == credentials
            ),
            None,
        )
        if index is None:
            return None
            # end if
        issued = state.credentials[index]
        if issued.retired_for_attempts and not self._admits_retired(state.session_id, issued, submission):
            return None
            # end if
        # §5.7: once a newer credential is used, the older ones admit only records owed.
        if any(not entry.retired_for_attempts for entry in state.credentials[:index]):
            own = self._records_of(state.session_id)
            last_seq = own[-1].seq if own else -1

            def retire(draft: SessionState) -> None:
                for entry in draft.credentials[:index]:
                    if not entry.retired_for_attempts:
                        entry.newest_until_seq = last_seq
                        # end if
                    entry.retired_for_attempts = True
                    # end for
                # end def

            await self._update(state.session_id, retire)
            # end if
        return state.session_id
        # end def

    def _admits_retired(self, session_id: str, issued: IssuedCredential, submission: AuditSubmission) -> bool:
        """§5.4, §5.7: a replaced credential admits the position, a resend of a sealed attempt, and the outcomes and
        execution reports of attempts sealed while it was the newest."""
        if submission.position is True:
            return True
            # end if
        event = dict(submission.event or {})
        if not event:
            return False
            # end if
        limit = -1 if issued.newest_until_seq is None else issued.newest_until_seq

        def sealed_up_to(attempt_id: object) -> bool:
            return any(
                record.event.get('id') == attempt_id
                and record.event.get('outcome') == 'attempted'
                and record.seq <= limit
                for record in self._records_of(session_id)
            )
            # end def

        if event.get('outcome') != 'attempted':
            return sealed_up_to(event.get('id'))
            # end if
        if self._sealed_repeat(session_id, event) is not None:
            return True
            # end if
        context = event.get('action_context')
        return (
            event.get('action_type') == EXECUTION_REPORT_ACTION_TYPE
            and isinstance(context, dict)
            and sealed_up_to(context.get('attemptId'))
        )
        # end def

    async def _answer_attempt(
        self, session_id: str, submission: AuditSubmission, event: dict[str, object]
    ) -> SubmissionAnswer:
        """§6.2, §6.6: an attempt."""
        state = self._state(session_id)
        # §6.6: a byte-identical repeat of a sealed attempt is answered from the ledger first.
        repeat = self._sealed_repeat(session_id, event)
        if repeat is not None:
            return SubmissionAnswer(200, repeat.to_wire())
            # end if
        if state.bound_task_id is not None and submission.taskId != state.bound_task_id:
            return SubmissionAnswer(200, reject('replay-detected').to_wire())
            # end if
        if state.end is not None and not self._is_report_for_accepted(session_id, event):
            return SubmissionAnswer(200, reject('replay-detected').to_wire())
            # end if
        if state.bound_task_id is not None:
            response = await self._host.handle_attempt(event, session_id=session_id)
            return SubmissionAnswer(200, response.to_wire())
            # end if
        # §5.1: stored before the binding attempt is sealed, so no restart can lose it; a refusal unbinds it.
        key_id = event.get('key_id')
        bound_key_id = key_id if self._level == Level.L2 and isinstance(key_id, str) else None

        def bind(draft: SessionState) -> None:
            draft.bound_task_id = submission.taskId
            if bound_key_id is not None:
                draft.bound_key_id = bound_key_id
                # end if
            # end def

        def unbind(draft: SessionState) -> None:
            draft.bound_task_id = None
            draft.bound_key_id = None
            # end def

        try:
            await self._update(session_id, bind)
        except SessionStoreError:
            return SubmissionAnswer(200, unavailable().to_wire())
            # end try
        response = await self._host.handle_attempt(event, session_id=session_id)
        if response.status != 'accept':
            try:
                await self._update(session_id, unbind)
            except SessionStoreError:
                # The safe side of §5.1: the session stays reserved for this Task.
                logger.warning('the session %s stayed bound after its first attempt was refused', session_id)
                # end try
            # end if
        return SubmissionAnswer(200, response.to_wire())
        # end def

    async def _answer_outcome(
        self, session_id: str, submission: AuditSubmission, event: dict[str, object]
    ) -> SubmissionAnswer:
        """§6.3, §6.6: an outcome, acknowledged once recorded."""
        state = self._state(session_id)
        if state.bound_task_id is not None and submission.taskId != state.bound_task_id:
            anomaly = SessionAnomaly(
                str(event.get('id')),
                'replay-detected',
                f'an outcome for task {submission.taskId} arrived on the session bound to {state.bound_task_id} (§6.6)',
            )

            def note(draft: SessionState) -> None:
                draft.anomalies.append(anomaly)
                # end def

            try:
                await self._update(session_id, note)
            except SessionStoreError:
                return SubmissionAnswer(503, {'error': 'the outcome could not be recorded; send it again (§6.3)'})
                # end try
            return SubmissionAnswer(204)
            # end if
        disposition = await self._host.record_outcome(event, session_id=session_id)
        if disposition == OutcomeDisposition.NOT_RECORDED:
            return SubmissionAnswer(503, {'error': 'the outcome could not be recorded; send it again (§6.3)'})
            # end if
        return SubmissionAnswer(204)
        # end def

    def _answer_position(self, session_id: str, submission: AuditSubmission) -> SubmissionAnswer:
        """§6.5: the session's last sealed record."""
        state = self._state(session_id)
        if state.bound_task_id is not None and submission.taskId != state.bound_task_id:
            return SubmissionAnswer(403, {'error': 'the session is bound to another Task (§6.6)'})
            # end if
        last = self._last_of(session_id)
        # `last` is the one member the schema admits as null (§6.5), so it is written even when absent.
        return SubmissionAnswer(200, {'last': None if last is None else last.to_wire()})
        # end def

    async def _answer_close(self, session_id: str, submission: AuditSubmission) -> SubmissionAnswer:
        """§6.7: the Server Agent's close."""
        state = self._state(session_id)
        if state.bound_task_id is not None and submission.taskId != state.bound_task_id:
            return SubmissionAnswer(403, {'error': 'the session is bound to another Task (§6.6)'})
            # end if
        try:
            await self._end(session_id, EndCause.CLOSE)
        except SessionStoreError:
            return SubmissionAnswer(503, {'error': 'the close could not be recorded; send it again (§6.7)'})
            # end try
        return SubmissionAnswer(204)
        # end def

    def _is_report_for_accepted(self, session_id: str, event: dict[str, object]) -> bool:
        """§8.6, §5.4: after the end, an execution report for an attempt this session accepted is admitted."""
        context = event.get('action_context')
        if not is_execution_report(event) or not isinstance(context, dict):
            return False
            # end if
        attempt_id = context.get('attemptId')
        return any(
            record.event.get('id') == attempt_id and record.event.get('outcome') == 'attempted'
            for record in self._records_of(session_id)
        )
        # end def

    def _sealed_repeat(self, session_id: str, event: dict[str, object]) -> AttemptResponse | None:
        """The accept of a sealed attempt `event` repeats byte for byte, or None."""
        try:
            canonical = canonicalize(event)
        except CanonicalizationError:
            return None
            # end try
        for record in self._records_of(session_id):
            if (
                record.event.get('id') == event.get('id')
                and record.event.get('outcome') == 'attempted'
                and canonicalize(record.event) == canonical
            ):
                return accept(
                    record.seq,
                    record.record_hash,
                    record.host_ts,
                    record.previous_hash,
                    host_signature=record.host_signature,
                    host_key_id=record.host_key_id,
                    log_id=record.log_id,
                )
                # end if
            # end for
        return None
        # end def

    def _last_of(self, session_id: str) -> SealedPosition | None:
        """The session's last sealed record, in the host-assigned fields of an accept."""
        records = self._records_of(session_id)
        if not records:
            return None
            # end if
        last = records[-1]
        return SealedPosition(
            seq=last.seq,
            host_ts=last.host_ts,
            previous_hash=last.previous_hash,
            record_hash=last.record_hash,
            log_id=last.log_id,
            host_signature=last.host_signature,
            host_key_id=last.host_key_id,
        )
        # end def

    async def _end_if_expired(self, session_id: str) -> bool:
        """§5.3: a session past `expiresAt` ends, with its expiry as the time of the end."""
        state = self._state(session_id)
        if state.end is not None or _instant(self._clock.now()) < _instant(state.expires_at):
            return False
            # end if
        await self._end(session_id, EndCause.EXPIRY, state.expires_at)
        return True
        # end def

    async def _end(self, session_id: str, cause: EndCause, at: str | None = None) -> None:
        """§5.4: record the cause, the time, the last seq before the end, and every unresolved attempt."""
        if self._state(session_id).end is not None:
            return
            # end if
        self._sync()
        end = SessionEnd(cause=cause, at=at or self._clock.now(), last_seq=self._last_seq)
        own = self._records_of(session_id)
        resolved = {str(record.event.get('id')) for record in own if record.event.get('outcome') != 'attempted'}
        unresolved = [
            str(record.event.get('id'))
            for record in own
            if record.event.get('outcome') == 'attempted' and str(record.event.get('id')) not in resolved
        ]

        def close(draft: SessionState) -> None:
            draft.end = end
            draft.anomalies.extend(
                SessionAnomaly(
                    event_id, 'unresolved-attempt', f'session ended ({cause}) with attempt {event_id} unresolved (§5.4)'
                )
                for event_id in unresolved
            )
            # end def

        await self._update(session_id, close)
        # end def

    async def _verify(self, event: dict[str, object]) -> RejectReason | None:
        """§5.1, §10.2: under Level 2 every event verifies against its session's snapshot, under its bound key."""
        session_id = event.get('session_id')
        state = self._states.get(session_id) if isinstance(session_id, str) else None
        if state is None:
            return 'unknown-key'
            # end if
        if state.bound_key_id is not None and event.get('key_id') != state.bound_key_id:
            return 'unknown-key'
            # end if
        verifier = self._verifiers.get(state.session_id)
        if verifier is None and state.attestation_keys is not None and state.key_snapshot is not None:
            verifier = KeyRegistryVerifier(registry_from_jwks(state.attestation_keys, state.key_snapshot, KeyRole.TOOL))
            self._verifiers[state.session_id] = verifier
            # end if
        if verifier is None:
            return 'unknown-key'
            # end if
        return await verifier.verify(event)
        # end def

    def _new_credential(self) -> IssuedAuthentication:
        """Mint a credential."""
        return IssuedAuthentication(scheme=_BEARER, credentials=_b64url(self._random(_CREDENTIAL_BYTES)))
        # end def

    def _state(self, session_id: str) -> SessionState:
        """The session's state, or raise."""
        state = self._states.get(session_id)
        if state is None:
            raise KeyError(f'no session {session_id} at this audit host')
            # end if
        return state
        # end def

    async def _update(self, session_id: str, change: Callable[[SessionState], None]) -> None:
        """Change the session's state once the changed state, with its unstored anomalies, is stored."""
        draft = copy.deepcopy(self._state(session_id))
        unstored = self._unstored_anomalies.get(session_id, [])
        draft.anomalies.extend(unstored)
        change(draft)
        await self._store.put(draft)
        self._remember(draft)
        self._unstored_anomalies.pop(session_id, None)
        # end def

    def _remember(self, state: SessionState) -> None:
        """Hold the state, and index its credentials."""
        self._states[state.session_id] = state
        for credential in state.credentials:
            self._credentials[credential.credentials] = state.session_id
            # end for
        # end def

    def _sync(self) -> None:
        """Add the records sealed in this process since the last sync to each session's index."""
        records = self._host.records()
        for record in records[self._indexed :]:
            self._index(record)
            # end for
        self._indexed = len(records)
        # end def

    def _index(self, record: SealedRecord) -> None:
        """Add one sealed record to its session's index."""
        session_id = record.event.get('session_id')
        if isinstance(session_id, str):
            self._records.setdefault(session_id, []).append(record)
            # end if
        self._last_seq = record.seq if self._last_seq is None else max(self._last_seq, record.seq)
        # end def

    def _records_of(self, session_id: str) -> list[SealedRecord]:
        """The session's sealed records, before and after a restart."""
        self._sync()
        return self._records.get(session_id, [])
        # end def

    # end class


class _SessionVerifier:
    """a-MCP's `SignatureVerifier`, dispatching to the session the event names (§5.1)."""

    def __init__(self, holder: list[A2aAuditHost]) -> None:
        """Bind to the host, which is built after a-MCP's host and so is reached through `holder`."""
        self._holder = holder
        # end def

    async def verify(self, event: dict[str, object]) -> RejectReason | None:
        """Verify through the session's registry and bound key."""
        return await self._holder[0]._verify(event)
        # end def

    # end class
