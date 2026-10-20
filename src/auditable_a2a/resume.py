"""Resumption of a Task after a Server Agent restart (§5.5), from the Task's partition of its own ledger.

Steps 1 - 4 run here and perform nothing accepted before the restart again; steps 5 and 6 are the caller's.
An accept first received on a step-2 resend is reported `not-performed`.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from auditable_mcp import (
    WIRE,
    AcceptResponse,
    AmcpAbortedError,
    Deps,
    EventSigner,
    SystemDeps,
    compute_record_hash,
    countersignature_payload,
)

from auditable_a2a.audited_task import AuditedTask
from auditable_a2a.endpoint_client import DEFAULT_TIMEOUT_SECONDS, Post
from auditable_a2a.execution_report import EXECUTION_REPORT_ACTION_TYPE, Execution
from auditable_a2a.host_keys import FetchHostKeys, HostKeysVerifier
from auditable_a2a.models import AuditCredentials, AuditRequest, AuditStatus, Countersign, Level
from auditable_a2a.position import HeldState, check_position
from auditable_a2a.self_ledger import JournalEntry, SelfLedger, SelfLedgerError

ResumeState = Literal['continue', 'delivered', 'closed', 'held', 'failed']
ResumeFailure = Literal[
    'own-ledger',
    'key-changed',
    'position-refused',
    'no-matching-event',
    'later-accept',
    'empty-with-accepts',
    'position-uncountersigned',
    'position-signature-invalid',
    'session-expired',
]

_SIGNATURE_FIELDS = ('signature', 'key_id', 'signer_seq')


@dataclass(frozen=True)
class ResumeContinue:
    """Continue the Task (§5.5 step 6), after attempting again what `not_performed` names if it still needs it."""

    task: AuditedTask
    not_performed: list[str] = field(default_factory=list)
    """Accesses reported `not-performed`, which may be attempted again (step 5)."""
    indeterminate: list[str] = field(default_factory=list)
    """Accesses reported `indeterminate`, to settle before any new attempt (§8.6)."""
    state: Literal['continue'] = 'continue'
    # end class


@dataclass(frozen=True)
class ResumeDelivered:
    """The Task was already terminal; its records are delivered (§5.5)."""

    task: AuditedTask
    not_performed: list[str] = field(default_factory=list)
    indeterminate: list[str] = field(default_factory=list)
    state: Literal['delivered'] = 'delivered'
    # end class


@dataclass(frozen=True)
class ResumeClosed:
    """The own ledger shows the close: complete the move to the terminal state (§5.5 step 6)."""

    task: AuditedTask
    state: Literal['closed'] = 'closed'
    # end class


@dataclass(frozen=True)
class ResumeHeld:
    """The audit host could not be reached at `step`: hold the Task with `status`, and resume again later."""

    step: int
    status: AuditStatus
    state: Literal['held'] = 'held'
    # end class


@dataclass(frozen=True)
class ResumeFailed:
    """A check failed for `reason`: move the Task to `TASK_STATE_FAILED` (§5.5)."""

    reason: ResumeFailure
    state: Literal['failed'] = 'failed'
    # end class


ResumeResult = ResumeContinue | ResumeDelivered | ResumeClosed | ResumeHeld | ResumeFailed
"""What the caller does next (§5.5), told apart by `state`."""


@dataclass
class _Restored:
    """What step 1 restores from the own ledger."""

    task_id: str
    request: AuditRequest
    key_id: str | None
    host_key_snapshot: Mapping[str, Any] | None
    sent: list[dict[str, object]] = field(default_factory=list)
    attempts: dict[str, dict[str, object]] = field(default_factory=dict)
    outcomes: dict[str, dict[str, object]] = field(default_factory=dict)
    responses: dict[str, dict[str, object]] = field(default_factory=dict)
    performing: set[str] = field(default_factory=set)
    records: set[str] = field(default_factory=set)
    resolved: dict[str, str] = field(default_factory=dict)
    acked: set[str] = field(default_factory=set)
    closed: bool = False
    next_signer_seq: int = 0
    # end class


def _restore(entries: list[JournalEntry], credentials: AuditCredentials) -> _Restored:
    """Fold the own ledger's entries into the state step 1 restores.

    Raises:
        SelfLedgerError: The ledger does not begin with the session, or holds a second one.
    """
    if not entries or entries[0].get('entry') != 'session':
        raise SelfLedgerError('the own ledger does not begin with the session')
        # end if
    first = entries[0]
    journaled = dict(first['request'])  # type: ignore[call-overload]
    journaled['auditEndpoint'] = {
        'url': journaled['auditEndpoint']['url'],
        'authentication': credentials.authentication.to_wire(),
        **({} if credentials.token is None else {'token': credentials.token}),
    }
    restored = _Restored(
        task_id=str(first['taskId']),
        request=AuditRequest.model_validate(journaled),
        key_id=first.get('keyId'),  # type: ignore[arg-type]
        host_key_snapshot=first.get('hostKeySnapshot'),  # type: ignore[arg-type]
    )
    for entry in entries[1:]:
        kind = entry.get('entry')
        if kind == 'session':
            raise SelfLedgerError('the own ledger holds a second session')
        elif kind == 'sent':
            event: dict[str, object] = entry['event']  # type: ignore[assignment]
            restored.sent.append(event)
            (restored.attempts if event.get('outcome') == 'attempted' else restored.outcomes)[str(event['id'])] = event
            signer_seq = event.get('signer_seq')
            if isinstance(signer_seq, int):
                restored.next_signer_seq = max(restored.next_signer_seq, signer_seq + 1)
                # end if
        elif kind == 'response':
            restored.responses[str(entry['id'])] = entry['response']  # type: ignore[assignment]
        elif kind == 'performing':
            restored.performing.add(str(entry['id']))
        elif kind == 'record':
            restored.records.add(str(entry['id']))
        elif kind == 'resolved':
            restored.resolved[str(entry['id'])] = str(entry['outcome'])
        elif kind == 'acked':
            restored.acked.add(str(entry['id']))
        elif kind == 'close':
            restored.closed = True
            # end if
        # end for
    return restored
    # end def


def _reported_attempt_of(event: Mapping[str, object]) -> str | None:
    """The attempt an execution report names, or None for any other event."""
    if event.get('action_type') != EXECUTION_REPORT_ACTION_TYPE:
        return None
        # end if
    context = event.get('action_context')
    attempt_id = context.get('attemptId') if isinstance(context, dict) else None
    return attempt_id if isinstance(attempt_id, str) else None
    # end def


async def resume_task(
    *,
    self_ledger: SelfLedger,
    credentials: AuditCredentials,
    post: Post,
    signer: EventSigner | None = None,
    terminal: bool = False,
    deps: Deps | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    fetch_host_keys: FetchHostKeys | None = None,
) -> ResumeResult:
    """Resume a Task from its own ledger after a Server Agent restart (§5.5).

    Args:
        self_ledger: The Task's partition of the Server Agent's own ledger.
        credentials: The endpoint's credentials and token, from where the Server Agent holds them as secrets
            (§13.2).
        post: The HTTP POST (`AuditEndpointClient`).
        signer: Under Level 2, the signer of the key the session is bound to (§5.2).
        terminal: The Task was in a terminal state at the restart: resumption only delivers (§5.5).
        deps: a-MCP's clock and id source.
        timeout: The bound on each POST, in seconds (§6.8).
        fetch_host_keys: Under `countersign: "host"`, fetches `hostKeys` again for a `kid` the Task's own ledger
            does not hold (§10.2); see `AuditedTask`.

    Returns:
        What the caller does next.

    Raises:
        ValueError: `countersign: "host"` without `fetch_host_keys`.
        SelfLedgerError: An entry could not be written while resuming. Nothing it would have preceded was done;
            resume again, which repeats no step whose effect the ledger holds.
    """
    clock = deps if deps is not None else SystemDeps()

    # Step 1.
    try:
        restored = _restore(await self_ledger.entries(), credentials)
    except SelfLedgerError:
        return ResumeFailed('own-ledger')
        # end try
    request = restored.request
    if restored.key_id != (None if signer is None else signer.key_id) or (request.level == Level.L2) != (
        signer is not None
    ):
        return ResumeFailed('key-changed')
        # end if
    task = AuditedTask(
        task_id=restored.task_id,
        request=request,
        post=post,
        signer=signer,
        host_key_snapshot=restored.host_key_snapshot,
        deps=deps,
        timeout=timeout,
        self_ledger=self_ledger,
        resumed_at=restored.next_signer_seq,
        fetch_host_keys=fetch_host_keys,
    )
    client = task.client
    countersignatures = (
        HostKeysVerifier(str(request.hostKeys), restored.host_key_snapshot, fetch_host_keys)
        if request.countersign == Countersign.HOST and restored.host_key_snapshot is not None
        else None
    )

    def held(step: int, *, attempt: str | None = None, outcome: str | None = None) -> ResumeResult:
        """A hold whose auditStatus names the submission it is about: an attempt, an outcome, or none."""
        if attempt is not None:
            failure = client.attempt_failure_of(attempt)
        elif outcome is not None:
            failure = client.outcome_failure_of(outcome)
        else:
            failure = client.last_failure
            # end if
        http_status = None if failure is None else failure.http_status
        attempt_id = attempt if attempt is not None else outcome
        return ResumeHeld(
            step=step,
            status=AuditStatus.model_validate(
                {
                    'reason': 'host-unavailable',
                    **({} if http_status in (None, 200) else {'httpStatus': http_status}),
                    **({} if attempt_id is None else {'attemptId': attempt_id}),
                }
            ),
        )
        # end def

    async def countersigned(
        seq: int,
        host_ts: str,
        log_id: str | None,
        previous_hash: str,
        record_hash: str,
        host_key_id: str | None,
        host_signature: str | None,
    ) -> str | None:
        """None when the countersignature verifies; 'unavailable' when the keys could not be fetched; otherwise
        the a-MCP abort reason (a-MCP §7.2)."""
        if host_signature is None or host_key_id is None or log_id is None or countersignatures is None:
            return 'host-uncountersigned'
            # end if
        payload = countersignature_payload(seq, host_ts, log_id, previous_hash, record_hash)
        verdict = await countersignatures.verify(host_key_id, host_signature, payload)
        if verdict == 'unavailable':
            return 'unavailable'
            # end if
        return None if verdict else 'host-signature-invalid'
        # end def

    # Step 2. An attempt answered `unavailable` is resent as one never answered (a-MCP §7.1).
    accepted_before = [rid for rid, response in restored.responses.items() if response.get('status') == 'accept']

    def answered(event_id: str) -> bool:
        response = restored.responses.get(event_id)
        return response is not None and response.get('status') != 'unavailable'
        # end def

    accepted_on_resend: dict[str, AcceptResponse] = {}
    # A reject the ledger holds whose aborted outcome was not written before the restart.
    refused: dict[str, str] = {
        rid: 'host-rejected'
        for rid, response in restored.responses.items()
        if response.get('status') == 'reject' and rid not in restored.outcomes
    }
    for event in restored.sent:
        event_id = str(event['id'])
        if event.get('outcome') == 'attempted':
            if answered(event_id) or event_id in restored.outcomes:
                continue
                # end if
            response = await client.resend_attempt(event)
            if response.status == 'unavailable':
                return held(2, attempt=event_id)
            elif isinstance(response, AcceptResponse):
                accepted_on_resend[event_id] = response
            else:
                refused[event_id] = 'host-rejected'
                # end if
        elif event_id not in restored.acked:
            await client.resend_outcome(event)
            if client.owed:
                return held(2, outcome=event_id)
                # end if
            # end if
        # end for

    # Step 3.
    position = await client.position()
    if position == 'refused':
        return ResumeFailed('position-refused')
    elif position is None or isinstance(position, str):
        return held(3)
        # end if
    accepted_seqs = [int(restored.responses[rid]['seq']) for rid in accepted_before]  # type: ignore[call-overload]
    accepted_seqs += [response.seq for response in accepted_on_resend.values()]
    check = check_position(position, HeldState(events=restored.sent, accepted_seqs=accepted_seqs))
    if not check.ok:
        # A failed check names its reason; one that did not is read as matching nothing.
        return ResumeFailed(check.reason or 'no-matching-event')
        # end if
    last = position.last
    if request.countersign == Countersign.HOST and last is not None:
        refusal = await countersigned(
            last.seq,
            last.host_ts,
            last.log_id,
            last.previous_hash,
            last.record_hash,
            last.host_key_id,
            last.host_signature,
        )
        if refusal == 'unavailable':
            return held(3)
            # end if
        if refusal is not None:
            return ResumeFailed(
                'position-uncountersigned' if refusal == 'host-uncountersigned' else 'position-signature-invalid',
            )
            # end if
        # end if

    # Every accept not yet acted on is checked as a-MCP checks any accept (a-MCP §7.2), including one a restart
    # caught before a failed check's abort was written.
    unchecked: dict[str, AcceptResponse] = {
        rid: AcceptResponse.model_validate(restored.responses[rid], context=WIRE)
        for rid in accepted_before
        # One written as performing passed the check and may have been performed; keys may have changed since.
        if rid not in restored.outcomes and rid not in restored.performing
    }
    unchecked.update(accepted_on_resend)
    for event_id, accept in unchecked.items():
        attempt = restored.attempts[event_id]
        refusal = None
        if request.countersign == Countersign.HOST:
            refusal = await countersigned(
                accept.seq,
                accept.host_ts,
                accept.log_id,
                accept.previous_hash,
                accept.record_hash,
                accept.host_key_id,
                accept.host_signature,
            )
            if refusal == 'unavailable':
                return held(2, attempt=event_id)
                # end if
            # end if
        if refusal is None and (
            compute_record_hash(attempt, accept.seq, accept.host_ts, accept.previous_hash) != accept.record_hash
        ):
            refusal = 'hash-mismatch'
            # end if
        if refusal is not None:
            accepted_on_resend.pop(event_id, None)
            if event_id in accepted_before:
                accepted_before.remove(event_id)
                # end if
            refused[event_id] = refusal
            # end if
        # end for

    # Step 4.
    reported = {
        attempt_id
        for event_id, event in restored.attempts.items()
        if (event_id in accepted_before or event_id in accepted_on_resend)
        and restored.outcomes.get(event_id, {}).get('outcome') != 'aborted'
        and (attempt_id := _reported_attempt_of(event)) is not None
    }
    task._restore_accepts(
        {
            event_id
            for event_id in [*accepted_before, *accepted_on_resend]
            if _reported_attempt_of(restored.attempts.get(event_id, {})) is None
            and event_id not in restored.outcomes
            and event_id not in restored.records
        },
        reported,
    )
    not_performed: list[str] = []
    indeterminate: list[str] = []
    for event_id, reason in refused.items():
        if not await task._emit_outcome(restored.attempts[event_id], 'aborted', reason):
            return held(4, outcome=event_id)
            # end if
        # end for
    for event_id in [*accepted_before, *accepted_on_resend]:
        attempt_event = restored.attempts.get(event_id)
        if event_id in restored.outcomes or attempt_event is None:
            continue
            # end if
        # A report, and a record that is not an access (§8.1), is completed with its `success` outcome, not
        # reported on.
        if attempt_event.get('action_type') == EXECUTION_REPORT_ACTION_TYPE or event_id in restored.records:
            if not await task._emit_outcome(attempt_event, 'success'):
                return held(4, outcome=event_id)
                # end if
            continue
            # end if
        if event_id in reported:
            continue
            # end if
        resolved = restored.resolved.get(event_id)
        if resolved is not None and event_id in accepted_before:
            if not await task._emit_outcome(attempt_event, resolved):
                return held(4, outcome=event_id)
                # end if
            continue
            # end if
        execution = (
            Execution.INDETERMINATE
            if event_id in accepted_before and event_id in restored.performing
            else Execution.NOT_PERFORMED
        )
        try:
            await task.report_execution(event_id, execution)
        except AmcpAbortedError as error:
            return ResumeHeld(step=4, status=task.status_of(error, event_id))
            # end try
        (indeterminate if execution == Execution.INDETERMINATE else not_performed).append(event_id)
        # end for

    # Step 6.
    if restored.closed:
        return ResumeClosed(task) if await client.close() else held(6)
        # end if
    if terminal:
        return ResumeDelivered(task, not_performed, indeterminate)
        # end if
    if _instant(clock.now()) >= _instant(request.expiresAt):
        return ResumeFailed('session-expired')
        # end if
    return ResumeContinue(task, not_performed, indeterminate)
    # end def


def _instant(timestamp: str) -> datetime:
    """Parse an RFC 3339 timestamp."""
    return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    # end def
