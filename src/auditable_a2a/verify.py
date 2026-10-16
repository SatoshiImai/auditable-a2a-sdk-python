"""Verification of a Client's ledger under this extension (§11), after a-MCP's own (a-MCP §11.4).

A session of a version this verifier does not implement, or whose version is not recorded, is reported unchecked
(§4.1, §11 Inputs); its records are still verified as a-MCP records.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from auditable_mcp import ExpectedIdentity, KeyRegistryVerifier, KeyRole, SealedRecord, VerifyReport, verify_ledger
from auditable_mcp.verify import CountersignatureChecker

from auditable_a2a.execution_report import EXECUTION_REPORT_ACTION_TYPE, is_execution_report
from auditable_a2a.keys import registry_from_jwks
from auditable_a2a.models import EXTENSION_URI, Countersign, Level
from auditable_a2a.session_store import SessionAnomaly, SessionEnd, SessionState


class A2aFinding(StrEnum):
    """This extension's findings (§11)."""

    ATTEMPT_AFTER_END = 'timberlandchapel.com/a2a-attempt-after-end'
    REPORT_UNMATCHED = 'timberlandchapel.com/a2a-report-unmatched'
    REPORT_DUPLICATED = 'timberlandchapel.com/a2a-report-duplicated'
    # end class


TIER1_FALLBACK: Final[dict[A2aFinding, str]] = {
    A2aFinding.ATTEMPT_AFTER_END: 'replay-detected',
    A2aFinding.REPORT_UNMATCHED: 'orphaned-outcome',
    A2aFinding.REPORT_DUPLICATED: 'replay-detected',
}
"""The a-MCP Tier-1 code each finding is read as by a consumer that knows only a-MCP (a-MCP §7.6)."""


@dataclass(frozen=True)
class Finding:
    """One finding of §11's checks."""

    code: str
    """An `A2aFinding`, or a-MCP's `signature-invalid` for check 1."""
    tier1: str
    session_id: str
    seq: int
    id: str
    detail: str
    # end class


@dataclass(frozen=True)
class SessionEvidence:
    """What the verifier needs of a session from outside the chain (§11 Inputs)."""

    session_id: str
    level: Level
    version: str | None = None
    """The version the session was opened for (§4.1); a session without it is not checked."""
    countersign: Countersign | None = None
    attestation_keys: str | None = None
    key_snapshot: Mapping[str, Any] | None = None
    bound_key_id: str | None = None
    end: SessionEnd | None = None
    anomalies: Sequence[SessionAnomaly] | None = None
    """The session's anomaly set; None when it was not recorded."""
    # end class


@dataclass(frozen=True)
class RecordAfterClose:
    """A record sealed in a session after the Server Agent closed it, to be read against the reason for the close."""

    session_id: str
    seq: int
    id: str
    # end class


Session = SessionEvidence | SessionState
"""A session as the verifier reads it: the evidence alone, or the whole state an audit host of this SDK keeps."""


@dataclass(frozen=True)
class A2aVerifyReport:
    """a-MCP's verification of the partition and this extension's findings."""

    amcp: VerifyReport
    findings: list[Finding] = field(default_factory=list)
    resolved_after_end: list[str] = field(default_factory=list)
    """Attempts recorded `unresolved-attempt` and resolved after the end (§5.4, §11 check 4)."""
    records_after_close: list[RecordAfterClose] = field(default_factory=list)
    """Records sealed after an end caused by a close, listed apart from the findings (§11 check 2, §13.7)."""
    unchecked: list[str] = field(default_factory=list)
    """Checks that applied and could not run, for lack of an input (§11 Inputs)."""

    @property
    def complete(self) -> bool:
        """True when neither a-MCP nor this extension found anything and nothing was left unchecked."""
        return self.amcp.complete and not self.findings and not self.unchecked
        # end def

    # end class


_Add = Callable[[A2aFinding, Session, SealedRecord, str], None]


def _context(event: Mapping[str, object]) -> Mapping[str, object]:
    """The event's `action_context`, or an empty mapping."""
    context = event.get('action_context')
    return context if isinstance(context, dict) else {}
    # end def


def verify_a2a_ledger(
    records: list[SealedRecord],
    sessions: Sequence[Session],
    *,
    anchored_digest: str | None = None,
    countersignature_checker: CountersignatureChecker | None = None,
    countersignature_required: bool | None = None,
    expected_identity: ExpectedIdentity | None = None,
) -> A2aVerifyReport:
    """Verify a partition of a Client's ledger and the sessions sealed in it (§11).

    Args:
        records: The partition's sealed records, in order.
        sessions: What the audit host keeps for each session (§5.1, §5.4): its `SessionState`, or the
            `SessionEvidence` drawn from another store.
        anchored_digest: The anchored tail digest, when there is one (a-MCP §8.3).
        countersignature_checker: The host-key check, when the chain is countersigned.
        countersignature_required: Whether every record must carry a countersignature; by default, whether
            any session was opened with `countersign: "host"`.
        expected_identity: The identity the partition is expected to hold, passed to a-MCP's verification
            (a-MCP §10.10).

    Returns:
        The report.
    """
    unchecked: list[str] = []
    known: list[Session] = []
    for session in sessions:
        if session.version is None:
            unchecked.append(f'version of session {session.session_id}: not recorded')
        elif session.version != EXTENSION_URI:
            unchecked.append(f'session {session.session_id}: version {session.version} is not implemented')
        else:
            known.append(session)
            # end if
        # end for

    # §5.1: each Level-2 record verifies against the snapshot of its own session.
    checkers: dict[str, KeyRegistryVerifier] = {}
    for session in known:
        if session.level != Level.L2:
            continue
            # end if
        if session.attestation_keys is None or session.key_snapshot is None:
            unchecked.append(f'signatures of session {session.session_id}: no key snapshot')
            continue
            # end if
        try:
            registry = registry_from_jwks(session.attestation_keys, session.key_snapshot, KeyRole.TOOL)
        except ValueError:
            unchecked.append(
                f'signatures of session {session.session_id}: the key snapshot is not a conforming key set'
            )
            continue
            # end try
        checkers[session.session_id] = KeyRegistryVerifier(registry)
        # end for

    def signature_checker(event: Mapping[str, object]) -> bool:
        # A session this verifier cannot check is reported unchecked above; its signatures are not judged invalid.
        verifier = checkers.get(str(event.get('session_id')))
        return verifier is None or verifier.check(event)
        # end def

    any_level_2 = any(session.level == Level.L2 for session in sessions)
    if countersignature_required is None:
        countersignature_required = any(session.countersign == Countersign.HOST for session in sessions)
        # end if
    amcp = verify_ledger(
        records,
        anchored_digest,
        countersignature_checker=countersignature_checker,
        signature_checker=signature_checker if any_level_2 else None,
        expected_identity=expected_identity,
        countersignature_required=countersignature_required,
    )

    findings: list[Finding] = []
    resolved_after_end: list[str] = []
    records_after_close: list[RecordAfterClose] = []

    def add(code: A2aFinding, session: Session, record: SealedRecord, detail: str) -> None:
        findings.append(
            Finding(code, TIER1_FALLBACK[code], session.session_id, record.seq, str(record.event.get('id')), detail)
        )
        # end def

    for session in known:
        own = [record for record in records if record.event.get('session_id') == session.session_id]
        _check_bound_key(session, own, findings, unchecked)
        records_after_close.extend(_check_after_end(session, own, add, unchecked))
        _check_reports(session, own, add)
        if session.anomalies is None:
            if session.end is not None:
                unchecked.append(f'anomaly set of session {session.session_id}: not recorded')
                # end if
            continue
            # end if
        for anomaly in session.anomalies:
            if anomaly.kind == 'unresolved-attempt' and _resolved(anomaly.id, own):
                resolved_after_end.append(anomaly.id)
                # end if
            # end for
        # end for

    recorded = {session.session_id for session in sessions}
    for record in records:
        session_id = record.event.get('session_id')
        if isinstance(session_id, str) and session_id not in recorded:
            unchecked.append(f'session {session_id}: no session record')
            # end if
        # end for
    return A2aVerifyReport(
        amcp=amcp,
        findings=findings,
        resolved_after_end=resolved_after_end,
        records_after_close=records_after_close,
        unchecked=list(dict.fromkeys(unchecked)),
    )
    # end def


def _check_bound_key(session: Session, own: list[SealedRecord], findings: list[Finding], unchecked: list[str]) -> None:
    """Check 1: under Level 2, every record of the session is under the bound key."""
    if session.level != Level.L2:
        return
        # end if
    if session.bound_key_id is None:
        if own:
            unchecked.append(f'bound key of session {session.session_id}: not recorded')
            # end if
        return
        # end if
    for record in own:
        if record.event.get('key_id') != session.bound_key_id:
            findings.append(
                Finding(
                    'signature-invalid',
                    'signature-invalid',
                    session.session_id,
                    record.seq,
                    str(record.event.get('id')),
                    f"under key {record.event.get('key_id')}, not the session's bound key (§5.1)",
                )
            )
            # end if
        # end for
    # end def


def _check_after_end(
    session: Session, own: list[SealedRecord], add: _Add, unchecked: list[str]
) -> list[RecordAfterClose]:
    """Check 2: nothing sealed after the end that the end refuses; the records sealed after a close, apart."""
    if session.end is None:
        if own:
            unchecked.append(f'end of session {session.session_id}: not recorded')
            # end if
        return []
        # end if
    after_close: list[RecordAfterClose] = []
    last_seq = -1 if session.end.last_seq is None else session.end.last_seq
    for record in (candidate for candidate in own if candidate.seq > last_seq):
        is_report = record.event.get('action_type') == EXECUTION_REPORT_ACTION_TYPE
        if record.event.get('outcome') == 'attempted' and not is_report:
            add(
                A2aFinding.ATTEMPT_AFTER_END,
                session,
                record,
                f'attempt sealed after the session ended at seq {last_seq}',
            )
            # end if
        if session.end.cause == 'close':
            after_close.append(RecordAfterClose(session.session_id, record.seq, str(record.event.get('id'))))
            # end if
        # end for
    return after_close
    # end def


def _check_reports(session: Session, own: list[SealedRecord], add: _Add) -> None:
    """Check 3: each execution report names an accepted attempt of the session, once."""
    reported: dict[str, int] = {}
    for record in own:
        event = record.event
        if event.get('action_type') != EXECUTION_REPORT_ACTION_TYPE or event.get('outcome') != 'attempted':
            continue
            # end if
        # A report the Server Agent aborted was not accepted, and a new one may follow it (§8.6).
        if any(c.event.get('id') == event.get('id') and c.event.get('outcome') == 'aborted' for c in own):
            continue
            # end if
        attempt_id = _context(event).get('attemptId')
        attempt = next(
            (
                candidate
                for candidate in own
                if candidate.event.get('id') == attempt_id
                and candidate.event.get('outcome') == 'attempted'
                # An execution report is never itself the subject of one (§8.6).
                and candidate.event.get('action_type') != EXECUTION_REPORT_ACTION_TYPE
                and candidate.seq < record.seq
            ),
            None,
        )
        resolved_by_outcome = any(
            candidate.event.get('id') == attempt_id and candidate.event.get('outcome') != 'attempted'
            for candidate in own
        )
        shaped = is_execution_report(event) and event.get('session_id') == session.session_id
        if attempt is None or resolved_by_outcome or not shaped:
            detail = f'reports on {attempt_id}, no accepted unresolved attempt of this session'
            add(A2aFinding.REPORT_UNMATCHED, session, record, detail)
            continue
            # end if
        count = reported.get(str(attempt_id), 0) + 1
        reported[str(attempt_id)] = count
        if count > 1:
            add(A2aFinding.REPORT_DUPLICATED, session, record, f'a second accepted report on {attempt_id}')
            # end if
        # end for
    # end def


def _resolved(attempt_id: str, own: list[SealedRecord]) -> bool:
    """Check 4: whether an attempt got an outcome or an execution report."""
    return any(
        (record.event.get('id') == attempt_id and record.event.get('outcome') != 'attempted')
        or (
            record.event.get('action_type') == EXECUTION_REPORT_ACTION_TYPE
            and _context(record.event).get('attemptId') == attempt_id
        )
        for record in own
    )
    # end def
