"""The verifier (§11): a-MCP's verification of the partition, and this extension's checks per session."""

import dataclasses
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from auditable_mcp import SPEC_VERSION
from auditable_mcp.l2 import Ed25519Signer, generate_tool_key, public_jwk
from auditable_mcp.l2.algorithms import KeyRole, SignatureAlgorithm

from auditable_a2a import Countersign, Level, execution_report, key_id_of
from auditable_a2a.audit_host import A2aAuditHost
from auditable_a2a.endpoint_handler import create_audit_endpoint_handler
from auditable_a2a.session_store import EndCause, InMemorySessionStore, SessionEnd, SessionState
from auditable_a2a.verify import A2aFinding, RecordAfterClose, SessionEvidence, verify_a2a_ledger

_TASK = 'task-1'
_AGENT_KEYS = 'https://agent.example/.well-known/jwks.json'


class _Clock:
    """A clock one second further on at each reading."""

    def __init__(self) -> None:
        """Start at the epoch of the tests."""
        self._n = 0
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return (datetime(2026, 10, 15, tzinfo=UTC) + timedelta(seconds=self._n)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        # end def

    # end class


def _id(n: int) -> str:
    """A stable valid event id."""
    return f'0199a3e1-0000-7000-8000-{n:012x}'
    # end def


def _event(session_id: str, n: int, outcome: str = 'attempted') -> dict[str, object]:
    """Build a wire event of the session."""
    return {
        'id': _id(n),
        'spec_version': SPEC_VERSION,
        'ts': '2026-10-15T00:00:00.000Z',
        'session_id': session_id,
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': outcome,
    }
    # end def


def _report(session_id: str, n: int, attempt_id: str) -> dict[str, object]:
    """Build an execution report's attempt."""
    return execution_report(
        {
            'id': _id(n),
            'ts': '2026-10-15T00:00:00.000Z',
            'sessionId': session_id,
            'attemptId': attempt_id,
            'execution': 'not-performed',
        },
        'attempted',
    )
    # end def


class _Sender:
    """Posts submissions through the ASGI endpoint with one credential."""

    def __init__(self, host: A2aAuditHost, scheme: str, credentials: str) -> None:
        """Bind to the host's endpoint."""
        self._app = create_audit_endpoint_handler(host)
        self._header = f'{scheme} {credentials}'.encode('latin-1')
        # end def

    async def __call__(self, body: object) -> int:
        """POST one submission; return the status."""
        sent: list[dict[str, Any]] = []
        messages = [{'type': 'http.request', 'body': json.dumps(body).encode('utf-8'), 'more_body': False}]

        async def receive() -> dict[str, Any]:
            return messages.pop(0)
            # end def

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)
            # end def

        scope = {'type': 'http', 'method': 'POST', 'headers': [(b'authorization', self._header)]}
        await self._app(scope, receive, send)
        return int(sent[0]['status'])
        # end def

    # end class


async def _l1() -> tuple[A2aAuditHost, str, _Sender]:
    """An L1 audit host with one session open."""
    host = A2aAuditHost.create('client-a', Level.L1, Countersign.NONE, store=InMemorySessionStore(), clock=_Clock())
    session_id, auth = await host.open_session(delegate='https://agent.example', expires_at='2026-11-15T00:00:00Z')
    return host, session_id, _Sender(host, auth.scheme, auth.credentials)
    # end def


def _evidence(state: SessionState | None) -> SessionEvidence:
    """The verifier's view of a session the host keeps."""
    assert state is not None
    return SessionEvidence(
        session_id=state.session_id,
        level=state.level,
        version=state.version,
        countersign=state.countersign,
        attestation_keys=state.attestation_keys,
        key_snapshot=state.key_snapshot,
        bound_key_id=state.bound_key_id,
        end=state.end,
        anomalies=tuple(state.anomalies),
    )
    # end def


class TestACleanSession:
    """A clean session."""

    async def test_verifies_complete_once_it_has_ended(self) -> None:
        host, session_id, send = await _l1()
        await send({'taskId': _TASK, 'event': _event(session_id, 1)})
        await send({'taskId': _TASK, 'event': _event(session_id, 1, 'success')})
        await send({'taskId': _TASK, 'close': True})
        result = verify_a2a_ledger(host.records(), [_evidence(host.session(session_id))], anchored_digest=host.digest())
        assert result.findings == []
        assert result.complete
        # end def

    async def test_reports_the_end_it_could_not_check_while_open(self) -> None:
        host, session_id, send = await _l1()
        await send({'taskId': _TASK, 'event': _event(session_id, 1)})
        result = verify_a2a_ledger(host.records(), [_evidence(host.session(session_id))])
        assert result.unchecked == [f'end of session {session_id}: not recorded']
        assert not result.complete
        # end def

    # end class


class TestAfterTheEnd:
    """Check 2 (§11)."""

    async def test_lists_a_record_sealed_after_a_close(self) -> None:
        host, session_id, send = await _l1()
        await send({'taskId': _TASK, 'event': _event(session_id, 1)})
        await send({'taskId': _TASK, 'close': True})
        await send({'taskId': _TASK, 'event': _event(session_id, 1, 'success')})
        result = verify_a2a_ledger(host.records(), [_evidence(host.session(session_id))])
        assert result.findings == []
        assert result.records_after_close == [RecordAfterClose(session_id, 1, str(host.records()[1].event['id']))]
        assert result.complete
        # end def

    async def test_finds_an_attempt_sealed_after_the_end_the_evidence_records(self) -> None:
        host, session_id, send = await _l1()
        await send({'taskId': _TASK, 'event': _event(session_id, 1)})
        await send({'taskId': _TASK, 'event': _event(session_id, 2)})
        evidence = dataclasses.replace(
            _evidence(host.session(session_id)),
            end=SessionEnd(cause=EndCause.CLIENT_NOTICE, at='2026-10-15T00:00:01Z', last_seq=0),
        )
        result = verify_a2a_ledger(host.records(), [evidence])
        assert [(f.code, f.tier1, f.seq) for f in result.findings] == [
            (A2aFinding.ATTEMPT_AFTER_END, 'replay-detected', 1)
        ]
        # end def

    # end class


async def test_finds_an_unmatched_and_a_duplicated_execution_report() -> None:
    """Check 3 (§8.6, §11)."""
    host, session_id, send = await _l1()
    await send({'taskId': _TASK, 'event': _event(session_id, 1)})
    await send({'taskId': _TASK, 'event': _report(session_id, 2, _id(99))})
    await send({'taskId': _TASK, 'event': _report(session_id, 3, _id(1))})
    await send({'taskId': _TASK, 'event': _report(session_id, 4, _id(1))})
    await send({'taskId': _TASK, 'close': True})
    result = verify_a2a_ledger(host.records(), [_evidence(host.session(session_id))])
    assert [(f.code, f.tier1, f.id) for f in result.findings] == [
        (A2aFinding.REPORT_UNMATCHED, 'orphaned-outcome', _id(2)),
        (A2aFinding.REPORT_DUPLICATED, 'replay-detected', _id(4)),
    ]
    # end def


async def test_reads_an_unresolved_attempt_resolved_after_the_end_as_resolved() -> None:
    """Check 4 (§5.4, §11)."""
    host, session_id, send = await _l1()
    await send({'taskId': _TASK, 'event': _event(session_id, 1)})
    await send({'taskId': _TASK, 'event': _event(session_id, 2)})
    await host.end_session(session_id)
    await send({'taskId': _TASK, 'event': _event(session_id, 1, 'success')})
    await send({'taskId': _TASK, 'event': _report(session_id, 3, _id(2))})
    result = verify_a2a_ledger(host.records(), [_evidence(host.session(session_id))])
    assert sorted(result.resolved_after_end) == [_id(1), _id(2)]
    assert result.findings == []
    # end def


async def test_one_key_per_session() -> None:
    """Check 1 (§5.1, §11): signatures against the snapshot, and a record under another key found."""
    key = generate_tool_key(key_id_of(_AGENT_KEYS, 'a1'))
    jwk = {
        k: v
        for k, v in public_jwk('a1', key.public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL).items()  # type: ignore[arg-type]
        if k != 'amcp_role'
    }
    host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, store=InMemorySessionStore(), clock=_Clock())
    session_id, auth = await host.open_session(
        delegate='https://agent.example',
        expires_at='2026-11-15T00:00:00Z',
        attestation_keys=_AGENT_KEYS,
        key_snapshot={'keys': [jwk]},
    )
    send = _Sender(host, auth.scheme, auth.credentials)
    signer = Ed25519Signer.from_tool_key(key)
    await send({'taskId': _TASK, 'event': await signer.sign(_event(session_id, 1), 0)})
    await host.end_session(session_id)
    evidence = _evidence(host.session(session_id))
    assert not verify_a2a_ledger(host.records(), [evidence]).amcp.unchecked
    tampered = dataclasses.replace(evidence, bound_key_id=key_id_of(_AGENT_KEYS, 'other'))
    assert [f.code for f in verify_a2a_ledger(host.records(), [tampered]).findings] == ['signature-invalid']
    no_snapshot = dataclasses.replace(evidence, key_snapshot=None)
    assert (
        f'signatures of session {session_id}: no key snapshot'
        in verify_a2a_ledger(host.records(), [no_snapshot]).unchecked
    )
    # end def


class TestTheVersion:
    """§4.1, §11 Inputs: the version a session was opened for."""

    async def test_reports_a_session_of_another_version_or_of_none_recorded_as_not_checked(self) -> None:
        host, session_id, send = await _l1()
        await send({'taskId': _TASK, 'event': _event(session_id, 1)})
        await send({'taskId': _TASK, 'close': True})
        evidence = _evidence(host.session(session_id))
        later = dataclasses.replace(evidence, version='https://timberlandchapel.com/a2a/extensions/auditable-a2a/0.2')
        result = verify_a2a_ledger(host.records(), [later])
        assert result.unchecked == [f'session {session_id}: version {later.version} is not implemented']
        assert result.amcp.issues == []
        assert not result.complete
        unversioned = dataclasses.replace(evidence, version=None)
        assert verify_a2a_ledger(host.records(), [unversioned]).unchecked == [
            f'version of session {session_id}: not recorded'
        ]
        # end def

    # end class


async def test_an_execution_report_that_names_an_execution_report_is_unmatched() -> None:
    """§8.6."""
    host, session_id, send = await _l1()
    await send({'taskId': _TASK, 'event': _event(session_id, 1)})
    await send({'taskId': _TASK, 'event': _report(session_id, 2, _id(1))})
    await send({'taskId': _TASK, 'event': _report(session_id, 3, _id(2))})
    result = verify_a2a_ledger(host.records(), [_evidence(host.session(session_id))])
    assert [(f.code, f.id) for f in result.findings] == [(A2aFinding.REPORT_UNMATCHED, _id(3))]
    # end def


async def test_a_missing_anomaly_set_of_an_ended_session_is_not_checked() -> None:
    """§11 Inputs."""
    host, session_id, send = await _l1()
    await send({'taskId': _TASK, 'event': _event(session_id, 1)})
    await send({'taskId': _TASK, 'close': True})
    evidence = dataclasses.replace(_evidence(host.session(session_id)), anomalies=None)
    assert verify_a2a_ledger(host.records(), [evidence]).unchecked == [
        f'anomaly set of session {session_id}: not recorded'
    ]
    # end def


async def test_a_key_snapshot_that_is_not_a_conforming_key_set_leaves_the_signatures_unchecked() -> None:
    """§11 Inputs: reported, not raised."""
    host, session_id, send = await _l1()
    await send({'taskId': _TASK, 'event': _event(session_id, 1)})
    await send({'taskId': _TASK, 'close': True})
    broken = dataclasses.replace(
        _evidence(host.session(session_id)),
        level=Level.L2,
        attestation_keys=_AGENT_KEYS,
        key_snapshot={'keys': [{'kty': 'OKP'}]},
    )
    assert f'signatures of session {session_id}: the key snapshot is not a conforming key set' in (
        verify_a2a_ledger(host.records(), [broken]).unchecked
    )
    # end def


async def test_an_execution_report_the_server_agent_aborted_is_not_counted() -> None:
    """§8.6: the report that follows an aborted one is not a duplicate."""
    host, session_id, send = await _l1()
    await send({'taskId': _TASK, 'event': _event(session_id, 1)})
    await send({'taskId': _TASK, 'event': _report(session_id, 2, _id(1))})
    aborted = {**_report(session_id, 2, _id(1)), 'outcome': 'aborted', 'reason': 'host-signature-invalid'}
    await send({'taskId': _TASK, 'event': aborted})
    await send({'taskId': _TASK, 'event': _report(session_id, 3, _id(1))})
    await send({'taskId': _TASK, 'event': {**_report(session_id, 3, _id(1)), 'outcome': 'success'}})
    await send({'taskId': _TASK, 'close': True})
    assert verify_a2a_ledger(host.records(), [_evidence(host.session(session_id))]).findings == []
    # end def


async def test_a_report_naming_the_type_without_its_shape_is_unmatched() -> None:
    """§8.6, §11 check 3."""
    host, session_id, send = await _l1()
    await send({'taskId': _TASK, 'event': _event(session_id, 1)})
    await send({'taskId': _TASK, 'event': {**_report(session_id, 2, _id(1)), 'egress': True}})
    result = verify_a2a_ledger(host.records(), [_evidence(host.session(session_id))])
    assert [(f.code, f.id) for f in result.findings] == [(A2aFinding.REPORT_UNMATCHED, _id(2))]
    # end def
