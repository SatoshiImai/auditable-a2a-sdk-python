"""The audit host and its HTTP endpoint (§5, §6), driven through the ASGI app as a Server Agent would."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from auditable_mcp import SPEC_VERSION, InMemoryLedgerRepository, RepositoryError
from auditable_mcp.l2 import Ed25519Signer, generate_tool_key, public_jwk
from auditable_mcp.l2.algorithms import KeyRole, SignatureAlgorithm
from auditable_mcp.ledger import SealedRecord

from auditable_a2a import EXTENSION_URI, Countersign, Level, execution_report, key_id_of
from auditable_a2a.audit_host import A2aAuditHost, IssuedAuthentication
from auditable_a2a.endpoint_handler import AsgiApp, create_audit_endpoint_handler
from auditable_a2a.session_store import InMemorySessionStore, SessionState, SessionStoreError

_JWKS_URL = 'https://agent.example/.well-known/jwks.json'
_TASK = 'task-1'
_EXPIRES = '2026-11-15T00:00:00Z'


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


def _event(session_id: str, n: int, outcome: str = 'attempted', **extra: object) -> dict[str, object]:
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
        **extra,
    }
    # end def


async def _post(app: AsgiApp, authentication: IssuedAuthentication, body: object) -> tuple[int, Any]:
    """POST one submission through the ASGI app; return the status and the parsed body."""
    payload = json.dumps(body).encode('utf-8')
    messages = [{'type': 'http.request', 'body': payload, 'more_body': False}]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return messages.pop(0)
        # end def

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        # end def

    header = f'{authentication.scheme} {authentication.credentials}'.encode('latin-1')
    scope = {'type': 'http', 'method': 'POST', 'headers': [(b'authorization', header)]}
    await app(scope, receive, send)
    status = sent[0]['status']
    raw = sent[1]['body']
    return status, (json.loads(raw) if raw else None)
    # end def


async def _l1(
    expires_at: str = _EXPIRES,
) -> tuple[A2aAuditHost, InMemorySessionStore, InMemoryLedgerRepository, str, IssuedAuthentication, AsgiApp]:
    """An L1 audit host with one session open."""
    store = InMemorySessionStore()
    repository = InMemoryLedgerRepository()
    host = A2aAuditHost.create(
        'client-a', Level.L1, Countersign.NONE, store=store, repository=repository, clock=_Clock()
    )
    session_id, authentication = await host.open_session(delegate='https://agent.example', expires_at=expires_at)
    return host, store, repository, session_id, authentication, create_audit_endpoint_handler(host)
    # end def


class TestOneSession:
    """One session from first attempt to close (§5, §6)."""

    async def test_binds_seals_answers_the_position_and_refuses_attempts_after_the_close(self) -> None:
        host, _, _, session_id, auth, app = await _l1()
        status, body = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        assert (status, body['status']) == (200, 'accept')
        state = host.session(session_id)
        assert state is not None and state.bound_task_id == _TASK
        assert (await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1, 'success')}))[0] == 204
        status, body = await _post(app, auth, {'taskId': _TASK, 'position': True})
        assert (status, body['last']['seq']) == (200, 1)
        assert (await _post(app, auth, {'taskId': _TASK, 'close': True}))[0] == 204
        _, after = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 2)})
        assert after == {'status': 'reject', 'reason': 'replay-detected'}
        state = host.session(session_id)
        assert state is not None and state.end is not None and state.end.cause == 'close'
        # end def

    async def test_answers_a_byte_identical_resend_from_the_ledger_even_after_the_end(self) -> None:
        host, _, _, session_id, auth, app = await _l1()
        _, first = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        await host.end_session(session_id)
        _, again = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        assert again == first
        # end def

    async def test_answers_the_position_of_an_empty_session_with_null(self) -> None:
        _, _, _, _, auth, app = await _l1()
        assert await _post(app, auth, {'taskId': _TASK, 'position': True}) == (200, {'last': None})
        # end def

    # end class


class TestAfterTheEnd:
    """After the session ends (§5.4)."""

    async def test_seals_an_outcome_owed_and_admits_an_execution_report(self) -> None:
        host, _, _, session_id, auth, app = await _l1()
        await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 2)})
        await host.end_session(session_id)
        assert [a.kind for a in host.anomalies()] == ['unresolved-attempt', 'unresolved-attempt']
        assert (await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1, 'success')}))[0] == 204
        report = execution_report(
            {
                'id': _id(3),
                'ts': '2026-10-15T00:00:00.000Z',
                'sessionId': session_id,
                'attemptId': _id(2),
                'execution': 'not-performed',
            },
            'attempted',
        )
        _, admitted = await _post(app, auth, {'taskId': _TASK, 'event': report})
        assert admitted['status'] == 'accept'
        assert len([r for r in host.records() if r.event.get('session_id') == session_id]) == 4
        # end def

    async def test_ends_at_expires_at_and_refuses_the_next_attempt(self) -> None:
        host, _, _, session_id, auth, app = await _l1('2026-10-15T00:00:01Z')
        _, late = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        assert late == {'status': 'reject', 'reason': 'replay-detected'}
        state = host.session(session_id)
        assert state is not None and state.end is not None and state.end.cause == 'expiry'
        # end def

    # end class


class TestTheSessionCheck:
    """§6.6."""

    async def test_refuses_another_task_on_a_bound_session_by_submission_kind(self) -> None:
        host, _, _, session_id, auth, app = await _l1()
        await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        _, attempt = await _post(app, auth, {'taskId': 'task-2', 'event': _event(session_id, 2)})
        assert attempt == {'status': 'reject', 'reason': 'replay-detected'}
        assert (await _post(app, auth, {'taskId': 'task-2', 'event': _event(session_id, 1, 'success')}))[0] == 204
        assert [a.kind for a in host.anomalies()] == ['replay-detected']
        assert (await _post(app, auth, {'taskId': 'task-2', 'position': True}))[0] == 403
        assert (await _post(app, auth, {'taskId': 'task-2', 'close': True}))[0] == 403
        # end def

    async def test_answers_401_to_credentials_it_did_not_issue(self) -> None:
        _, _, _, session_id, _, app = await _l1()
        forged = IssuedAuthentication(scheme='Bearer', credentials='not-issued')
        assert (await _post(app, forged, {'taskId': _TASK, 'event': _event(session_id, 1)}))[0] == 401
        # end def

    async def test_answers_400_to_a_body_that_is_not_a_submission(self) -> None:
        _, _, _, _, auth, app = await _l1()
        assert (await _post(app, auth, {'taskId': _TASK, 'position': True, 'close': True}))[0] == 400
        # end def

    # end class


class TestCredentials:
    """§5.7."""

    async def test_retires_the_old_credential_for_attempts_but_keeps_it_for_records_owed(self) -> None:
        host, _, _, session_id, auth, app = await _l1()
        await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        renewed = await host.issue_credentials(session_id)
        assert (await _post(app, renewed, {'taskId': _TASK, 'event': _event(session_id, 2)}))[0] == 200
        assert (await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 3)}))[0] == 401
        assert (await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1, 'success')}))[0] == 204
        # end def

    # end class


class _FailingRepository:
    """A repository whose `append` always fails."""

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Refuse the append."""
        raise RepositoryError('storage down')
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """Hold nothing."""
        return None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Hold nothing."""
        return []
        # end def

    # end class


async def test_answers_503_when_the_outcome_could_not_be_recorded() -> None:
    """§6.3: acknowledged only once recorded."""
    host = A2aAuditHost.create(
        'client-b',
        Level.L1,
        Countersign.NONE,
        store=InMemorySessionStore(),
        repository=_FailingRepository(),
        clock=_Clock(),
    )
    session_id, auth = await host.open_session(delegate='https://agent.example', expires_at=_EXPIRES)
    app = create_audit_endpoint_handler(host)
    aborted = _event(session_id, 1, 'aborted', reason='host-unavailable')
    assert (await _post(app, auth, {'taskId': _TASK, 'event': aborted}))[0] == 503
    # end def


class TestLevel2:
    """§5.1, §10.2."""

    @staticmethod
    def _jwk(public_key: object, kid: str) -> dict[str, object]:
        """Publish a key as an ordinary JWK: no a-MCP role member."""
        jwk = public_jwk(kid, public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)  # type: ignore[arg-type]
        return {key: value for key, value in jwk.items() if key != 'amcp_role'}
        # end def

    async def test_verifies_against_the_snapshot_and_binds_the_first_key(self) -> None:
        tool_key = generate_tool_key(key_id_of(_JWKS_URL, 'k1'))
        other_key = generate_tool_key(key_id_of(_JWKS_URL, 'k2'))
        host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, store=InMemorySessionStore(), clock=_Clock())
        snapshot = {'keys': [self._jwk(tool_key.public_key, 'k1'), self._jwk(other_key.public_key, 'k2')]}
        session_id, auth = await host.open_session(
            delegate='https://agent.example', expires_at=_EXPIRES, attestation_keys=_JWKS_URL, key_snapshot=snapshot
        )
        app = create_audit_endpoint_handler(host)
        signer = Ed25519Signer.from_tool_key(tool_key)
        other = Ed25519Signer.from_tool_key(other_key)
        _, first = await _post(app, auth, {'taskId': _TASK, 'event': await signer.sign(_event(session_id, 1), 0)})
        assert first['status'] == 'accept'
        state = host.session(session_id)
        assert state is not None and state.bound_key_id == key_id_of(_JWKS_URL, 'k1')
        _, switched = await _post(app, auth, {'taskId': _TASK, 'event': await other.sign(_event(session_id, 2), 0)})
        assert switched == {'status': 'reject', 'reason': 'unknown-key'}
        # end def

    async def test_refuses_a_jwks_whose_key_carries_no_alg(self) -> None:
        host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, store=InMemorySessionStore())
        key = generate_tool_key('k1')
        no_alg = {k: v for k, v in self._jwk(key.public_key, 'k1').items() if k != 'alg'}
        with pytest.raises(ValueError, match='alg'):
            await host.open_session(
                delegate='https://agent.example',
                expires_at=_EXPIRES,
                attestation_keys=_JWKS_URL,
                key_snapshot={'keys': [no_alg]},
            )
            # end with
        # end def

    # end class


async def test_a_restart_keeps_every_session_open_and_an_ended_session_ended() -> None:
    """§5.6."""
    host, store, repository, session_id, auth, app = await _l1()
    await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
    second_id, second_auth = await host.open_session(delegate='https://agent.example', expires_at=_EXPIRES)
    await host.end_session(second_id)
    resumed = await A2aAuditHost.resume(
        'client-a', Level.L1, Countersign.NONE, store=store, repository=repository, clock=_Clock()
    )
    resumed_app = create_audit_endpoint_handler(resumed)
    assert (await _post(resumed_app, auth, {'taskId': _TASK, 'event': _event(session_id, 1, 'success')}))[0] == 204
    _, accepted = await _post(resumed_app, auth, {'taskId': _TASK, 'event': _event(session_id, 2)})
    assert accepted['status'] == 'accept'
    state = resumed.session(second_id)
    assert state is not None and state.end is not None and state.end.cause == 'client-notice'
    _, ended = await _post(resumed_app, second_auth, {'taskId': _TASK, 'event': _event(second_id, 9)})
    assert ended == {'status': 'reject', 'reason': 'replay-detected'}
    # end def


class TestAfterARestart:
    """§5.6: the records sealed before a restart."""

    async def test_answer_the_position_are_resolved_at_the_end_and_admit_a_report_after_it(self) -> None:
        _, store, repository, session_id, auth, app = await _l1()
        _, accepted = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        resumed = await A2aAuditHost.resume(
            'client-a', Level.L1, Countersign.NONE, store=store, repository=repository, clock=_Clock()
        )
        after = create_audit_endpoint_handler(resumed)
        _, position = await _post(after, auth, {'taskId': _TASK, 'position': True})
        assert (position['last']['seq'], position['last']['record_hash']) == (accepted['seq'], accepted['record_hash'])
        await resumed.end_session(session_id)
        state = resumed.session(session_id)
        assert state is not None and state.end is not None
        assert [(a.kind, a.id) for a in state.anomalies] == [('unresolved-attempt', _id(1))]
        assert state.end.last_seq == accepted['seq']
        report = execution_report(
            {
                'id': _id(2),
                'ts': '2026-10-15T00:00:00.000Z',
                'sessionId': session_id,
                'attemptId': _id(1),
                'execution': 'not-performed',
            },
            'attempted',
        )
        _, admitted = await _post(after, auth, {'taskId': _TASK, 'event': report})
        assert admitted['status'] == 'accept'
        # end def

    # end class


class TestTheVersion:
    """§4.1, §5.1: the version a session is opened for."""

    async def test_is_recorded_and_a_version_this_host_does_not_implement_is_refused(self) -> None:
        host, _, _, session_id, _, _ = await _l1()
        state = host.session(session_id)
        assert state is not None and state.version == EXTENSION_URI
        with pytest.raises(ValueError, match=r'0\.2'):
            await host.open_session(
                delegate='https://agent.example',
                expires_at=_EXPIRES,
                version='https://timberlandchapel.com/a2a/extensions/auditable-a2a/0.2',
            )
            # end with
        # end def

    # end class


class TestExpiryAndPurge:
    """§5.3, §5.4."""

    async def test_a_sweep_ends_an_expired_session_at_its_expiry(self) -> None:
        host, _, _, session_id, _, _ = await _l1('2026-10-15T00:00:00Z')
        assert await host.sweep() == [session_id]
        state = host.session(session_id)
        assert state is not None and state.end is not None
        assert (state.end.cause, state.end.at) == ('expiry', '2026-10-15T00:00:00Z')
        assert await host.sweep() == []
        # end def

    async def test_purges_only_an_ended_session_after_which_its_credentials_are_not_recognised(self) -> None:
        host, store, _, session_id, auth, app = await _l1()
        with pytest.raises(ValueError, match='not ended'):
            await host.purge(session_id)
            # end with
        await host.end_session(session_id)
        await host.purge(session_id)
        assert host.session(session_id) is None
        assert await store.all() == []
        assert (await _post(app, auth, {'taskId': _TASK, 'position': True}))[0] == 401
        # end def

    # end class


class _FlakyStore(InMemorySessionStore):
    """A session store whose writes fail while `failing` is set."""

    def __init__(self) -> None:
        """Start working."""
        super().__init__()
        self.failing = False
        # end def

    async def put(self, state: SessionState) -> None:
        """Fail, or store."""
        if self.failing:
            raise SessionStoreError('store down')
            # end if
        await super().put(state)
        # end def

    # end class


class TestAFailingStore:
    """§5.1, §5.6: a session store that fails."""

    async def test_leaves_the_session_unbound_and_the_attempt_unrecorded(self) -> None:
        store = _FlakyStore()
        host = A2aAuditHost.create('client-a', Level.L1, Countersign.NONE, store=store, clock=_Clock())
        session_id, auth = await host.open_session(delegate='https://agent.example', expires_at=_EXPIRES)
        app = create_audit_endpoint_handler(host)
        store.failing = True
        _, refused = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        assert refused['status'] == 'unavailable'
        state = host.session(session_id)
        assert state is not None and state.bound_task_id is None
        assert host.records() == []
        store.failing = False
        _, accepted = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        assert accepted['status'] == 'accept'
        state = host.session(session_id)
        assert state is not None and state.bound_task_id == _TASK
        # end def

    async def test_answers_503_when_a_credential_rotation_cannot_be_stored(self) -> None:
        store = _FlakyStore()
        host = A2aAuditHost.create('client-a', Level.L1, Countersign.NONE, store=store, clock=_Clock())
        session_id, _ = await host.open_session(delegate='https://agent.example', expires_at=_EXPIRES)
        second = await host.issue_credentials(session_id)
        app = create_audit_endpoint_handler(host)
        store.failing = True
        assert (await _post(app, second, {'taskId': _TASK, 'position': True}))[0] == 503
        state = host.session(session_id)
        assert state is not None and not state.credentials[0].retired_for_attempts
        # end def

    async def test_keeps_an_anomaly_it_could_not_store_for_the_next_change(self) -> None:
        tool_key = generate_tool_key(key_id_of(_JWKS_URL, 'k1'))
        store = _FlakyStore()
        host = A2aAuditHost.create('client-a', Level.L2, Countersign.NONE, store=store, clock=_Clock())
        session_id, auth = await host.open_session(
            delegate='https://agent.example',
            expires_at=_EXPIRES,
            attestation_keys=_JWKS_URL,
            key_snapshot={'keys': [TestLevel2._jwk(tool_key.public_key, 'k1')]},
        )
        app = create_audit_endpoint_handler(host)
        signer = Ed25519Signer.from_tool_key(tool_key)
        await _post(app, auth, {'taskId': _TASK, 'event': await signer.sign(_event(session_id, 1), 0)})
        # Under Level 2 the resend is refused as a replay of its signer_seq, so only the first answer records it.
        orphan = await signer.sign(_event(session_id, 7, 'success'), 1)
        store.failing = True
        assert (await _post(app, auth, {'taskId': _TASK, 'event': orphan}))[0] == 503
        store.failing = False
        await _post(app, auth, {'taskId': _TASK, 'event': orphan})
        state = host.session(session_id)
        assert state is not None and ('orphaned-outcome', _id(7)) in [(a.kind, a.id) for a in state.anomalies]
        # end def

    # end class


async def test_a_signer_seq_decided_by_a_refusal_is_refused_again_after_a_restart() -> None:
    """§5.6."""
    tool_key = generate_tool_key(key_id_of(_JWKS_URL, 'k1'))
    jwk = TestLevel2._jwk(tool_key.public_key, 'k1')
    store = InMemorySessionStore()
    repository = InMemoryLedgerRepository()
    host = A2aAuditHost.create(
        'client-a', Level.L2, Countersign.NONE, store=store, repository=repository, clock=_Clock()
    )
    session_id, auth = await host.open_session(
        delegate='https://agent.example',
        expires_at=_EXPIRES,
        attestation_keys=_JWKS_URL,
        key_snapshot={'keys': [jwk]},
    )
    signer = Ed25519Signer.from_tool_key(tool_key)
    app = create_audit_endpoint_handler(host)
    await _post(app, auth, {'taskId': _TASK, 'event': await signer.sign(_event(session_id, 1), 0)})
    refused_event = await signer.sign(_event(session_id, 1, 'attempted', action_type='db.write'), 1)
    _, refused = await _post(app, auth, {'taskId': _TASK, 'event': refused_event})
    assert refused == {'status': 'reject', 'reason': 'replay-detected'}
    resumed = await A2aAuditHost.resume(
        'client-a', Level.L2, Countersign.NONE, store=store, repository=repository, clock=_Clock()
    )
    again = await signer.sign(_event(session_id, 2), 1)
    _, answer = await _post(create_audit_endpoint_handler(resumed), auth, {'taskId': _TASK, 'event': again})
    assert answer == {'status': 'reject', 'reason': 'replay-detected'}
    # end def


async def test_a_token_the_audit_host_did_not_issue_is_answered_401() -> None:
    """§6.6."""
    _, _, _, session_id, auth, app = await _l1()
    status, _ = await _post(app, auth, {'taskId': _TASK, 'token': 'guess', 'event': _event(session_id, 1)})
    assert status == 401
    # end def


class TestAnswersThatCarryMore:
    """§6.6, §5.4."""

    async def test_names_the_scheme_in_www_authenticate_on_a_401(self) -> None:
        _, _, _, session_id, _, app = await _l1()
        sent: list[dict[str, Any]] = []
        body = json.dumps({'taskId': _TASK, 'event': _event(session_id, 1)}).encode('utf-8')
        messages = [{'type': 'http.request', 'body': body, 'more_body': False}]

        async def receive() -> dict[str, Any]:
            return messages.pop(0)
            # end def

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)
            # end def

        scope = {'type': 'http', 'method': 'POST', 'headers': [(b'authorization', b'Bearer not-issued')]}
        await app(scope, receive, send)
        assert sent[0]['status'] == 401
        assert (b'www-authenticate', b'Bearer') in sent[0]['headers']
        # end def

    async def test_admits_a_retired_credential_for_the_resend_of_an_attempt_it_sealed(self) -> None:
        host, _, _, session_id, auth, app = await _l1()
        first = await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
        newer = await host.issue_credentials(session_id)
        await _post(app, newer, {'taskId': _TASK, 'position': True})
        assert (await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 2)}))[0] == 401
        assert await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)}) == first
        assert (await _post(app, auth, {'taskId': _TASK, 'position': True}))[0] == 200
        # end def

    # end class


async def test_a_replaced_credential_admits_only_records_of_attempts_sealed_while_it_was_the_newest() -> None:
    """§5.4, §5.7."""
    host, _, _, session_id, auth, app = await _l1()
    await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
    newer = await host.issue_credentials(session_id)
    await _post(app, newer, {'taskId': _TASK, 'event': _event(session_id, 2)})
    assert (await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1, 'success')}))[0] == 204
    assert (await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 2, 'success')}))[0] == 401
    report = execution_report(
        {
            'id': _id(3),
            'ts': '2026-10-15T00:00:00.000Z',
            'sessionId': session_id,
            'attemptId': _id(2),
            'execution': 'not-performed',
        },
        'attempted',
    )
    assert (await _post(app, auth, {'taskId': _TASK, 'event': report}))[0] == 401
    # end def


async def test_an_attempt_naming_the_report_type_without_its_shape_is_not_admitted_after_the_end() -> None:
    """§8.6."""
    host, _, _, session_id, auth, app = await _l1()
    await _post(app, auth, {'taskId': _TASK, 'event': _event(session_id, 1)})
    await host.end_session(session_id)
    disguised = {
        **execution_report(
            {
                'id': _id(2),
                'ts': '2026-10-15T00:00:00.000Z',
                'sessionId': session_id,
                'attemptId': _id(1),
                'execution': 'not-performed',
            },
            'attempted',
        ),
        'mutates': True,
    }
    _, answer = await _post(app, auth, {'taskId': _TASK, 'event': disguised})
    assert answer == {'status': 'reject', 'reason': 'replay-detected'}
    # end def
