"""The Server Agent's side (§6, §8), run against this SDK's audit host over its ASGI endpoint."""

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from auditable_mcp import AmcpAbortedError
from auditable_mcp.l2 import Ed25519Countersigner, Ed25519Signer, generate_tool_key, public_jwk
from auditable_mcp.l2.algorithms import KeyRole, SignatureAlgorithm

from auditable_a2a import AuditRequest, AuthenticationInfo, Countersign, Level, key_id_of
from auditable_a2a.audit_host import A2aAuditHost
from auditable_a2a.audited_task import AuditedTask, TerminalBound
from auditable_a2a.endpoint_handler import AsgiApp, create_audit_endpoint_handler
from auditable_a2a.session_store import InMemorySessionStore

_ENDPOINT = 'https://audit.client.example/a2a'
_HOST_KEYS = 'https://audit.client.example/keys.json'
_AGENT_KEYS = 'https://agent.example/.well-known/jwks.json'
_TABLE: dict[str, object] = {'kind': 'table', 'ref': 'customers'}


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


class _Network:
    """A `Post` that serves an ASGI app in process, failing the next calls when told to."""

    def __init__(self, app: AsgiApp) -> None:
        """Serve `app`."""
        self._app = app
        self.failures: list[str | int] = []
        # end def

    async def post(self, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        """POST through the app, or fail as told."""
        if self.failures:
            failure = self.failures.pop(0)
            if failure == 'down':
                raise OSError('connection refused')
                # end if
            return int(failure), b''
            # end if
        sent: list[dict[str, Any]] = []
        messages = [{'type': 'http.request', 'body': body, 'more_body': False}]

        async def receive() -> dict[str, Any]:
            return messages.pop(0)
            # end def

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)
            # end def

        scope = {
            'type': 'http',
            'method': 'POST',
            'headers': [(k.encode('latin-1'), v.encode('latin-1')) for k, v in headers.items()],
        }
        await self._app(scope, receive, send)
        return sent[0]['status'], sent[1]['body']
        # end def

    # end class


def _ordinary_jwk(kid: str, public_key: object, role: KeyRole) -> dict[str, object]:
    """Publish a key as an ordinary JWK: no a-MCP role member."""
    jwk = public_jwk(kid, public_key, SignatureAlgorithm.ED25519, role)  # type: ignore[arg-type]
    return {k: v for k, v in jwk.items() if k != 'amcp_role'}
    # end def


async def _setup(
    level: Level = Level.L1, countersign: Countersign = Countersign.NONE
) -> tuple[A2aAuditHost, AuditedTask, _Network, str]:
    """An audit host with one session open, and the Server Agent's Task bound to it."""
    agent_key = generate_tool_key(key_id_of(_AGENT_KEYS, 'a1'))
    host_key = generate_tool_key(key_id_of(_HOST_KEYS, 'h1'))
    countersigned = countersign == Countersign.HOST
    host = A2aAuditHost.create(
        'client-a',
        level,
        countersign,
        store=InMemorySessionStore(),
        clock=_Clock(),
        countersigner=Ed25519Countersigner(host_key.key_id, host_key.private_key) if countersigned else None,
    )
    l2 = level == Level.L2
    session_id, auth = await host.open_session(
        delegate='https://agent.example',
        expires_at='2026-11-15T00:00:00Z',
        attestation_keys=_AGENT_KEYS if l2 else None,
        key_snapshot={'keys': [_ordinary_jwk('a1', agent_key.public_key, KeyRole.TOOL)]} if l2 else None,
        host_keys=_HOST_KEYS if countersigned else None,
    )
    request = AuditRequest.model_validate(
        {
            'auditEndpoint': {
                'url': _ENDPOINT,
                'authentication': {'scheme': auth.scheme, 'credentials': auth.credentials},
            },
            'sessionId': session_id,
            'level': level,
            'countersign': countersign,
            'expiresAt': '2026-11-15T00:00:00Z',
            **({'hostKeys': _HOST_KEYS} if countersigned else {}),
        }
    )
    network = _Network(create_audit_endpoint_handler(host))
    host_keys: dict[str, object] = {'keys': [_ordinary_jwk('h1', host_key.public_key, KeyRole.HOST)]}

    async def fetch_host_keys(url: str) -> Mapping[str, Any]:
        return host_keys
        # end def

    task = AuditedTask(
        task_id='task-1',
        request=request,
        post=network.post,
        signer=Ed25519Signer.from_tool_key(agent_key) if l2 else None,
        host_key_snapshot=host_keys if countersigned else None,
        fetch_host_keys=fetch_host_keys if countersigned else None,
    )
    return host, task, network, session_id
    # end def


class TestRecordedBeforePerformed:
    """§8.1, §8.3."""

    async def test_seals_attempt_and_outcome_and_closes_at_the_end(self) -> None:
        host, task, _, session_id = await _setup()
        async with task.action('db.read', _TABLE, mutates=False, egress=False):
            pass
            # end async with
        assert [r.event['outcome'] for r in host.records()] == ['attempted', 'success']
        assert task.may_end()
        assert await task.finish()
        state = host.session(session_id)
        assert state is not None and state.end is not None and state.end.cause == 'close'
        # end def

    async def test_works_signed_and_countersigned(self) -> None:
        host, task, _, _ = await _setup(Level.L2, Countersign.HOST)
        async with task.action('db.read', _TABLE, mutates=False, egress=False):
            pass
            # end async with
        assert len(host.records()) == 2
        assert host.records()[0].host_signature is not None
        # end def

    # end class


class TestAHold:
    """§8.4."""

    async def test_reads_a_refused_connection_as_unavailable(self) -> None:
        _, task, network, _ = await _setup()
        network.failures.extend(['down', 'down'])
        with pytest.raises(AmcpAbortedError) as raised:
            async with task.action('db.read', _TABLE, mutates=False, egress=False):
                pass
                # end async with
            # end with
        status = task.status_of(raised.value).to_wire()
        assert isinstance(status.pop('attemptId'), str)
        assert status == {'reason': 'host-unavailable'}
        # end def

    async def test_does_not_follow_a_redirect_and_names_the_status(self) -> None:
        _, task, network, _ = await _setup()
        network.failures.append(302)
        with pytest.raises(AmcpAbortedError) as raised:
            async with task.action('db.read', _TABLE, mutates=False, egress=False):
                pass
                # end async with
            # end with
        status = task.status_of(raised.value).to_wire()
        assert isinstance(status.pop('attemptId'), str)
        assert status == {'reason': 'host-unavailable', 'httpStatus': 302}
        # end def

    async def test_names_the_host_reason_of_a_reject(self) -> None:
        host, task, _, session_id = await _setup()
        await host.end_session(session_id)
        with pytest.raises(AmcpAbortedError) as raised:
            async with task.action('db.read', _TABLE, mutates=False, egress=False):
                pass
                # end async with
            # end with
        status = task.status_of(raised.value).to_wire()
        assert isinstance(status.pop('attemptId'), str)
        assert status == {'reason': 'host-rejected', 'hostReason': 'replay-detected'}
        # end def

    async def test_asks_for_new_credentials_on_401_and_records_once_replaced(self) -> None:
        host, task, _, session_id = await _setup()
        task.replace_credentials(AuthenticationInfo(scheme='Bearer', credentials='stale'))
        with pytest.raises(AmcpAbortedError) as raised:
            async with task.action('db.read', _TABLE, mutates=False, egress=False):
                pass
                # end async with
            # end with
        status = task.status_of(raised.value).to_wire()
        assert isinstance(status.pop('attemptId'), str)
        assert status == {'reason': 'host-unavailable', 'httpStatus': 401}
        renewed = await host.issue_credentials(session_id)
        task.replace_credentials(AuthenticationInfo(scheme=renewed.scheme, credentials=renewed.credentials))
        async with task.action('db.read', _TABLE, mutates=False, egress=False):
            pass
            # end async with
        assert [r.event['outcome'] for r in host.records()].count('success') == 1
        # end def

    # end class


async def test_an_unacknowledged_outcome_is_owed_until_flushed() -> None:
    """§5.4, §6.4."""
    host, task, network, _ = await _setup()
    async with task.action('db.read', _TABLE, mutates=False, egress=False):
        network.failures.append(503)
        # end async with
    assert len(task.client.owed) == 1
    assert not task.may_end()
    assert task.may_end(TerminalBound.CANCEL)
    assert await task.client.flush() == 0
    assert [r.event['outcome'] for r in host.records()] == ['attempted', 'success']
    # end def


async def test_the_execution_report_records_an_accept_not_performed() -> None:
    """§8.6."""
    host, task, _, _ = await _setup()
    action = task.action('payment.send', _TABLE, mutates=True, egress=True)
    await action.__aenter__()
    attempt_id = str(host.records()[0].event['id'])
    await task.report_execution(attempt_id, 'not-performed')
    report = next(r for r in host.records() if r.event['action_type'] == 'a2a.execution-report')
    assert report.event['action_context'] == {'attemptId': attempt_id, 'execution': 'not-performed'}
    # end def


async def test_a_countersigning_key_not_named_under_host_keys_is_refused_before_a_session_opens() -> None:
    """§7.1, §10.2: a delegate looks the key up at hostKeys as `{hostKeys}#{kid}`; any other name never verifies."""
    host_key = generate_tool_key('h1')
    host = A2aAuditHost.create(
        'client-a',
        Level.L1,
        Countersign.HOST,
        store=InMemorySessionStore(),
        clock=_Clock(),
        countersigner=Ed25519Countersigner(host_key.key_id, host_key.private_key),
    )
    with pytest.raises(ValueError, match='§7.1'):
        await host.open_session(
            delegate='https://agent.example', expires_at='2026-11-15T00:00:00Z', host_keys=_HOST_KEYS
        )
        # end with
    # end def


async def test_a_countersigned_task_needs_the_means_to_fetch_the_host_keys_again() -> None:
    """§10.2: without it, a rotated key would read as a bad countersignature."""
    _, task, network, _ = await _setup(countersign=Countersign.HOST)
    with pytest.raises(ValueError, match='§10.2'):
        AuditedTask(
            task_id='task-1',
            request=task._request,
            post=network.post,
            host_key_snapshot={'keys': []},
        )
        # end with
    # end def
