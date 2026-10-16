"""Resumption after a Server Agent restart (§5.5), from the Task's own ledger alone."""

import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
import pytest
from auditable_mcp import AmcpAbortedError, InMemoryLedgerRepository, RepositoryError, SealedRecord
from auditable_mcp.l2 import (
    CountersignatureRegistryVerifier,
    Ed25519Countersigner,
    Ed25519Signer,
    generate_tool_key,
    public_jwk,
)
from auditable_mcp.l2.algorithms import KeyRole, SignatureAlgorithm

from auditable_a2a import (
    AuditCredentials,
    AuditRequest,
    AuthenticationInfo,
    Countersign,
    FetchHostKeys,
    Level,
    key_id_of,
    registry_from_jwks,
)
from auditable_a2a.audit_host import A2aAuditHost
from auditable_a2a.audited_task import AuditedTask
from auditable_a2a.endpoint_handler import AsgiApp, create_audit_endpoint_handler
from auditable_a2a.execution_report import EXECUTION_REPORT_ACTION_TYPE
from auditable_a2a.resume import ResumeResult, resume_task
from auditable_a2a.self_ledger import SelfLedger, SelfLedgerError
from auditable_a2a.session_store import InMemorySessionStore
from auditable_a2a.verify import verify_a2a_ledger

_ENDPOINT = 'https://audit.client.example/a2a'
_HOST_KEYS = 'https://audit.client.example/keys.json'
_AGENT_KEYS = 'https://agent.example/.well-known/jwks.json'
_PARTITION = 'tasks/task-1'
_TABLE: dict[str, object] = {'kind': 'table', 'ref': 'customers'}


class _Clock:
    """A clock one second further on at each reading, which also mints event ids."""

    def __init__(self) -> None:
        """Start at the epoch of the tests."""
        self._n = 0
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return (datetime(2026, 10, 15, tzinfo=UTC) + timedelta(seconds=self._n)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        # end def

    def new_id(self) -> str:
        """Return a fresh event id."""
        return str(uuid.uuid4())
        # end def

    # end class


class _FlakyRepository(InMemoryLedgerRepository):
    """A repository whose appends can be made to fail, as a full disk or a lost connection does."""

    def __init__(self) -> None:
        """Start with every append succeeding."""
        super().__init__()
        self.fail_when: Callable[[SealedRecord], bool] | None = None
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Append, unless told to fail this record."""
        if self.fail_when is not None and self.fail_when(record):
            raise RepositoryError('disk full')
            # end if
        await super().append(partition, record)
        # end def

    # end class


class _Network:
    """A `Post` serving an ASGI app in process; each of `modes` shapes one call: None, 'down', 'hang', status, body."""

    def __init__(self, app: AsgiApp) -> None:
        """Serve `app`."""
        self._app = app
        self.modes: list[str | int | dict[str, object] | None] = []
        # end def

    async def post(self, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        """POST through the app, or as the next mode says."""
        mode = self.modes.pop(0) if self.modes else None
        if mode == 'down':
            raise OSError('connection refused')
        elif isinstance(mode, int):
            return mode, b''
        elif isinstance(mode, dict):
            return 200, json.dumps(mode).encode('utf-8')
            # end if
        answer = await self._serve(headers, body)
        if mode == 'hang':
            await anyio.sleep_forever()
            # end if
        return answer
        # end def

    async def _serve(self, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        """One request through the ASGI app."""
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


def _fetcher(snapshot: Mapping[str, Any]) -> FetchHostKeys:
    """A `FetchHostKeys` that answers with `snapshot`."""

    async def fetch(url: str) -> Mapping[str, Any]:
        return snapshot
        # end def

    return fetch
    # end def


@dataclass
class _World:
    """An audit host with one session open, the Server Agent's Task bound to it, and its own ledger."""

    host: A2aAuditHost
    task: AuditedTask
    network: _Network
    repository: _FlakyRepository
    session_id: str
    authentication: AuthenticationInfo
    signer: Ed25519Signer | None
    clock: _Clock
    host_key_snapshot: dict[str, object]

    async def restart(
        self,
        *,
        modes: list[str | int | dict[str, object] | None] | None = None,
        signer: Ed25519Signer | None = None,
        terminal: bool = False,
    ) -> ResumeResult:
        """A new process: the same own ledger and the same audit host, nothing else of the old one."""
        network = _Network(create_audit_endpoint_handler(self.host))
        network.modes.extend(modes or [])
        return await resume_task(
            self_ledger=await SelfLedger.open(self.repository, _PARTITION, self.clock.now),
            credentials=AuditCredentials(authentication=self.authentication),
            post=network.post,
            fetch_host_keys=_fetcher(self.host_key_snapshot),
            signer=signer or self.signer,
            terminal=terminal,
            deps=self.clock,
            timeout=0.05,
        )
        # end def

    def outcomes_of(self, event_id: str) -> list[SealedRecord]:
        """The sealed outcomes of one operation."""
        return [r for r in self.host.records() if r.event['id'] == event_id and r.event['outcome'] != 'attempted']
        # end def

    def reports_on(self, event_id: str) -> list[SealedRecord]:
        """The sealed execution reports on one attempt."""
        return [
            r
            for r in self.host.records()
            if r.event['action_type'] == EXECUTION_REPORT_ACTION_TYPE
            and r.event['outcome'] == 'attempted'
            and r.event['action_context']['attemptId'] == event_id  # type: ignore[index]
        ]
        # end def

    # end class


async def _setup(level: Level = Level.L2, countersign: Countersign = Countersign.HOST) -> _World:
    """Open a session and bind a Task that writes ahead into its own ledger."""
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
    authentication = AuthenticationInfo(scheme=auth.scheme, credentials=auth.credentials)
    request = AuditRequest.model_validate(
        {
            'auditEndpoint': {'url': _ENDPOINT, 'authentication': authentication.to_wire()},
            'sessionId': session_id,
            'level': level,
            'countersign': countersign,
            'expiresAt': '2026-11-15T00:00:00Z',
            **({'hostKeys': _HOST_KEYS} if countersigned else {}),
        }
    )
    repository = _FlakyRepository()
    clock = _Clock()
    signer = Ed25519Signer.from_tool_key(agent_key) if l2 else None
    network = _Network(create_audit_endpoint_handler(host))
    host_key_snapshot: dict[str, object] = {'keys': [_ordinary_jwk('h1', host_key.public_key, KeyRole.HOST)]}
    task = AuditedTask(
        task_id='task-1',
        request=request,
        post=network.post,
        signer=signer,
        host_key_snapshot=host_key_snapshot if countersigned else None,
        fetch_host_keys=_fetcher(host_key_snapshot) if countersigned else None,
        deps=clock,
        self_ledger=await SelfLedger.open(repository, _PARTITION, clock.now),
    )
    return _World(host, task, network, repository, session_id, authentication, signer, clock, host_key_snapshot)
    # end def


def _entry_event(record: SealedRecord) -> dict[str, object]:
    """The event a `sent` entry holds, or an empty dict for any other entry."""
    event = record.event.get('event')
    return event if isinstance(event, dict) else {}
    # end def


async def _read(world: _World) -> str:
    """Perform and resolve one read; return its id."""
    async with world.task.action('db.read', _TABLE, mutates=False, egress=False) as action:
        return action.id
        # end async with
    # end def


async def _accept_then_lose_the_performing_entry(world: _World) -> str:
    """An accept the restart caught before it was written that the access was about to be performed."""
    world.repository.fail_when = lambda record: record.event.get('entry') == 'performing'
    with pytest.raises(SelfLedgerError, match='performing'):
        async with world.task.action('db.write', _TABLE, mutates=True, egress=False):
            pass
            # end async with
        # end with
    world.repository.fail_when = None
    return str(world.host.records()[0].event['id'])
    # end def


async def _hang_an_attempt(world: _World) -> str:
    """An attempt the host sealed whose answer the restart lost."""
    world.network.modes.append('hang')

    async def attempt() -> None:
        async with world.task.action('db.write', _TABLE, mutates=True, egress=False):
            pass
            # end async with
        # end def

    async with anyio.create_task_group() as group:
        group.start_soon(attempt)
        while not world.host.records():
            await anyio.sleep(0)
            # end while
        # The process stops here: nothing more reaches its own ledger or the audit endpoint.
        world.repository.fail_when = lambda record: True
        world.network.modes.extend(['down'] * 8)
        group.cancel_scope.cancel()
        # end async with
    world.repository.fail_when = None
    world.network.modes.clear()
    return str(world.host.records()[0].event['id'])
    # end def


class TestAfterTheAccessResolved:
    """§5.5 steps 2 and 4."""

    async def test_delivers_the_owed_outcome_and_numbers_after_the_last_event(self) -> None:
        world = await _setup()
        world.network.modes.extend([None, 'down'])
        event_id = await _read(world)
        assert len(world.task.client.owed) == 1

        resumed = await world.restart()
        assert resumed.state == 'continue'
        assert [r.event['outcome'] for r in world.outcomes_of(event_id)] == ['success']
        assert resumed.task is not None
        async with resumed.task.action('db.read', _TABLE, mutates=False, egress=False):
            pass
            # end async with
        assert [r.event['signer_seq'] for r in world.host.records()] == [0, 1, 2, 3]
        # end def

    async def test_writes_the_outcome_from_how_the_access_resolved(self) -> None:
        world = await _setup()
        world.repository.fail_when = lambda record: _entry_event(record).get('outcome') == 'failed'
        event_id = ''
        with pytest.raises(RuntimeError):
            async with world.task.action('db.write', _TABLE, mutates=True, egress=False) as action:
                event_id = action.id
                raise RuntimeError('the write failed')
                # end async with
            # end with
        world.repository.fail_when = None
        assert world.outcomes_of(event_id) == []

        resumed = await world.restart()
        assert resumed.state == 'continue'
        assert [r.event['outcome'] for r in world.outcomes_of(event_id)] == ['failed']
        assert world.reports_on(event_id) == []
        # end def

    # end class


class TestNeverPerformedAgain:
    """§5.5 step 4: an accept from before the restart is never performed again."""

    async def test_reports_not_performed_an_accept_it_had_not_started_on(self) -> None:
        world = await _setup()
        event_id = await _accept_then_lose_the_performing_entry(world)

        resumed = await world.restart()
        assert (resumed.state, resumed.not_performed, resumed.indeterminate) == ('continue', [event_id], [])
        assert len(world.reports_on(event_id)) == 1
        assert world.outcomes_of(event_id) == []
        # end def

    async def test_reports_indeterminate_an_accept_it_was_performing(self) -> None:
        world = await _setup()
        action = await world.task.action('db.write', _TABLE, mutates=True, egress=False).__aenter__()

        resumed = await world.restart()
        assert (resumed.state, resumed.not_performed, resumed.indeterminate) == ('continue', [], [action.id])
        report = world.reports_on(action.id)[0]
        assert report.event['action_context']['execution'] == 'indeterminate'  # type: ignore[index]
        # end def

    async def test_reports_not_performed_an_accept_that_first_reaches_it_on_a_resend(self) -> None:
        world = await _setup()
        event_id = await _hang_an_attempt(world)

        resumed = await world.restart()
        assert (resumed.state, resumed.not_performed) == ('continue', [event_id])
        attempts = [r for r in world.host.records() if r.event['id'] == event_id and r.event['outcome'] == 'attempted']
        assert len(attempts) == 1
        assert len(world.reports_on(event_id)) == 1
        # end def

    async def test_completes_a_report_whose_own_outcome_was_never_written(self) -> None:
        world = await _setup()
        event_id = await _accept_then_lose_the_performing_entry(world)
        world.repository.fail_when = lambda record: (
            _entry_event(record).get('action_type') == EXECUTION_REPORT_ACTION_TYPE
            and _entry_event(record).get('outcome') == 'success'
        )
        assert (await world.restart()).state == 'continue'
        world.repository.fail_when = None
        report_id = str(world.reports_on(event_id)[0].event['id'])
        assert world.outcomes_of(report_id) == []

        assert (await world.restart()).state == 'continue'
        assert len(world.reports_on(event_id)) == 1
        assert [r.event['outcome'] for r in world.outcomes_of(report_id)] == ['success']
        # end def

    async def test_resends_a_report_outcome_written_but_not_acknowledged(self) -> None:
        world = await _setup()
        event_id = await _accept_then_lose_the_performing_entry(world)
        # Position, report attempt, then the report's outcome is lost.
        assert (await world.restart(modes=[None, None, 'down'])).state == 'continue'
        report_id = str(world.reports_on(event_id)[0].event['id'])
        assert world.outcomes_of(report_id) == []

        assert (await world.restart()).state == 'continue'
        assert len(world.reports_on(event_id)) == 1
        assert [r.event['outcome'] for r in world.outcomes_of(report_id)] == ['success']
        # end def

    # end class


class TestInterruptedRefusal:
    """§5.5 step 2."""

    async def test_sends_the_aborted_outcome_of_a_reject_it_recorded_but_had_not_answered(self) -> None:
        world = await _setup()
        await world.host.end_session(world.session_id)
        world.repository.fail_when = lambda record: _entry_event(record).get('outcome') == 'aborted'
        with pytest.raises(AmcpAbortedError, match='host-rejected'):
            await _read(world)
            # end with
        world.repository.fail_when = None
        sent = next(r for r in await world.repository.read_all(_PARTITION) if r.event['entry'] == 'sent')
        event_id = str(_entry_event(sent)['id'])
        assert world.outcomes_of(event_id) == []

        await world.restart()
        assert [(r.event['outcome'], r.event['reason']) for r in world.outcomes_of(event_id)] == [
            ('aborted', 'host-rejected')
        ]
        # end def

    # end class


class TestIdempotent:
    """Resuming again changes nothing."""

    async def test_neither_reports_nor_seals_twice_and_the_client_ledger_verifies(self) -> None:
        world = await _setup()
        action = await world.task.action('db.write', _TABLE, mutates=True, egress=False).__aenter__()
        await world.restart()
        sealed = len(world.host.records())
        again = await world.restart()
        assert (again.state, again.not_performed, again.indeterminate) == ('continue', [], [])
        assert len(world.host.records()) == sealed
        assert len(world.reports_on(action.id)) == 1

        await world.host.end_session(world.session_id)
        state = world.host.session(world.session_id)
        assert state is not None
        checker = CountersignatureRegistryVerifier(
            registry_from_jwks(_HOST_KEYS, world.host_key_snapshot, KeyRole.HOST)
        ).check
        report = verify_a2a_ledger(world.host.records(), [state], countersignature_checker=checker)
        assert report.findings == []
        assert report.amcp.complete
        # end def

    # end class


class TestHeld:
    """§5.5: a step that cannot reach the audit host holds the Task."""

    async def test_holds_at_step_3_while_the_position_is_unanswered(self) -> None:
        world = await _setup(Level.L1, Countersign.NONE)
        await _read(world)
        resumed = await world.restart(modes=['down'])
        assert (resumed.state, resumed.step) == ('held', 3)
        assert resumed.status is not None and resumed.status.to_wire() == {'reason': 'host-unavailable'}
        assert (await world.restart()).state == 'continue'
        # end def

    async def test_holds_at_step_2_on_401_asking_for_new_credentials(self) -> None:
        world = await _setup(Level.L1, Countersign.NONE)
        await _hang_an_attempt(world)
        resumed = await world.restart(modes=[401])
        assert (resumed.state, resumed.step) == ('held', 2)
        assert resumed.status is not None
        assert resumed.status.to_wire() == {
            'reason': 'host-unavailable',
            'httpStatus': 401,
            'attemptId': str(world.host.records()[0].event['id']),
        }
        assert (await world.restart()).state == 'continue'
        # end def

    # end class


class TestFailed:
    """§5.5: a check that fails fails the Task."""

    async def test_fails_when_the_own_ledger_does_not_recompute(self) -> None:
        world = await _setup()
        await _read(world)
        records = await world.repository.read_all(_PARTITION)
        records[1] = SealedRecord(
            event={'entry': 'performing', 'id': 'forged'},
            seq=records[1].seq,
            host_ts=records[1].host_ts,
            previous_hash=records[1].previous_hash,
            record_hash=records[1].record_hash,
        )
        tampered = InMemoryLedgerRepository()
        for record in records:
            await tampered.append(_PARTITION, record)
            # end for
        resumed = await resume_task(
            self_ledger=await SelfLedger.open(tampered, _PARTITION),
            credentials=AuditCredentials(authentication=world.authentication),
            post=world.network.post,
            fetch_host_keys=_fetcher(world.host_key_snapshot),
        )
        assert (resumed.state, resumed.reason) == ('failed', 'own-ledger')
        # end def

    async def test_fails_when_the_signer_is_not_the_bound_key(self) -> None:
        world = await _setup()
        await _read(world)
        other = Ed25519Signer.from_tool_key(generate_tool_key(key_id_of(_AGENT_KEYS, 'a2')))
        resumed = await world.restart(signer=other)
        assert (resumed.state, resumed.reason) == ('failed', 'key-changed')
        # end def

    async def test_fails_when_the_position_does_not_recompute(self) -> None:
        world = await _setup(Level.L1, Countersign.NONE)
        await _read(world)
        first, second = world.host.records()
        forged = {
            'seq': second.seq,
            'host_ts': second.host_ts,
            'previous_hash': second.previous_hash,
            'record_hash': first.record_hash,
        }
        resumed = await world.restart(modes=[{'last': forged}])
        assert (resumed.state, resumed.reason) == ('failed', 'no-matching-event')
        # end def

    async def test_fails_when_the_position_is_empty_while_it_holds_an_accept(self) -> None:
        world = await _setup(Level.L1, Countersign.NONE)
        await world.task.action('db.read', _TABLE, mutates=False, egress=False).__aenter__()
        resumed = await world.restart(modes=[{'last': None}])
        assert (resumed.state, resumed.reason) == ('failed', 'empty-with-accepts')
        # end def

    async def test_fails_when_the_position_request_is_refused(self) -> None:
        world = await _setup(Level.L1, Countersign.NONE)
        await world.task.action('db.read', _TABLE, mutates=False, egress=False).__aenter__()
        resumed = await world.restart(modes=[403])
        assert (resumed.state, resumed.reason) == ('failed', 'position-refused')
        # end def

    async def test_fails_when_the_position_is_not_countersigned(self) -> None:
        world = await _setup()
        await world.task.action('db.read', _TABLE, mutates=False, egress=False).__aenter__()
        record = world.host.records()[0]
        last = {
            'seq': record.seq,
            'host_ts': record.host_ts,
            'previous_hash': record.previous_hash,
            'record_hash': record.record_hash,
        }
        resumed = await world.restart(modes=[{'last': last}])
        assert (resumed.state, resumed.reason) == ('failed', 'position-uncountersigned')
        # end def

    # end class


class TestTerminal:
    """§5.5 step 6, and a Task already terminal at the restart."""

    async def test_delivers_only_for_a_task_already_terminal(self) -> None:
        world = await _setup()
        action = await world.task.action('db.write', _TABLE, mutates=True, egress=False).__aenter__()
        resumed = await world.restart(terminal=True)
        assert (resumed.state, resumed.indeterminate) == ('delivered', [action.id])
        assert len(world.reports_on(action.id)) == 1
        # end def

    async def test_reports_closed_when_the_own_ledger_shows_the_close(self) -> None:
        world = await _setup()
        await _read(world)
        assert await world.task.finish()
        resumed = await world.restart()
        assert resumed.state == 'closed'
        state = world.host.session(world.session_id)
        assert state is not None and state.end is not None and state.end.cause == 'close'
        # end def

    # end class


async def test_an_attempt_answered_unavailable_before_the_restart_is_resent_and_reported_not_performed() -> None:
    """§5.5 step 2."""
    world = await _setup(Level.L1, Countersign.NONE)
    world.network.modes.append({'status': 'unavailable', 'reason': 'internal-error'})
    world.repository.fail_when = lambda record: _entry_event(record).get('outcome') == 'aborted'
    with pytest.raises(AmcpAbortedError):
        async with world.task.action('db.read', _TABLE, mutates=False, egress=False):
            pass
            # end async with
        # end with
    world.repository.fail_when = None
    assert world.host.records() == []
    sent = next(r for r in await world.repository.read_all(_PARTITION) if r.event.get('entry') == 'sent')
    event_id = str(_entry_event(sent)['id'])

    resumed = await world.restart()
    assert (resumed.state, resumed.not_performed) == ('continue', [event_id])
    assert [r.event['outcome'] for r in world.host.records() if r.event['id'] == event_id] == ['attempted']
    assert len(world.reports_on(event_id)) == 1
    # end def


async def test_fails_when_a_well_chained_entry_is_not_one_the_sdk_writes() -> None:
    """§5.5: a chain that recomputes proves the entries unchanged, not that this SDK wrote them."""
    world = await _setup()
    await _read(world)
    reopened = await SelfLedger.open(world.repository, _PARTITION, world.clock.now)
    await reopened.write({'entry': 'resolved', 'id': 'x', 'outcome': 'maybe'})
    assert (await world.restart()).reason == 'own-ledger'
    # end def
