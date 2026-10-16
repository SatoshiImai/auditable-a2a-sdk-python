"""What an AuditedTask holds as outstanding (§5.4), and the auditStatus of a hold (§7.3, §8.4)."""

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
import pytest
from auditable_mcp import AmcpAbortedError, InMemoryLedgerRepository, RepositoryError, SealedRecord
from auditable_mcp.l2 import Ed25519Countersigner, generate_tool_key, public_jwk
from auditable_mcp.l2.algorithms import KeyRole, SignatureAlgorithm

from auditable_a2a import (
    AuditCredentials,
    AuditRequest,
    AuthenticationInfo,
    Countersign,
    FetchHostKeys,
    Level,
    Post,
    key_id_of,
)
from auditable_a2a.audit_host import A2aAuditHost
from auditable_a2a.audited_task import AuditedTask, SessionExpiredError
from auditable_a2a.endpoint_handler import create_audit_endpoint_handler
from auditable_a2a.resume import ResumeContinue, resume_task
from auditable_a2a.self_ledger import SelfLedger, SelfLedgerError
from auditable_a2a.session_store import InMemorySessionStore

_ENDPOINT = 'https://audit.client.example/a2a'
_HOST_KEYS = 'https://audit.client.example/keys.json'
_TASK = 'task-1'
_TABLE: dict[str, object] = {'kind': 'table', 'ref': 'customers'}
_EXPIRES = '2026-11-15T00:00:00Z'

Rule = Callable[[dict[str, Any]], Awaitable[int | None]]
"""Inspect a submission's event; hold it back, or answer it with a status instead of passing it on."""


class _Clock:
    """A clock one second further on at each reading, which also mints ids."""

    def __init__(self, start: int = 0) -> None:
        """Start at the epoch of the tests, minting ids after `start`."""
        self._n = start
        self._ids = start
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return (datetime(2026, 10, 15, tzinfo=UTC) + timedelta(seconds=self._n)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        # end def

    def new_id(self) -> str:
        """Return a fresh valid event id."""
        self._ids += 1
        return f'0199a3e1-0000-7000-8000-{self._ids:012x}'
        # end def

    # end class


class _FlakyRepository(InMemoryLedgerRepository):
    """A ledger repository whose appends fail while `fail_when` says so."""

    def __init__(self) -> None:
        """Start working."""
        super().__init__()
        self.fail_when: Callable[[SealedRecord], bool] | None = None
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Fail, or append."""
        if self.fail_when is not None and self.fail_when(record):
            raise RepositoryError('disk full')
            # end if
        await super().append(partition, record)
        # end def

    # end class


@dataclass
class _World:
    """An audit host with one session, and the Server Agent's Task bound to it."""

    host: A2aAuditHost
    task: AuditedTask
    session_id: str
    rules: list[Rule]
    repository: _FlakyRepository
    post: Post
    task_request: AuditRequest
    fetch_host_keys: FetchHostKeys
    authentication: AuthenticationInfo
    key_fetches: list[str] = field(default_factory=list)
    host_key: list[Any] = field(default_factory=list)

    def rotate_host_key(self, kid: str) -> None:
        """Rotate the audit host's countersignature key, as a host rotating its keys would."""
        self.host_key[0] = generate_tool_key(key_id_of(_HOST_KEYS, kid))
        # end def

    # end class


def _jwks(key: Any) -> dict[str, object]:
    """The host's key set as it publishes it: ordinary JWKs, no a-MCP role member."""
    kid = key.key_id.split('#')[1]
    jwk = public_jwk(kid, key.public_key, SignatureAlgorithm.ED25519, KeyRole.HOST)
    return {'keys': [{k: v for k, v in jwk.items() if k != 'amcp_role'}]}
    # end def


class _RotatingCountersigner:
    """A countersigner over whatever key the world holds now."""

    def __init__(self, holder: list[Any]) -> None:
        """Sign with `holder[0]`."""
        self._holder = holder
        # end def

    @property
    def key_id(self) -> str:
        """The current key's id."""
        return str(self._holder[0].key_id)
        # end def

    async def sign(self, payload: bytes) -> str:
        """Sign with the current key."""
        key = self._holder[0]
        return await Ed25519Countersigner(key.key_id, key.private_key).sign(payload)
        # end def

    # end class


async def _setup(
    *,
    expires_at: str = _EXPIRES,
    countersign: Countersign = Countersign.NONE,
    self_ledger: bool = False,
    key_server_fails_after: int | None = 1,
) -> _World:
    """Stand the audit host and the Task up, with a network whose rules the test sets."""
    countersigned = countersign == Countersign.HOST
    holder: list[Any] = [generate_tool_key(key_id_of(_HOST_KEYS, 'h1'))]
    host = A2aAuditHost.create(
        'client-a',
        Level.L1,
        countersign,
        store=InMemorySessionStore(),
        clock=_Clock(),
        countersigner=_RotatingCountersigner(holder) if countersigned else None,
    )
    session_id, auth = await host.open_session(
        delegate='https://agent.example', expires_at=expires_at, host_keys=_HOST_KEYS if countersigned else None
    )
    request = AuditRequest.model_validate(
        {
            'auditEndpoint': {
                'url': _ENDPOINT,
                'authentication': {'scheme': auth.scheme, 'credentials': auth.credentials},
            },
            'sessionId': session_id,
            'level': 'L1',
            'countersign': countersign,
            'expiresAt': expires_at,
            **({'hostKeys': _HOST_KEYS} if countersigned else {}),
        }
    )
    app = create_audit_endpoint_handler(host)
    rules: list[Rule] = []

    async def post(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        submission = json.loads(body)
        for rule in rules:
            status = await rule(submission)
            if status is not None:
                return status, b''
                # end if
            # end for
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
        await app(scope, receive, send)
        return sent[0]['status'], sent[1]['body']
        # end def

    repository = _FlakyRepository()
    key_fetches: list[str] = []

    async def fetch_host_keys(url: str) -> Mapping[str, Any]:
        key_fetches.append(url)
        if key_server_fails_after is not None and len(key_fetches) > key_server_fails_after:
            raise OSError('key server down')
            # end if
        return _jwks(holder[0])
        # end def

    task = AuditedTask(
        task_id=_TASK,
        request=request,
        post=post,
        deps=_Clock(),
        timeout=1.0,
        host_key_snapshot=_jwks(holder[0]) if countersigned else None,
        fetch_host_keys=fetch_host_keys if countersigned else None,
        self_ledger=await SelfLedger.open(repository, _TASK) if self_ledger else None,
    )
    return _World(
        host,
        task,
        session_id,
        rules,
        repository,
        post,
        request,
        fetch_host_keys,
        request.auditEndpoint.authentication,
        key_fetches,
        holder,
    )
    # end def


async def _read(task: AuditedTask) -> str:
    """Record and perform one read; return its id."""
    action = task.action('db.read', _TABLE, mutates=False, egress=False)
    async with action:
        pass
        # end async with
    return action.id
    # end def


class TestNothingOutstanding:
    """§5.4: nothing outstanding means nothing outstanding."""

    async def test_does_not_close_the_session_under_an_attempt_still_on_its_way(self) -> None:
        world = await _setup()
        held = anyio.Event()
        reached = anyio.Event()

        async def hold_attempts(submission: dict[str, Any]) -> int | None:
            if submission.get('event', {}).get('outcome') == 'attempted':
                reached.set()
                await held.wait()
                # end if
            return None
            # end def

        world.rules.append(hold_attempts)
        async with anyio.create_task_group() as group:
            group.start_soon(_read, world.task)
            await reached.wait()
            assert not world.task.may_end()
            assert not await world.task.finish()
            held.set()
            # end async with
        assert await world.task.finish()
        state = world.host.session(world.session_id)
        assert state is not None and state.anomalies == []
        # end def

    async def test_keeps_an_accept_whose_performing_was_not_written_until_a_report_resolves_it(self) -> None:
        world = await _setup(self_ledger=True)
        world.repository.fail_when = lambda record: record.event.get('entry') == 'performing'
        with pytest.raises(SelfLedgerError):
            async with world.task.action('db.write', _TABLE, mutates=True, egress=False):
                pass
                # end async with
            # end with
        world.repository.fail_when = None
        assert not world.task.may_end()
        attempt_id = str(world.host.records()[0].event['id'])
        await world.task.report_execution(attempt_id, 'not-performed')
        assert world.task.may_end()
        # end def

    async def test_sends_no_outcome_for_an_action_resolved_by_an_execution_report(self) -> None:
        world = await _setup()
        action = world.task.action('db.write', _TABLE, mutates=True, egress=False)
        async with action:
            await world.task.report_execution(action.id, 'not-performed')
            # end async with
        assert [r.event['outcome'] for r in world.host.records() if r.event['id'] == action.id] == ['attempted']
        assert world.task.may_end()
        # end def

    # end class


class TestTheAuditStatusOfAHold:
    """§7.3, §8.4."""

    async def test_names_the_failure_of_the_attempt_it_is_about_whatever_was_recorded_since(self) -> None:
        world = await _setup()

        async def refuse_writes(submission: dict[str, Any]) -> int | None:
            event = submission.get('event', {})
            return 401 if event.get('action_type') == 'db.write' and event.get('outcome') == 'attempted' else None
            # end def

        world.rules.append(refuse_writes)
        with pytest.raises(AmcpAbortedError) as refused:
            async with world.task.action('db.write', _TABLE, mutates=True, egress=False):
                pass
                # end async with
            # end with
        await _read(world.task)
        status = world.task.status_of(refused.value)
        assert (status.reason, status.httpStatus) == ('host-unavailable', 401)
        # end def

    async def test_names_an_outcome_it_could_not_deliver_with_the_status_that_asks_for_credentials(self) -> None:
        world = await _setup()

        async def refuse_outcomes(submission: dict[str, Any]) -> int | None:
            return 401 if submission.get('event', {}).get('outcome') == 'success' else None
            # end def

        world.rules.append(refuse_outcomes)
        event_id = await _read(world.task)
        status = world.task.held_status()
        assert status is not None
        assert (status.reason, status.httpStatus, status.attemptId) == ('host-unavailable', 401, event_id)
        # end def

    # end class


class TestTheSessionExpiry:
    """§5.3."""

    async def test_refuses_an_access_after_it(self) -> None:
        world = await _setup(expires_at='2026-10-15T00:00:00Z')
        with pytest.raises(SessionExpiredError):
            async with world.task.action('db.read', _TABLE, mutates=False, egress=False):
                pass
                # end async with
            # end with
        assert world.host.records() == []
        assert world.task.may_end()
        # end def

    # end class


class TestTheAuditHostKeys:
    """§10.2."""

    async def test_fetches_them_again_for_a_kid_it_does_not_hold_and_reads_a_failed_fetch_as_unrecorded(self) -> None:
        world = await _setup(countersign=Countersign.HOST)
        world.rotate_host_key('h2')
        await _read(world.task)
        assert world.key_fetches == [_HOST_KEYS]
        world.rotate_host_key('h3')
        with pytest.raises(AmcpAbortedError) as error:
            async with world.task.action('db.read', _TABLE, mutates=False, egress=False):
                pass
                # end async with
            # end with
        assert error.value.reason == 'host-unavailable'
        # end def

    # end class


async def test_a_performed_access_is_not_recorded_aborted_after_the_host_keys_rotate_across_a_restart() -> None:
    """§5.5 step 4: an accept written as performing is resolved, not checked again under keys that changed."""
    world = await _setup(countersign=Countersign.HOST, self_ledger=True, key_server_fails_after=None)
    world.rotate_host_key('h2')
    performed = world.task.action('db.write', _TABLE, mutates=True, egress=False)

    def outcome_entry(record: SealedRecord) -> bool:
        event = record.event.get('event')
        return record.event.get('entry') == 'sent' and isinstance(event, dict) and event.get('outcome') == 'success'
        # end def

    world.repository.fail_when = outcome_entry
    async with performed:
        pass
        # end async with
    world.repository.fail_when = None
    # The host publishes only its newest key; the next access is countersigned under it.
    world.rotate_host_key('h3')
    await _read(world.task)

    resumed = await resume_task(
        self_ledger=await SelfLedger.open(world.repository, _TASK),
        credentials=AuditCredentials(authentication=world.authentication),
        post=world.post,
        deps=_Clock(start=500),
        fetch_host_keys=world.fetch_host_keys,
    )
    assert isinstance(resumed, ResumeContinue)
    outcomes = [r.event['outcome'] for r in world.host.records() if r.event['id'] == performed.id]
    assert outcomes == ['attempted', 'success']
    # end def


class TestWhateverTheClientRaises:
    """§6.2, §6.4, §10.2: anything the injected client raises is no answer."""

    async def test_keeps_an_outcome_owed_when_the_post_raises(self) -> None:
        world = await _setup()

        async def broken_outcomes(submission: dict[str, Any]) -> int | None:
            if submission.get('event', {}).get('outcome') == 'success':
                raise RuntimeError('a malformed Content-Encoding')
                # end if
            return None
            # end def

        world.rules.append(broken_outcomes)
        event_id = await _read(world.task)
        assert [str(event['id']) for event in world.task.client.owed] == [event_id]
        assert not world.task.may_end()
        assert not await world.task.finish()
        world.rules.clear()
        assert await world.task.finish()
        # end def

    async def test_reads_a_key_fetch_that_raises_as_a_failure_to_record(self) -> None:
        world = await _setup(countersign=Countersign.HOST, key_server_fails_after=None)

        async def broken(url: str) -> Mapping[str, Any]:
            raise RuntimeError('a malformed Content-Encoding')
            # end def

        task = AuditedTask(
            task_id=_TASK,
            request=world.task_request,
            post=world.post,
            deps=_Clock(start=100),
            host_key_snapshot=_jwks(world.host_key[0]),
            fetch_host_keys=broken,
        )
        world.rotate_host_key('h2')
        with pytest.raises(AmcpAbortedError) as error:
            async with task.action('db.read', _TABLE, mutates=False, egress=False):
                pass
                # end async with
            # end with
        assert error.value.reason == 'host-unavailable'
        assert task.may_end()
        # end def

    # end class


class _TailLostRepository(_FlakyRepository):
    """A repository whose tail cannot be read while `tail_down` is set."""

    tail_down = False

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """Fail, or read the tail."""
        if self.tail_down:
            raise RepositoryError('store down')
            # end if
        return await super().load_tail(partition)
        # end def

    # end class


async def test_the_own_ledger_raises_its_own_error_when_the_tail_cannot_be_read_back() -> None:
    """§5.5: a failed write and a failed read-back are both a SelfLedgerError, and the next write reads the tail."""
    repository = _TailLostRepository()
    ledger = await SelfLedger.open(repository, _TASK)
    repository.fail_when = lambda record: True
    repository.tail_down = True
    with pytest.raises(SelfLedgerError):
        await ledger.write({'entry': 'close'})
        # end with
    with pytest.raises(SelfLedgerError):
        await ledger.write({'entry': 'close'})
        # end with
    repository.fail_when = None
    repository.tail_down = False
    await ledger.write({'entry': 'close'})
    assert [entry['entry'] for entry in await ledger.entries()] == ['close']
    # end def


class TestCancellation:
    """§5.4: a cancellation does not make outstanding records disappear."""

    async def test_gives_up_an_attempt_cancelled_on_its_way_with_its_aborted_outcome(self) -> None:
        world = await _setup()
        reached = anyio.Event()

        async def hold_attempts(submission: dict[str, Any]) -> int | None:
            if submission.get('event', {}).get('outcome') == 'attempted':
                reached.set()
                await anyio.sleep_forever()
                # end if
            return None
            # end def

        world.rules.append(hold_attempts)
        async with anyio.create_task_group() as group:
            group.start_soon(_read, world.task)
            await reached.wait()
            group.cancel_scope.cancel()
            # end async with
        # It may have reached the host, so it is given up with its aborted outcome (§8.3).
        assert [r.event['outcome'] for r in world.host.records()] == ['aborted']
        assert world.task.may_end()
        # end def

    async def test_needs_nothing_for_an_attempt_cancelled_before_it_was_sent(self) -> None:
        world = await _setup()
        async with anyio.create_task_group() as group:
            group.cancel_scope.cancel()
            group.start_soon(_read, world.task)
            # end async with
        assert world.host.records() == []
        assert world.task.may_end()
        # end def

    async def test_sends_the_outcome_of_a_body_its_caller_cancelled(self) -> None:
        world = await _setup()
        action = world.task.action('db.read', _TABLE, mutates=False, egress=False)
        with anyio.CancelScope() as scope:
            async with action:
                scope.cancel()
                await anyio.sleep(0)
                # end async with
            # end with
        outcomes = [r.event['outcome'] for r in world.host.records() if r.event['id'] == action.id]
        assert outcomes == ['attempted', 'failed']
        assert world.task.may_end()
        # end def

    # end class


class _AckLostRepository(_FlakyRepository):
    """A repository that takes the first session entry and then reports a failure."""

    lost = False

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Append; lose the acknowledgement of the first session entry."""
        await super().append(partition, record)
        if record.event.get('entry') == 'session' and not self.lost:
            self.lost = True
            raise RepositoryError('acknowledgement lost')
            # end if
        # end def

    # end class


async def test_a_session_entry_whose_acknowledgement_was_lost_is_not_written_twice() -> None:
    """§5.5: the own ledger stays one that can be restored."""
    world = await _setup()
    repository = _AckLostRepository()
    task = AuditedTask(
        task_id=_TASK,
        request=world.task_request,
        post=world.post,
        deps=_Clock(start=100),
        self_ledger=await SelfLedger.open(repository, _TASK),
    )
    await _read(task)
    entries = [entry['entry'] for entry in await (await SelfLedger.open(repository, _TASK)).entries()]
    assert entries.count('session') == 1
    resumed = await resume_task(
        self_ledger=await SelfLedger.open(repository, _TASK),
        credentials=AuditCredentials(authentication=world.authentication),
        post=world.post,
        deps=_Clock(start=200),
    )
    assert resumed.state == 'continue'
    # end def


class TestExecutionReports:
    """§8.6: at most one accepted report per accepted attempt, and none on anything else."""

    async def test_refuses_a_second_report_and_one_on_an_attempt_it_never_had_accepted(self) -> None:
        world = await _setup()
        action = world.task.action('db.write', _TABLE, mutates=True, egress=False)
        async with action:
            await world.task.report_execution(action.id, 'not-performed')
            with pytest.raises(ValueError, match='already accepted'):
                await world.task.report_execution(action.id, 'not-performed')
                # end with
            # end async with
        with pytest.raises(ValueError, match='not an access'):
            await world.task.report_execution('0199a3e1-0000-7000-8000-0000000000ff', 'not-performed')
            # end with
        # end def

    async def test_an_action_whose_report_was_not_recorded_sends_its_outcome(self) -> None:
        world = await _setup()

        async def refuse_reports(submission: dict[str, Any]) -> int | None:
            event = submission.get('event', {})
            return 503 if event.get('action_type') == 'a2a.execution-report' else None
            # end def

        action = world.task.action('db.write', _TABLE, mutates=True, egress=False)
        async with action:
            world.rules.append(refuse_reports)
            with pytest.raises(AmcpAbortedError):
                await world.task.report_execution(action.id, 'not-performed')
                # end with
            world.rules.clear()
            # end async with
        assert await world.task.finish()
        outcomes = [r.event['outcome'] for r in world.host.records() if r.event['id'] == action.id]
        assert outcomes == ['attempted', 'success']
        # end def

    # end class


class TestNothingLost:
    """§6.4, §8.6: an outcome stays owed whatever stops its send, and one attempt gets one resolution."""

    async def test_keeps_an_outcome_owed_when_its_post_is_cancelled(self) -> None:
        world = await _setup()
        reached = anyio.Event()

        async def hold_outcomes(submission: dict[str, Any]) -> int | None:
            if submission.get('event', {}).get('outcome') == 'success':
                reached.set()
                await anyio.sleep_forever()
                # end if
            return None
            # end def

        async with anyio.create_task_group() as group:
            world.rules.append(hold_outcomes)
            second = world.task.action('db.read', _TABLE, mutates=False, egress=False)

            async def read() -> None:
                async with second:
                    pass
                    # end async with
                # end def

            group.start_soon(read)
            await reached.wait()
            group.cancel_scope.cancel()
            # end async with
        assert [str(event['id']) for event in world.task.client.owed] == [second.id]
        assert not await world.task.finish()
        world.rules.clear()
        assert await world.task.finish()
        # end def

    async def test_seals_one_report_when_its_own_ledger_entry_fails(self) -> None:
        world = await _setup(self_ledger=True)
        action = world.task.action('db.write', _TABLE, mutates=True, egress=False)
        async with action:
            # Any further performing entry would be the report's own, which performs nothing.
            world.repository.fail_when = lambda record: record.event.get('entry') == 'performing'
            await world.task.report_execution(action.id, 'not-performed')
            world.repository.fail_when = None
            # end async with
        reports = [r for r in world.host.records() if r.event['action_type'] == 'a2a.execution-report']
        assert [r.event['outcome'] for r in reports] == ['attempted', 'success']
        assert world.task.may_end()
        # end def

    async def test_refuses_a_report_while_another_on_the_same_attempt_is_on_its_way(self) -> None:
        world = await _setup()
        action = world.task.action('db.write', _TABLE, mutates=True, egress=False)
        released = anyio.Event()
        reached = anyio.Event()

        async def hold_reports(submission: dict[str, Any]) -> int | None:
            event = submission.get('event', {})
            if event.get('action_type') == 'a2a.execution-report' and event.get('outcome') == 'attempted':
                reached.set()
                await released.wait()
                # end if
            return None
            # end def

        async with action:
            world.rules.append(hold_reports)
            async with anyio.create_task_group() as group:
                group.start_soon(world.task.report_execution, action.id, 'not-performed')
                await reached.wait()
                with pytest.raises(ValueError, match='on its way'):
                    await world.task.report_execution(action.id, 'not-performed')
                    # end with
                released.set()
                # end async with
            # end async with
        # end def

    async def test_refuses_a_report_on_an_attempt_whose_outcome_was_sent(self) -> None:
        world = await _setup()
        event_id = await _read(world.task)
        with pytest.raises(ValueError, match='has its outcome'):
            await world.task.report_execution(event_id, 'not-performed')
            # end with
        # end def

    async def test_refuses_an_execution_value_section_8_6_does_not_define(self) -> None:
        world = await _setup()
        action = world.task.action('db.write', _TABLE, mutates=True, egress=False)
        async with action:
            with pytest.raises(ValueError):
                await world.task.report_execution(action.id, 'not-performd')
                # end with
            await world.task.report_execution(action.id, 'not-performed')
            # end async with
        # end def

    # end class
