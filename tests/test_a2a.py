"""This extension on the official A2A Python SDK: a Client and a Server Agent on `a2a-sdk`, over in-process JSON-RPC."""

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from a2a.client import ClientCallContext, ClientConfig, ClientFactory
from a2a.client.service_parameters import ServiceParametersFactory, with_a2a_extensions
from a2a.server.agent_execution import RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentInterface,
    ExtensionSupportRequiredError,
    GetTaskRequest,
    InvalidParamsError,
    Message,
    Part,
    Role,
    SendMessageRequest,
    Task,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
)
from auditable_mcp import AmcpAbortedError
from starlette.applications import Starlette

from auditable_a2a.a2a import (
    ActivationContextBuilder,
    ActivationMiddleware,
    AuditContext,
    AuditedExecutor,
    AuditedRequestHandler,
    held_for_audit,
    metadata_of,
    read_rejection,
    send_audited,
)
from auditable_a2a.admission import (
    HoldRemedy,
    SessionUse,
    agent_card_extension,
    audit_credentials_metadata,
    read_audit_status,
)
from auditable_a2a.audit_host import A2aAuditHost
from auditable_a2a.audited_task import AuditedTask
from auditable_a2a.endpoint_handler import create_audit_endpoint_handler
from auditable_a2a.models import EXTENSION_URI, AgentCardParams, AuditCredentials, AuditRequest, Countersign, Level
from auditable_a2a.session_store import InMemorySessionStore
from auditable_a2a.verify import verify_a2a_ledger

_AGENT = 'http://agent.example'
_AUDIT = 'https://audit.client.example/a2a'
_TABLE: dict[str, object] = {'kind': 'table', 'ref': 'customers'}
_FIELD = f'metadata[{json.dumps(EXTENSION_URI)}]'


class _Clock:
    """A clock one second further on at each reading."""

    def __init__(self) -> None:
        """Start at the epoch of the tests."""
        self._n = 0
        # end def

    def now(self) -> str:
        """Return the next timestamp."""
        self._n += 1
        return f'2026-10-15T00:00:{self._n:02d}.000Z'
        # end def

    # end class


class _Audit:
    """A `Post` to the audit host's ASGI endpoint, which can be taken down."""

    def __init__(self, host: A2aAuditHost) -> None:
        """Serve `host`."""
        self._app = create_audit_endpoint_handler(host)
        self.down = False
        # end def

    async def post(self, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        """POST through the app, unless it is down."""
        if self.down:
            raise OSError('connection refused')
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


@dataclass
class _Executor:
    """The Server Agent's work: one recorded read of the customers table."""

    audit: _Audit
    answer_with_message: bool = False
    sessions: dict[str, str] = field(default_factory=dict)
    audits: list[str | None] = field(default_factory=list)
    """The `sessionId` of the audit the executor received for each request, in order."""

    async def execute(self, context: RequestContext, event_queue: EventQueue, audit: AuditContext | None) -> None:
        """Record and perform the read, or hold the Task when it cannot be recorded."""
        self.audits.append(None if audit is None else audit.audit_session.sessionId)
        task_id, context_id = str(context.task_id), str(context.context_id)
        if self.answer_with_message:
            # No recorded access, so no Task (§4.3).
            await event_queue.enqueue_event(
                Message(
                    message_id=str(uuid.uuid4()), context_id=context_id, role=Role.ROLE_AGENT, parts=[Part(text='42')]
                )
            )
            return
            # end if
        if context.current_task is None:
            await event_queue.enqueue_event(
                Task(id=task_id, context_id=context_id, status=TaskStatus(state=TaskState.TASK_STATE_WORKING))
            )
            # end if
        if audit is not None and audit.request is not None:
            self.sessions[audit.request.sessionId] = task_id
            task = AuditedTask(task_id=task_id, request=audit.request, post=self.audit.post, timeout=0.1)
            try:
                async with task.action('db.read', _TABLE, mutates=False, egress=False):
                    pass
                    # end async with
            except AmcpAbortedError as error:
                await event_queue.enqueue_event(held_for_audit(task_id, context_id, task.status_of(error)))
                return
                # end try
            await task.finish()
            # end if
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=task_id, context_id=context_id, status=TaskStatus(state=TaskState.TASK_STATE_COMPLETED)
            )
        )
        # end def

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Nothing to cancel."""
        # end def

    # end class


@dataclass
class _World:
    """An audit host, a Server Agent on the SDK, and a Client on the SDK."""

    host: A2aAuditHost
    audit: _Audit
    client: Any
    activated: list[list[str]]
    """The extensions each response listed in `A2A-Extensions`, in order."""
    saved: list[str]
    credentials_replaced: list[tuple[str, AuditCredentials]]
    executor: _Executor

    async def open(self) -> AuditRequest:
        """Open a session at the audit host, as the Client's request carries it."""
        session_id, auth = await self.host.open_session(delegate=_AGENT, expires_at='2026-11-15T00:00:00Z')
        return AuditRequest.model_validate(
            {
                'auditEndpoint': {
                    'url': _AUDIT,
                    'authentication': {'scheme': auth.scheme, 'credentials': auth.credentials},
                },
                'sessionId': session_id,
                'level': 'L1',
                'countersign': 'none',
                'expiresAt': '2026-11-15T00:00:00Z',
            }
        )
        # end def

    async def send(self, audit_request: AuditRequest) -> tuple[Any, bool]:
        """Delegate with this extension."""
        return await send_audited(self.client, SendMessageRequest(message=_message()), audit_request)
        # end def

    async def send_plain(
        self, task_id: str | None = None, metadata: dict[str, Any] | None = None, extensions: list[str] | None = None
    ) -> Any:
        """Send a message as an ordinary Client does, with `extensions` listed."""
        context = ClientCallContext(
            service_parameters=ServiceParametersFactory.create([with_a2a_extensions(extensions or [])])
        )
        result = None
        async for response in self.client.send_message(
            SendMessageRequest(message=_message(task_id), metadata=metadata or {}), context=context
        ):
            result = response.task if response.HasField('task') else response.message
            # end async for
        return result
        # end def

    async def get_task(self, task_id: str, extensions: list[str] | None = None) -> Task:
        """Get a Task as an ordinary Client does, with `extensions` listed."""
        context = ClientCallContext(
            service_parameters=ServiceParametersFactory.create([with_a2a_extensions(extensions or [])])
        )
        task: Task = await self.client.get_task(GetTaskRequest(id=task_id), context=context)
        return task
        # end def

    # end class


def _message(task_id: str | None = None) -> Message:
    """A user message, on `task_id` when given."""
    return Message(
        message_id=str(uuid.uuid4()),
        role=Role.ROLE_USER,
        parts=[Part(text='Count the customers.')],
        **({} if task_id is None else {'task_id': task_id}),
    )
    # end def


async def _setup(*, required: bool = False, answer_with_message: bool = False) -> _World:
    """Stand the three parties up in process."""
    host = A2aAuditHost.create('client-a', Level.L1, Countersign.NONE, store=InMemorySessionStore(), clock=_Clock())
    audit = _Audit(host)
    executor = _Executor(audit, answer_with_message)
    params = AgentCardParams.model_validate({'level': 'L1', 'countersign': 'none'})
    declaration = agent_card_extension(params, required=required)
    card = AgentCard(
        name='ledger agent',
        description='reads the customers table',
        version='1.0.0',
        supported_interfaces=[AgentInterface(url=f'{_AGENT}/', protocol_binding='JSONRPC', protocol_version='1.0')],
        capabilities=AgentCapabilities(
            streaming=False,
            extensions=[AgentExtension(uri=EXTENSION_URI, required=required, params=declaration['params'])],  # type: ignore[arg-type]
        ),
        default_input_modes=['text/plain'],
        default_output_modes=['text/plain'],
    )
    saved: list[str] = []
    store = InMemoryTaskStore()
    original_save = store.save

    async def save(task: Task, context: ServerCallContext | None = None) -> None:
        saved.append(task.id)
        await original_save(task, context)  # type: ignore[arg-type]
        # end def

    store.save = save  # type: ignore[method-assign]
    credentials_replaced: list[tuple[str, AuditCredentials]] = []

    async def session_in_use(session_id: str, context: ServerCallContext) -> SessionUse | None:
        task_id = executor.sessions.get(session_id)
        return None if task_id is None else SessionUse(task_id, same_client=True)
        # end def

    async def on_credentials(task_id: str, credentials: AuditCredentials) -> None:
        credentials_replaced.append((task_id, credentials))
        # end def

    handler = AuditedRequestHandler(
        required=required,
        params=params,
        session_in_use=session_in_use,
        on_credentials=on_credentials,
        agent_executor=AuditedExecutor(executor),
        task_store=store,
        agent_card=card,
    )
    app = ActivationMiddleware(
        Starlette(
            routes=create_agent_card_routes(card)
            + create_jsonrpc_routes(handler, '/', context_builder=ActivationContextBuilder())
        )
    )
    activated: list[list[str]] = []

    async def record(response: httpx.Response) -> None:
        header = response.headers.get('a2a-extensions', '')
        activated.append([uri for uri in header.split(',') if uri])
        # end def

    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=_AGENT, event_hooks={'response': [record]}
    )
    client = ClientFactory(ClientConfig(httpx_client=http, streaming=False)).create(card)
    return _World(host, audit, client, activated, saved, credentials_replaced, executor)
    # end def


class TestNegotiated:
    """§4.3."""

    async def test_lists_the_uri_carries_audit_session_and_records_the_access(self) -> None:
        world = await _setup()
        request = await world.open()
        result, audited = await world.send(request)

        assert audited
        assert world.activated[-1] == [EXTENSION_URI]
        assert result.status.state == TaskState.TASK_STATE_COMPLETED
        assert [record.event['outcome'] for record in world.host.records()] == ['attempted', 'success']
        session = world.host.session(request.sessionId)
        assert session is not None and session.end is not None and session.end.cause == 'close'
        assert verify_a2a_ledger(world.host.records(), [session]).complete
        # end def

    # end class


class TestDirectMessage:
    """§4.3: a negotiated request answered with a direct Message."""

    async def test_carries_audit_session_in_the_message_and_records_nothing(self) -> None:
        world = await _setup(answer_with_message=True)
        result, audited = await world.send(await world.open())

        assert audited
        assert isinstance(result, Message)
        assert world.host.records() == []
        # end def

    # end class


class TestNotNegotiated:
    """§4.4, §4.5."""

    async def test_serves_an_unactivated_request_as_an_ordinary_task(self) -> None:
        world = await _setup()
        result = await world.send_plain()
        assert result.status.state == TaskState.TASK_STATE_COMPLETED
        assert EXTENSION_URI not in metadata_of(result.metadata)
        assert world.host.records() == []
        # end def

    async def test_refuses_an_unactivated_request_under_the_mandatory_posture(self) -> None:
        world = await _setup(required=True)
        with pytest.raises(ExtensionSupportRequiredError):
            await world.send_plain()
            # end with
        assert world.saved == []
        # end def

    async def test_rejects_a_level_the_agent_does_not_meet_and_creates_no_task(self) -> None:
        world = await _setup()
        request = (await world.open()).model_copy(update={'level': Level.L2})
        with pytest.raises(InvalidParamsError) as caught:
            await world.send(request)
            # end with
        rejection = read_rejection(caught.value)
        assert rejection is not None and rejection.field == f'{_FIELD}.auditRequest.level'
        assert world.saved == []
        # end def

    async def test_names_the_task_of_a_reused_session_id_to_the_same_client(self) -> None:
        world = await _setup()
        request = await world.open()
        first, _ = await world.send(request)
        with pytest.raises(InvalidParamsError) as caught:
            await world.send(request)
            # end with
        rejection = read_rejection(caught.value)
        assert rejection is not None and rejection.session_in_use == first.id
        # end def

    # end class


class TestHeld:
    """§8.4, §8.5."""

    async def test_is_held_in_auth_required_with_an_audit_status_the_client_reads(self) -> None:
        world = await _setup()
        request = await world.open()
        world.audit.down = True
        result, audited = await world.send(request)

        assert audited
        assert result.status.state == TaskState.TASK_STATE_AUTH_REQUIRED
        read = read_audit_status(metadata_of(result.status.message.metadata))
        assert read is not None and read[1] == HoldRemedy.RESTORE_HOST
        # end def

    # end class


class TestLaterRequest:
    """§4.6, §5.7."""

    async def test_hands_audit_credentials_to_the_task_and_rejects_an_audit_request(self) -> None:
        world = await _setup()
        request = await world.open()
        world.audit.down = True
        result, _ = await world.send(request)
        credentials = AuditCredentials.model_validate(
            {'authentication': {'scheme': 'Bearer', 'credentials': 'renewed'}}
        )

        await world.send_plain(result.id, audit_credentials_metadata(credentials), [EXTENSION_URI])
        assert world.credentials_replaced == [(result.id, credentials)]

        with pytest.raises(InvalidParamsError) as caught:
            await world.send_plain(result.id, {EXTENSION_URI: {'auditRequest': request.to_wire()}}, [EXTENSION_URI])
            # end with
        rejection = read_rejection(caught.value)
        assert rejection is not None and rejection.field == f'{_FIELD}.auditRequest'
        # end def

    # end class


class TestAuditedTaskLaterRequest:
    """§4.3, §8.1: a later request on an audit-negotiated Task that does not list the URI."""

    async def test_still_hands_the_executor_the_audit_of_the_task(self) -> None:
        world = await _setup()
        request = await world.open()
        world.audit.down = True
        result, _ = await world.send(request)
        world.audit.down = False
        await world.send_plain(result.id, None, [])
        assert world.executor.audits[-1] == request.sessionId
        # end def

    # end class


class TestMandatoryLaterRequest:
    """§4.6, A2A §3.3.4: the mandatory posture on a later request."""

    async def test_refuses_a_get_task_that_does_not_list_the_uri(self) -> None:
        world = await _setup(required=True)
        result, _ = await world.send(await world.open())
        with pytest.raises(ExtensionSupportRequiredError):
            await world.get_task(result.id)
            # end with
        assert (await world.get_task(result.id, [EXTENSION_URI])).id == result.id
        # end def

    # end class
