"""This extension on the official A2A Python SDK (`a2a-sdk`), installed with the `a2a` extra.

`AuditedRequestHandler` decides a request before the SDK sees it: an executor's exception still leaves a stored
`TASK_STATE_FAILED` Task, and §4.4 creates none. The SDK has no notion of an activated extension, so
`ActivationMiddleware` and `ActivationContextBuilder` carry it to the response's `A2A-Extensions`.
"""

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping, MutableSet
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol, cast

from a2a.client import Client, ClientCallContext
from a2a.client.service_parameters import ServiceParametersFactory, with_a2a_extensions
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events.event_queue import Event, EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import DefaultServerCallContextBuilder
from a2a.types import (
    CancelTaskRequest,
    DeleteTaskPushNotificationConfigRequest,
    ExtensionSupportRequiredError,
    GetTaskPushNotificationConfigRequest,
    GetTaskRequest,
    InvalidParamsError,
    ListTaskPushNotificationConfigsRequest,
    ListTaskPushNotificationConfigsResponse,
    ListTasksRequest,
    ListTasksResponse,
    Message,
    Part,
    Role,
    SendMessageRequest,
    SubscribeToTaskRequest,
    Task,
    TaskPushNotificationConfig,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
)
from google.protobuf import json_format
from google.protobuf.struct_pb2 import Struct
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.types import Message as AsgiMessage

from auditable_a2a.admission import (
    AUDIT_SESSION_IN_USE,
    Rejection,
    SessionUse,
    admit_later_request,
    admit_new_task,
    audit_request_metadata,
    audit_session_metadata,
    audit_status_metadata,
    integral_json,
    is_audited,
)
from auditable_a2a.models import (
    EXTENSION_URI,
    AgentCardParams,
    AuditCredentials,
    AuditRequest,
    AuditSession,
    AuditStatus,
)

__all__ = [
    'ActivationContextBuilder',
    'ActivationMiddleware',
    'AuditContext',
    'AuditedAgentExecutor',
    'AuditedExecutor',
    'AuditedRequestHandler',
    'ReadRejection',
    'activated_extensions',
    'held_for_audit',
    'metadata_of',
    'read_rejection',
    'rejection_error',
    'resumed_from_hold',
    'send_audited',
]

_ACTIVATED: Final = 'auditable_a2a.activated_extensions'
_HELD_TEXT: Final = 'The next step cannot be recorded in your audit ledger, so it has not been taken.'


def metadata_of(struct: Struct | Mapping[str, Any] | None) -> dict[str, Any]:
    """A `metadata` Struct as JSON, with integral numbers as integers: a Struct's numbers are doubles."""
    if struct is None:
        return {}
    elif isinstance(struct, Struct):
        return integral_json(json_format.MessageToDict(struct))  # type: ignore[return-value]
        # end if
    return integral_json(dict(struct))  # type: ignore[return-value]
    # end def


def rejection_error(rejection: Rejection) -> InvalidParamsError:
    """The validation error of §4.4, carried in the A2A `ErrorInfo`'s `metadata`, which both official SDKs deliver."""
    data: dict[str, Any] = {'auditField': rejection.field}
    if rejection.session_in_use is not None:
        data['auditReason'] = AUDIT_SESSION_IN_USE
        data['auditTaskId'] = rejection.session_in_use
        # end if
    return InvalidParamsError(message=f'{rejection.field} {rejection.description}', data=data)
    # end def


class ActivationMiddleware:
    """ASGI middleware that writes the extensions a request activated as the response's `A2A-Extensions`."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap `app`."""
        self._app = app
        # end def

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Give the request a set to activate into, and write it into the response's headers."""
        if scope['type'] != 'http':
            await self._app(scope, receive, send)
            return
            # end if
        activated: set[str] = set()
        scope[_ACTIVATED] = activated

        async def send_with_header(message: AsgiMessage) -> None:
            if message['type'] == 'http.response.start' and activated:
                message['headers'] = [
                    *message.get('headers', []),
                    (b'a2a-extensions', ','.join(sorted(activated)).encode('latin-1')),
                ]
                # end if
            await send(message)
            # end def

        await self._app(scope, receive, send_with_header)
        # end def

    # end class


class ActivationContextBuilder(DefaultServerCallContextBuilder):
    """The SDK's call context builder, with the request's activation set from `ActivationMiddleware`."""

    def build(self, request: Request) -> ServerCallContext:
        """Build the SDK's context and carry the activation set in its state."""
        context = super().build(request)
        context.state[_ACTIVATED] = request.scope.get(_ACTIVATED, set())
        return context
        # end def

    # end class


def activated_extensions(context: ServerCallContext) -> MutableSet[str]:
    """The extensions activated for this call, which `ActivationMiddleware` writes into the response."""
    activated = context.state.setdefault(_ACTIVATED, set())
    return activated  # type: ignore[no-any-return]
    # end def


def _audit_session_of(task: Task | None) -> AuditSession | None:
    """The `auditSession` a stored Task carries, if it is audit-negotiated."""
    if task is None:
        return None
        # end if
    own = metadata_of(task.metadata).get(EXTENSION_URI)
    if not isinstance(own, dict) or 'auditSession' not in own:
        return None
        # end if
    try:
        return AuditSession.model_validate(own['auditSession'])
    except ValueError:
        return None
        # end try
    # end def


class AuditedRequestHandler(DefaultRequestHandler):
    """The SDK's request handler, deciding each request as §4.3 - §4.6 direct before the SDK takes it.

    Serve it with `ActivationContextBuilder` as the routes' `context_builder`, inside `ActivationMiddleware`.
    """

    def __init__(
        self,
        *,
        required: bool,
        params: AgentCardParams,
        session_in_use: Callable[[str, ServerCallContext], Awaitable[SessionUse | None]],
        on_credentials: Callable[[str, AuditCredentials], Awaitable[None]],
        **kwargs: Any,
    ) -> None:
        """Bind the declaration and the Server Agent's callbacks; `kwargs` go to the SDK's handler.

        Args:
            required: The posture: mandatory when True (§4.5). The same entry must be in the Agent Card.
            params: What the Server Agent declares (§3.1).
            session_in_use: Who already uses a `sessionId`, from the Server Agent's Task store (§4.3). Reserve
                the `sessionId` atomically with this read, or two concurrent requests bind one session to two Tasks.
            on_credentials: Replace the running Task's endpoint credentials (§5.7); the request's Message is then
                processed as usual.
            **kwargs: The SDK's `DefaultRequestHandler` arguments.
        """
        super().__init__(**kwargs)
        self._required = required
        self._params = params
        self._session_in_use = session_in_use
        self._on_credentials = on_credentials
        # end def

    async def _admit(self, params: SendMessageRequest, context: ServerCallContext) -> None:
        """Decide the request; on return, the SDK may take it.

        Raises:
            InvalidParamsError: §4.4 or §4.6 rejects the request.
            ExtensionSupportRequiredError: The mandatory posture, without this extension (§4.5).
        """
        requested = sorted(context.requested_extensions)
        metadata = metadata_of(params.metadata)
        task_id = params.message.task_id
        if not task_id:

            async def in_use(session_id: str) -> SessionUse | None:
                return await self._session_in_use(session_id, context)
                # end def

            admission = await admit_new_task(
                required=self._required,
                params=self._params,
                requested_extensions=requested,
                metadata=metadata,
                session_in_use=in_use,
            )
            if admission.kind == 'unsupported':
                raise ExtensionSupportRequiredError(message=f'this agent requires the extension {EXTENSION_URI}')
            elif admission.kind == 'invalid' and admission.rejection is not None:
                raise rejection_error(admission.rejection)
            elif admission.kind == 'negotiated':
                activated_extensions(context).add(EXTENSION_URI)
                # end if
            return
            # end if
        self._require_activation(context)
        task = await self.on_get_task(GetTaskRequest(tenant=params.tenant, id=task_id), context)
        later = admit_later_request(
            requested_extensions=requested,
            metadata=metadata,
            audit_negotiated=_audit_session_of(task) is not None,
        )
        if later.kind == 'invalid' and later.rejection is not None:
            raise rejection_error(later.rejection)
        elif later.kind == 'credentials' and later.credentials is not None:
            await self._on_credentials(task_id, later.credentials)
            activated_extensions(context).add(EXTENSION_URI)
        elif later.activate:
            activated_extensions(context).add(EXTENSION_URI)
            # end if
        # end def

    async def on_message_send(self, params: SendMessageRequest, context: ServerCallContext) -> Message | Task:
        """Decide the request, then send the message as the SDK does."""
        await self._admit(params, context)
        result: Message | Task = await super().on_message_send(params, context)
        return result
        # end def

    async def on_message_send_stream(
        self, params: SendMessageRequest, context: ServerCallContext
    ) -> AsyncGenerator[Event, None]:
        """Decide the request before the first event, then stream as the SDK does."""
        await self._admit(params, context)
        async for event in super().on_message_send_stream(params, context):
            yield event
            # end async for
        # end def

    def _require_activation(self, context: ServerCallContext) -> None:
        """Under the mandatory posture, every request lists this extension, or A2A refuses it (§4.6, A2A §3.3.4).

        Raises:
            ExtensionSupportRequiredError: The mandatory posture, and the request does not list this extension.
        """
        if self._required and EXTENSION_URI not in context.requested_extensions:
            raise ExtensionSupportRequiredError(message=f'this agent requires the extension {EXTENSION_URI}')
            # end if
        # end def

    async def on_get_task(self, params: GetTaskRequest, context: ServerCallContext) -> Task | None:
        """Return the Task, listing this extension when the request does and the Task is audit-negotiated."""
        self._require_activation(context)
        task: Task | None = await super().on_get_task(params, context)
        if EXTENSION_URI in context.requested_extensions and _audit_session_of(task) is not None:
            activated_extensions(context).add(EXTENSION_URI)
            # end if
        return task
        # end def

    async def on_cancel_task(self, params: CancelTaskRequest, context: ServerCallContext) -> Task | None:
        """Cancel as the SDK does, listing this extension as `on_get_task` does."""
        self._require_activation(context)
        task: Task | None = await super().on_cancel_task(params, context)
        if EXTENSION_URI in context.requested_extensions and _audit_session_of(task) is not None:
            activated_extensions(context).add(EXTENSION_URI)
            # end if
        return task
        # end def

    async def on_create_task_push_notification_config(
        self, params: TaskPushNotificationConfig, context: ServerCallContext
    ) -> TaskPushNotificationConfig:
        """As the SDK does, under the posture (§4.6)."""
        self._require_activation(context)
        config: TaskPushNotificationConfig = await super().on_create_task_push_notification_config(params, context)
        return config
        # end def

    async def on_get_task_push_notification_config(
        self, params: GetTaskPushNotificationConfigRequest, context: ServerCallContext
    ) -> TaskPushNotificationConfig:
        """As the SDK does, under the posture (§4.6)."""
        self._require_activation(context)
        config: TaskPushNotificationConfig = await super().on_get_task_push_notification_config(params, context)
        return config
        # end def

    async def on_list_task_push_notification_configs(
        self, params: ListTaskPushNotificationConfigsRequest, context: ServerCallContext
    ) -> ListTaskPushNotificationConfigsResponse:
        """As the SDK does, under the posture (§4.6)."""
        self._require_activation(context)
        configs: ListTaskPushNotificationConfigsResponse = await super().on_list_task_push_notification_configs(
            params, context
        )
        return configs
        # end def

    async def on_delete_task_push_notification_config(
        self, params: DeleteTaskPushNotificationConfigRequest, context: ServerCallContext
    ) -> None:
        """As the SDK does, under the posture (§4.6)."""
        self._require_activation(context)
        await super().on_delete_task_push_notification_config(params, context)
        # end def

    async def on_subscribe_to_task(
        self, params: SubscribeToTaskRequest, context: ServerCallContext
    ) -> AsyncGenerator[Event, None]:
        """As the SDK does, under the posture (§4.6)."""
        self._require_activation(context)
        async for event in super().on_subscribe_to_task(params, context):
            yield event
            # end async for
        # end def

    async def on_list_tasks(self, params: ListTasksRequest, context: ServerCallContext) -> ListTasksResponse:
        """As the SDK does, under the posture (§4.6)."""
        self._require_activation(context)
        tasks: ListTasksResponse = await super().on_list_tasks(params, context)
        return tasks
        # end def

    # end class


@dataclass(frozen=True)
class AuditContext:
    """What an executor receives of this extension for the request it runs."""

    audit_session: AuditSession
    request: AuditRequest | None = None
    """The validated `auditRequest`, on the request that created the Task only; the credentials are in it."""
    # end class


class AuditedAgentExecutor(Protocol):
    """An executor that runs an audit-negotiated Task; `audit` is None for an ordinary one (§4.5)."""

    async def execute(self, context: RequestContext, event_queue: EventQueue, audit: AuditContext | None) -> None:
        """Run the request."""
        ...

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Cancel the Task."""
        ...

    # end class


class _AuditSessionQueue(EventQueue):
    """An event queue that places `auditSession` in every Task, and a direct Message, enqueued through it."""

    def __init__(self, inner: EventQueue, metadata: dict[str, object]) -> None:
        """Wrap the SDK's queue."""
        self._inner = inner
        self._metadata = metadata
        # end def

    async def enqueue_event(self, event: Event) -> None:
        """Enqueue `event`, a Task or Message with `auditSession` in its `metadata`."""
        if isinstance(event, Task | Message):
            event.metadata.update(cast('dict[str, Any]', self._metadata))
            # end if
        await self._inner.enqueue_event(event)
        # end def

    # end class


def _audit_context_of(context: RequestContext) -> AuditContext | None:
    """This extension's part of a request: of an audit-negotiated Task, or of one the handler activated it for."""
    # An audit-negotiated Task stays audited whatever a later request lists (§4.3, §8.1).
    existing = _audit_session_of(context.current_task)
    if existing is not None:
        return AuditContext(existing)
        # end if
    if EXTENSION_URI not in activated_extensions(context.call_context):
        return None
        # end if
    own = metadata_of(context.metadata).get(EXTENSION_URI)
    if not isinstance(own, dict):
        return None
        # end if
    try:
        request = AuditRequest.model_validate(own.get('auditRequest'))
    except ValueError:
        return None
        # end try
    session = AuditSession(sessionId=request.sessionId, level=request.level, countersign=request.countersign)
    return AuditContext(session, request)
    # end def


class AuditedExecutor(AgentExecutor):
    """An executor whose every Task, for an audit-negotiated request, carries `auditSession` (§4.3)."""

    def __init__(self, inner: AuditedAgentExecutor) -> None:
        """Wrap the Server Agent's executor."""
        self._inner = inner
        # end def

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Run the request, with this extension's part of it."""
        audit = _audit_context_of(context)
        if audit is None:
            await self._inner.execute(context, event_queue, None)
            return
            # end if
        queue = _AuditSessionQueue(event_queue, audit_session_metadata(audit.audit_session))
        await self._inner.execute(context, queue, audit)
        # end def

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Cancel the Task."""
        await self._inner.cancel(context, event_queue)
        # end def

    # end class


def held_for_audit(task_id: str, context_id: str, status: AuditStatus, text: str = _HELD_TEXT) -> TaskStatusUpdateEvent:
    """The status update that holds a Task for audit (§8.4): `TASK_STATE_AUTH_REQUIRED`, with `auditStatus`."""
    message = Message(
        message_id=str(uuid.uuid4()),
        context_id=context_id,
        task_id=task_id,
        role=Role.ROLE_AGENT,
        parts=[Part(text=text)],
        metadata=audit_status_metadata(status),
    )
    return TaskStatusUpdateEvent(
        task_id=task_id,
        context_id=context_id,
        status=TaskStatus(state=TaskState.TASK_STATE_AUTH_REQUIRED, message=message, timestamp=datetime.now(UTC)),
    )
    # end def


def resumed_from_hold(task_id: str, context_id: str) -> TaskStatusUpdateEvent:
    """The status update that resumes a Task once nothing is held (§8.4)."""
    return TaskStatusUpdateEvent(
        task_id=task_id,
        context_id=context_id,
        status=TaskStatus(state=TaskState.TASK_STATE_WORKING, timestamp=datetime.now(UTC)),
    )
    # end def


@dataclass(frozen=True)
class ReadRejection:
    """What a Client reads of a §4.4 rejection: the field, and the Task a reused `sessionId` belongs to."""

    field: str
    session_in_use: str | None = None
    """The Task's id, present only when the Server Agent named it as the same Client's (§4.4)."""
    # end class


def read_rejection(error: BaseException) -> ReadRejection | None:
    """Read a §4.4 rejection from an error the SDK's client raised: its `data` is the `ErrorInfo`'s `metadata`."""
    data = getattr(error, 'data', None)
    if not isinstance(data, Mapping) or not isinstance(data.get('auditField'), str):
        return None
        # end if
    task_id = data.get('auditTaskId')
    in_use = task_id if data.get('auditReason') == AUDIT_SESSION_IN_USE and isinstance(task_id, str) else None
    return ReadRejection(data['auditField'], in_use)
    # end def


async def send_audited(
    client: Client, request: SendMessageRequest, audit_request: AuditRequest
) -> tuple[Task | Message | None, bool]:
    """Delegate with this extension activated and `audit_request` attached; say whether the Task is audited (§4.3).

    The `auditRequest` is placed in `request.metadata` itself.

    Returns:
        The last Task or Message the response carried, and whether it shows the Task audited. A Client that
        requires audit treats False as not audited.
    """
    request.metadata.update(cast('dict[str, Any]', audit_request_metadata(audit_request)))
    context = ClientCallContext(
        service_parameters=ServiceParametersFactory.create([with_a2a_extensions([EXTENSION_URI])])
    )
    result: Task | Message | None = None
    async for response in client.send_message(request, context=context):
        if response.HasField('task'):
            result = response.task
        elif response.HasField('message'):
            result = response.message
            # end if
        # end async for
    audited = result is not None and is_audited(audit_request, metadata_of(result.metadata))
    return result, audited
    # end def
