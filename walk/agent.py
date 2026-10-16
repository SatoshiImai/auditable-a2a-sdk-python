"""The Server Agent, as a process: an A2A agent on the official SDK that records into the Client's audit host.

- `GET /.well-known/agent-card.json`: its Agent Card, declaring this extension at Level 2 with countersignatures.
- `GET /jwks.json`: its attestation keys (§10.2), from a key kept in `WALK_STATE_DIR` across restarts (§5.2).
- `GET /card-keys.json`: the key its Agent Card is signed with (§3.1, A2A §8.4), apart from the attestation key.
- `POST /`: A2A over JSON-RPC.

With `WALK_RESUME=1` it resumes every Task its own ledger in `WALK_STATE_DIR` holds (§5.5) before it serves, and
writes `WALK_RESUMED=<taskId> <state>` for each.
"""

import base64
import json
import os
import sys
import uuid
from pathlib import Path

import anyio
import httpx
import uvicorn
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
    Message,
    Part,
    Role,
    Task,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
)
from a2a.utils.signing import ProtectedHeader, create_agent_card_signer
from auditable_mcp import AmcpAbortedError
from auditable_mcp.l2 import Ed25519Signer, generate_tool_key, load_tool_key, tool_key_pkcs8
from auditable_mcp.l2.algorithms import KeyRole
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from auditable_a2a import (
    AgentCardParams,
    AuditCredentials,
    AuditedTask,
    AuditRequest,
    AuditStatus,
    ResumeContinue,
    SelfLedger,
    SessionUse,
    agent_card_extension,
    key_id_of,
    resume_task,
)
from auditable_a2a.a2a import (
    ActivationContextBuilder,
    ActivationMiddleware,
    AuditContext,
    AuditedExecutor,
    AuditedRequestHandler,
    held_for_audit,
    resumed_from_hold,
)
from auditable_a2a.httpx_post import httpx_fetch_host_keys, httpx_post
from walk.common import FileLedgerRepository, announce, listening_socket, ordinary_jwk, trust

TABLE: dict[str, object] = {'kind': 'table', 'ref': 'customers'}
LEDGER: dict[str, object] = {'kind': 'ledger', 'ref': 'general-ledger/2026-09'}
REPORT: dict[str, object] = {'kind': 'document', 'ref': 'settlement-report/2026-09'}


def _signer(state: Path, attestation_keys: str) -> tuple[Ed25519Signer, dict[str, object]]:
    """The agent's signing key, kept in the state directory so that a restart signs under the same key."""
    key_id = key_id_of(attestation_keys, 'a1')
    path = state / 'agent-key.der'
    if path.exists():
        key = load_tool_key(key_id, path.read_bytes())
    else:
        key = generate_tool_key(key_id)
        path.write_bytes(tool_key_pkcs8(key))
        # end if
    return Ed25519Signer.from_tool_key(key), {'keys': [ordinary_jwk('a1', key.public_key, KeyRole.TOOL)]}
    # end def


def _card_key(state: Path) -> Ed25519PrivateKey:
    """The Agent Card's signing key, kept in the state directory like the attestation key."""
    path = state / 'card-key.der'
    if path.exists():
        key = load_der_private_key(path.read_bytes(), password=None)
        assert isinstance(key, Ed25519PrivateKey)
        return key
        # end if
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))
    return key
    # end def


class _Agent:
    """The executor: one recorded read per audit-negotiated Task."""

    def __init__(self, state: Path, signer: Ed25519Signer, http: httpx.AsyncClient) -> None:
        """Keep the state directory, the signer, and the HTTPS client."""
        self._state = state
        self._signer = signer
        self._http = http
        self._repository = FileLedgerRepository(state / 'ledger')
        self.sessions: dict[str, str] = {}
        self.tasks: dict[str, AuditedTask] = {}
        """The audited Tasks held for a record, by id, which a later message takes up again (§8.5)."""
        # end def

    def _secrets(self, task_id: str) -> Path:
        """Where the endpoint's credentials for a Task are kept, apart from its own ledger (§13.2)."""
        return self._state / f'{task_id}.credentials.json'
        # end def

    async def execute(self, context: RequestContext, event_queue: EventQueue, audit: AuditContext | None) -> None:
        """Run the request; the end-to-end example's when it asks to reconcile (§16)."""
        task_id, context_id = str(context.task_id), str(context.context_id)
        # A later message is taken up on what this agent holds for the Task, whatever it lists (§4.3, §8.1).
        held = self.tasks.get(task_id)
        if held is not None:
            await self._fetch_report(held, task_id, context_id, event_queue, resumed=True)
            return
            # end if
        if context.current_task is None:
            await event_queue.enqueue_event(
                Task(id=task_id, context_id=context_id, status=TaskStatus(state=TaskState.TASK_STATE_WORKING))
            )
            # end if
        if audit is None or audit.request is None:
            await self._complete(task_id, context_id, event_queue, 'Done.')
            return
            # end if
        task = await self._audited(task_id, audit.request)
        if context.get_user_input().startswith('Reconcile'):
            self.tasks[task_id] = task
            async with task.action('ledger.read', LEDGER, mutates=False, egress=False, disclose={'period': '2026-09'}):
                pass
                # end async with
            await self._fetch_report(task, task_id, context_id, event_queue, resumed=False)
            return
            # end if
        async with task.action('db.read', TABLE, mutates=False, egress=False) as action:
            attempt_id = action.id
            # end async with
        if not await task.finish():
            status = AuditStatus.model_validate({'reason': 'host-unavailable', 'attemptId': attempt_id})
            await event_queue.enqueue_event(held_for_audit(task_id, context_id, status))
            return
            # end if
        await self._complete(task_id, context_id, event_queue, 'Done.')
        # end def

    async def _audited(self, task_id: str, request: AuditRequest) -> AuditedTask:
        """The audit of a Task this request negotiated, writing ahead into the own ledger (§5.5)."""
        self.sessions[request.sessionId] = task_id
        self._secrets(task_id).write_text(json.dumps(request.auditEndpoint.to_wire()))
        host_keys = (await self._http.get(str(request.hostKeys))).json()
        return AuditedTask(
            task_id=task_id,
            request=request,
            post=httpx_post(self._http),
            signer=self._signer,
            host_key_snapshot=host_keys,
            fetch_host_keys=httpx_fetch_host_keys(self._http),
            self_ledger=await SelfLedger.open(self._repository, task_id),
        )
        # end def

    async def _fetch_report(
        self, task: AuditedTask, task_id: str, context_id: str, event_queue: EventQueue, *, resumed: bool
    ) -> None:
        """Record and fetch the settlement report; hold the Task while it cannot be recorded (§8.4)."""
        try:
            async with task.action(
                'report.fetch', REPORT, mutates=False, egress=False, commit_salted={'path': '/settlement/2026-09.csv'}
            ):
                pass
                # end async with
        except AmcpAbortedError as error:
            await event_queue.enqueue_event(held_for_audit(task_id, context_id, task.status_of(error)))
            return
            # end try
        if resumed:
            await event_queue.enqueue_event(resumed_from_hold(task_id, context_id))
            # end if
        del self.tasks[task_id]
        await task.finish()
        await self._complete(task_id, context_id, event_queue, 'Reconciled: 3 entries differ.')
        # end def

    async def _complete(self, task_id: str, context_id: str, event_queue: EventQueue, text: str) -> None:
        """Move the Task to its terminal state, with a closing message."""
        message = Message(
            message_id=str(uuid.uuid4()),
            context_id=context_id,
            task_id=task_id,
            role=Role.ROLE_AGENT,
            parts=[Part(text=text)],
        )
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=task_id,
                context_id=context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_COMPLETED, message=message),
            )
        )
        # end def

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Nothing to cancel."""
        # end def

    async def resume_all(self) -> None:
        """Resume every Task the own ledger holds (§5.5), and say how each went."""
        for path in sorted((self._state / 'ledger').glob('*.jsonl')):
            task_id = path.stem
            endpoint = json.loads(self._secrets(task_id).read_text())
            result = await resume_task(
                self_ledger=await SelfLedger.open(self._repository, task_id),
                credentials=AuditCredentials.model_validate(
                    {
                        'authentication': endpoint['authentication'],
                        **({'token': endpoint['token']} if 'token' in endpoint else {}),
                    }
                ),
                post=httpx_post(self._http),
                signer=self._signer,
                fetch_host_keys=httpx_fetch_host_keys(self._http),
            )
            closed = isinstance(result, ResumeContinue) and await result.task.finish()
            sys.stdout.write(f'WALK_RESUMED={task_id} {result.state}{" closed" if closed else ""}\n')
            sys.stdout.flush()
            # end for
        # end def

    # end class


async def main() -> None:
    """Resume when asked, then serve until killed."""
    state = Path(os.environ['WALK_STATE_DIR'])
    state.mkdir(parents=True, exist_ok=True)
    sock = listening_socket()
    base = f'https://127.0.0.1:{sock.getsockname()[1]}'
    attestation_keys = f'{base}/jwks.json'
    signer, jwks = _signer(state, attestation_keys)
    params = AgentCardParams.model_validate(
        {'level': 'L2', 'countersign': 'host', 'selfChain': True, 'attestationKeys': attestation_keys}
    )
    declaration = agent_card_extension(params, required=False)
    card = AgentCard(
        name='ledger agent (Python)',
        description='reads the customers table',
        version='1.0.0',
        supported_interfaces=[AgentInterface(url=f'{base}/', protocol_binding='JSONRPC', protocol_version='1.0')],
        capabilities=AgentCapabilities(
            streaming=False,
            extensions=[AgentExtension(uri=str(declaration['uri']), required=False, params=declaration['params'])],  # type: ignore[arg-type]
        ),
        default_input_modes=['text/plain'],
        default_output_modes=['text/plain'],
    )
    card_key = _card_key(state)
    # Not an a-MCP key, so not published as one: its JWK names the JWS algorithm the signature carries.
    raw = card_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
    card_jwks = {'keys': [{'kty': 'OKP', 'crv': 'Ed25519', 'x': x, 'kid': 'c1', 'alg': 'EdDSA', 'use': 'sig'}]}
    protected: ProtectedHeader = {'kid': 'c1', 'alg': 'EdDSA', 'jku': f'{base}/card-keys.json', 'typ': 'JOSE'}
    card = create_agent_card_signer(
        card_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()), protected
    )(card)
    async with httpx.AsyncClient(verify=trust(), timeout=10) as http:
        agent = _Agent(state, signer, http)
        if os.environ.get('WALK_RESUME') == '1':
            await agent.resume_all()
            # end if

        async def session_in_use(session_id: str, context: ServerCallContext) -> SessionUse | None:
            task_id = agent.sessions.get(session_id)
            return None if task_id is None else SessionUse(task_id, same_client=True)
            # end def

        async def on_credentials(task_id: str, credentials: AuditCredentials) -> None:
            agent._secrets(task_id).write_text(json.dumps(credentials.to_wire()))
            # end def

        handler = AuditedRequestHandler(
            required=False,
            params=params,
            session_in_use=session_in_use,
            on_credentials=on_credentials,
            agent_executor=AuditedExecutor(agent),
            task_store=InMemoryTaskStore(),
            agent_card=card,
        )

        async def keys(request: Request) -> Response:
            return JSONResponse(jwks)
            # end def

        async def card_keys(request: Request) -> Response:
            return JSONResponse(card_jwks)
            # end def

        app = ActivationMiddleware(
            Starlette(
                routes=[
                    Route('/jwks.json', keys),
                    Route('/card-keys.json', card_keys),
                    *create_agent_card_routes(card),
                    *create_jsonrpc_routes(handler, '/', context_builder=ActivationContextBuilder()),
                ]
            )
        )
        config = uvicorn.Config(
            app,
            log_level='warning',
            ssl_certfile=os.environ['WALK_TLS_CERT'],
            ssl_keyfile=os.environ['WALK_TLS_KEY'],
            lifespan='off',
        )
        announce(base)
        await uvicorn.Server(config).serve(sockets=[sock])
        # end async with
    # end def


if __name__ == '__main__':
    anyio.run(main)
    # end if
