"""The Client's audit host, as a process: the HTTPS audit endpoint (§6), its keys, and the walk's controls.

- `POST /a2a`: the audit endpoint.
- `GET /keys.json`: the countersignature keys, as `hostKeys` names them (§10.2).
- `POST /admin/sessions`: open a session for a delegation (§5.1), as the Client asks its own audit host.
- `GET /admin/ledger`: the partition's records and each session's evidence, for the verifiers (§11).
- `POST /admin/outcomes`: `{"refuse": true}` answers outcomes `503` until set back, as a host that cannot
  record them would.
- `POST /admin/attempts`: `{"refuse": "<action_type>"}` answers attempts of that kind `503` until set back with
  `null`, as a host whose store for them is down would.
- `GET /admin/exchanges`: every submission and its answer, in order, for the end-to-end example (§16).

The `/admin` controls exist for the walk only.
"""

import json
import os
from typing import Any

import anyio
import uvicorn
from auditable_mcp.l2 import Ed25519Countersigner, generate_tool_key
from auditable_mcp.l2.algorithms import KeyRole
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send

from auditable_a2a import A2aAuditHost, Countersign, InMemorySessionStore, Level, key_id_of
from auditable_a2a.endpoint_handler import create_audit_endpoint_handler
from walk.common import announce, listening_socket, ordinary_jwk


def _evidence(state: Any) -> dict[str, object]:
    """A session's evidence, in the JSON shape of the TypeScript SDK's `SessionEvidence`."""
    end = state.end
    return {
        'sessionId': state.session_id,
        'version': state.version,
        'level': str(state.level),
        'countersign': str(state.countersign),
        **({} if state.attestation_keys is None else {'attestationKeys': state.attestation_keys}),
        **({} if state.key_snapshot is None else {'keySnapshot': state.key_snapshot}),
        **({} if state.bound_key_id is None else {'boundKeyId': state.bound_key_id}),
        **({} if end is None else {'end': {'cause': str(end.cause), 'at': end.at, 'lastSeq': end.last_seq}}),
        'anomalies': [{'id': a.id, 'kind': a.kind, 'detail': a.detail} for a in state.anomalies],
    }
    # end def


async def main() -> None:
    """Serve until killed."""
    sock = listening_socket()
    base = f'https://127.0.0.1:{sock.getsockname()[1]}'
    host_keys = f'{base}/keys.json'
    host_key = generate_tool_key(key_id_of(host_keys, 'h1'))
    store = InMemorySessionStore()
    host = A2aAuditHost.create(
        'walk-client',
        Level.L2,
        Countersign.HOST,
        store=store,
        countersigner=Ed25519Countersigner(host_key.key_id, host_key.private_key),
    )
    endpoint = create_audit_endpoint_handler(host)
    refuse_outcomes = False
    refuse_attempts: str | None = None
    exchanges: list[dict[str, object]] = []

    async def audit(scope: Scope, receive: Receive, send: Send) -> None:
        body = b''
        more = True
        while more:
            message = await receive()
            body += message.get('body', b'')
            more = message.get('more_body', False)
            # end while
        try:
            submission = json.loads(body)
        except ValueError:
            submission = {}
            # end try
        event = submission.get('event') or {}
        outcome = event.get('outcome') if isinstance(event, dict) else None
        refused = (refuse_outcomes and outcome not in (None, 'attempted')) or (
            refuse_attempts is not None and outcome == 'attempted' and event.get('action_type') == refuse_attempts
        )
        if refused:
            exchanges.append({'submission': submission, 'status': 503, 'answer': None})
            await Response(status_code=503)(scope, receive, send)
            return
            # end if
        delivered = False
        answered: dict[str, object] = {'status': None, 'body': b''}

        async def recording(message: Message) -> None:
            if message['type'] == 'http.response.start':
                answered['status'] = message['status']
            elif message['type'] == 'http.response.body':
                answered['body'] = answered['body'] + message.get('body', b'')  # type: ignore[operator]
                # end if
            await send(message)
            # end def

        async def replay() -> Message:
            nonlocal delivered
            if delivered:
                return {'type': 'http.disconnect'}
                # end if
            delivered = True
            return {'type': 'http.request', 'body': body, 'more_body': False}
            # end def

        await endpoint(scope, replay, recording)
        raw = answered['body']
        try:
            answer = json.loads(raw) if raw else None  # type: ignore[arg-type]
        except ValueError:
            answer = None
            # end try
        exchanges.append({'submission': submission, 'status': answered['status'], 'answer': answer})
        # end def

    async def keys(request: Request) -> Response:
        return JSONResponse({'keys': [ordinary_jwk('h1', host_key.public_key, KeyRole.HOST)]})
        # end def

    async def open_session(request: Request) -> Response:
        body = await request.json()
        session_id, auth = await host.open_session(
            delegate=body['delegate'],
            expires_at=body['expiresAt'],
            attestation_keys=body['attestationKeys'],
            key_snapshot=body['keySnapshot'],
            host_keys=host_keys,
        )
        return JSONResponse(
            {
                'sessionId': session_id,
                'authentication': {'scheme': auth.scheme, 'credentials': auth.credentials},
                'hostKeys': host_keys,
            }
        )
        # end def

    async def ledger(request: Request) -> Response:
        records = [record.to_dict() for record in host.records()]
        return JSONResponse({'records': records, 'sessions': [_evidence(s) for s in await store.all()]})
        # end def

    async def attempts(request: Request) -> Response:
        nonlocal refuse_attempts
        refuse_attempts = (await request.json())['refuse']
        return JSONResponse({'refuse': refuse_attempts})
        # end def

    async def recorded(request: Request) -> Response:
        return JSONResponse({'exchanges': exchanges})
        # end def

    async def outcomes(request: Request) -> Response:
        nonlocal refuse_outcomes
        refuse_outcomes = bool((await request.json())['refuse'])
        return JSONResponse({'refuse': refuse_outcomes})
        # end def

    admin = Starlette(
        routes=[
            Route('/keys.json', keys),
            Route('/admin/sessions', open_session, methods=['POST']),
            Route('/admin/ledger', ledger),
            Route('/admin/outcomes', outcomes, methods=['POST']),
            Route('/admin/attempts', attempts, methods=['POST']),
            Route('/admin/exchanges', recorded),
        ]
    )

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] == 'http' and scope['path'] == '/a2a':
            await audit(scope, receive, send)
        else:
            await admin(scope, receive, send)
            # end if
        # end def

    config = uvicorn.Config(
        app,
        log_level='warning',
        ssl_certfile=os.environ['WALK_TLS_CERT'],
        ssl_keyfile=os.environ['WALK_TLS_KEY'],
        lifespan='off',
    )
    announce(base)
    await uvicorn.Server(config).serve(sockets=[sock])
    # end def


if __name__ == '__main__':
    anyio.run(main)
    # end if
