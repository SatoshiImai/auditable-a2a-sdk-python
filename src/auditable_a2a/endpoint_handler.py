"""The audit endpoint over HTTP (§6): a plain ASGI application around an `A2aAuditHost`."""

import json
import logging
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, Final

from auditable_a2a.audit_host import A2aAuditHost

logger = logging.getLogger(__name__)

_CHALLENGE: Final = [(b'www-authenticate', b'Bearer')]

DEFAULT_MAX_BODY_BYTES: Final = 1024 * 1024
"""The transport's cap on a request body; a submission is one a-MCP event or a marker (§6.1)."""

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
AsgiApp = Callable[[Scope, Receive, Send], Awaitable[None]]


async def _respond(
    send: Send, status: int, body: object | None, headers: list[tuple[bytes, bytes]] | None = None
) -> None:
    """Send one HTTP response, JSON when there is a body."""
    payload = b'' if body is None else json.dumps(body, ensure_ascii=False).encode('utf-8')
    response_headers = list(headers or [])
    if body is not None:
        response_headers.append((b'content-type', b'application/json'))
        # end if
    await send({'type': 'http.response.start', 'status': status, 'headers': response_headers})
    await send({'type': 'http.response.body', 'body': payload})
    # end def


async def _read_capped(receive: Receive, max_bytes: int) -> bytes | None:
    """Read the request body, or None once it passes `max_bytes`."""
    chunks: list[bytes] = []
    total = 0
    more = True
    while more:
        message = await receive()
        chunk = message.get('body', b'')
        total += len(chunk)
        if total > max_bytes:
            return None
            # end if
        chunks.append(chunk)
        more = bool(message.get('more_body', False))
        # end while
    return b''.join(chunks)
    # end def


def create_audit_endpoint_handler(host: A2aAuditHost, *, max_body_bytes: int = DEFAULT_MAX_BODY_BYTES) -> AsgiApp:
    """Return an ASGI app answering `POST` submissions at the audit endpoint (§6.1 - §6.7).

    Args:
        host: The audit host.
        max_body_bytes: The largest request body read; a larger one is refused with `413` before it is parsed.

    Returns:
        The ASGI application.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get('type') != 'http':
            return
            # end if
        if scope.get('method') != 'POST':
            await _respond(send, 405, None, [(b'allow', b'POST')])
            return
            # end if
        raw = await _read_capped(receive, max_body_bytes)
        if raw is None:
            await _respond(send, 413, {'error': f'a submission is at most {max_body_bytes} bytes'})
            return
            # end if
        try:
            body = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            await _respond(send, 400, {'error': 'the body is not JSON (§6.1)'})
            return
            # end try
        authorization = next(
            (value.decode('latin-1') for name, value in scope.get('headers', []) if name.lower() == b'authorization'),
            None,
        )
        try:
            answer = await host.handle(body, authorization)
        except Exception:
            # The Server Agent reads 503 as not recorded (§6.2, §6.3). A cancellation is not caught.
            logger.exception('the audit host failed to answer a submission')
            await _respond(send, 503, {'error': 'the submission could not be recorded; send it again (§6.3)'})
            return
            # end try
        # A 401 names the scheme of the credentials the audit host issues (§6.6, RFC 9110 §15.5.2).
        await _respond(send, answer.status, answer.body, _CHALLENGE if answer.status == 401 else None)
        # end def

    return app
    # end def
