"""A `Post` and a `FetchHostKeys` built on httpx (installed with the `http` extra).

Redirects are not followed (§6.8, §13.1): httpx follows none unless asked to.
"""

import json
from collections.abc import Mapping
from typing import Any

import anyio
import httpx

from auditable_a2a.endpoint_client import DEFAULT_TIMEOUT_SECONDS, Post
from auditable_a2a.host_keys import FetchHostKeys


def httpx_post(client: httpx.AsyncClient) -> Post:
    """Return a `Post` that sends through `client`.

    Args:
        client: The httpx client; its own timeout is left to the caller, the endpoint client bounds each POST.

    Returns:
        The `Post`.
    """

    async def post(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        try:
            response = await client.post(url, headers=headers, content=body, follow_redirects=False)
        except httpx.HTTPError as error:
            raise OSError(str(error)) from error
            # end try
        return response.status_code, response.content
        # end def

    return post
    # end def


def httpx_fetch_host_keys(client: httpx.AsyncClient, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> FetchHostKeys:
    """Return a `FetchHostKeys` that GETs through `client`: one request, no redirect, bounded to `timeout`.

    Anything but a `200` whose body is a JSON object raises `OSError`.

    Args:
        client: The httpx client.
        timeout: The bound on the fetch, in seconds.

    Returns:
        The `FetchHostKeys`.
    """

    async def fetch(url: str) -> Mapping[str, Any]:
        response: httpx.Response | None = None
        with anyio.move_on_after(timeout):
            try:
                response = await client.get(url, follow_redirects=False)
            except httpx.HTTPError as error:
                raise OSError(str(error)) from error
                # end try
            # end with
        if response is None:
            raise OSError(f'hostKeys did not answer within {timeout} seconds')
            # end if
        if response.status_code != 200:
            raise OSError(f'hostKeys answered {response.status_code}')
            # end if
        try:
            body = json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OSError('hostKeys is not JSON') from error
            # end try
        if not isinstance(body, dict):
            raise OSError('hostKeys is not a JWK Set')
            # end if
        return body
        # end def

    return fetch
    # end def
