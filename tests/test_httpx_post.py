"""The httpx `Post` and `FetchHostKeys`: no redirect followed (§6.8), and nothing answered raised as `OSError`."""

import httpx
import pytest

from auditable_a2a.httpx_post import httpx_fetch_host_keys, httpx_post


async def test_returns_a_redirect_without_following_it() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={'location': 'https://elsewhere.example/'})
        # end def

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        status, _ = await httpx_post(client)('https://audit.example/a2a', {}, b'{}')
        # end async with
    assert status == 302
    # end def


async def test_raises_os_error_when_nothing_answers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError('refused', request=request)
        # end def

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(OSError):
            await httpx_post(client)('https://audit.example/a2a', {}, b'{}')
            # end with
        # end async with
    # end def


async def test_fetches_a_jwk_set_and_refuses_a_redirect_to_one() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == '/keys.json':
            return httpx.Response(200, json={'keys': []})
            # end if
        return httpx.Response(302, headers={'location': 'https://audit.example/keys.json'})
        # end def

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        fetch = httpx_fetch_host_keys(client)
        assert await fetch('https://audit.example/keys.json') == {'keys': []}
        with pytest.raises(OSError, match='302'):
            await fetch('https://audit.example/moved.json')
            # end with
        # end async with
    # end def
