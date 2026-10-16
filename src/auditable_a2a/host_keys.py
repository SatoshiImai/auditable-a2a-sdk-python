"""The audit host's countersignature keys as the Server Agent holds them (§10.2).

A fetch that fails is a failure to record, not a failed countersignature: a-MCP aborts it as `host-unavailable`.
"""

import copy
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Literal

from auditable_mcp import KeyRole
from auditable_mcp.l2 import CountersignatureRegistryVerifier

from auditable_a2a.keys import key_id_of, registry_from_jwks

logger = logging.getLogger(__name__)

FetchHostKeys = Callable[[str], Awaitable[Mapping[str, Any]]]
"""Fetch the JWKS at a URL, following no redirect; it raises `OSError` when it could not."""


class HostKeysVerifier:
    """Verifies countersignatures against the host's keys, fetching them again for a `kid` it does not hold."""

    def __init__(self, url: str, snapshot: Mapping[str, Any], fetch_keys: FetchHostKeys | None = None) -> None:
        """Hold the key set fetched from `url`.

        Args:
            url: The `hostKeys` URL.
            snapshot: The JWKS fetched from it.
            fetch_keys: Fetches it again; without it, a `kid` not in `snapshot` does not verify.

        Raises:
            ValueError: `snapshot` is not a conforming registry (§10.2).
        """
        self._url = url
        self._fetch = fetch_keys
        self._snapshot = copy.deepcopy(dict(snapshot))
        self._verifier = CountersignatureRegistryVerifier(registry_from_jwks(url, snapshot, KeyRole.HOST))
        # end def

    @property
    def snapshot(self) -> dict[str, Any]:
        """The key set the verifier holds now, for the Server Agent's own ledger."""
        return copy.deepcopy(self._snapshot)
        # end def

    async def verify(self, host_key_id: str, signature: str, payload: bytes) -> bool | Literal['unavailable']:
        """Verify, after fetching the keys again when `host_key_id` is not among them."""
        if not self._holds(host_key_id) and self._fetch is not None:
            try:
                fetched = dict(await self._fetch(self._url))
                # A key set with a non-conforming JWK is refused as one not fetched is (§10.2).
                self._verifier = CountersignatureRegistryVerifier(registry_from_jwks(self._url, fetched, KeyRole.HOST))
            except Exception:
                # A cancellation is not caught.
                logger.warning('the audit host keys could not be fetched from %s', self._url, exc_info=True)
                return 'unavailable'
                # end try
            self._snapshot = fetched
            # end if
        return await self._verifier.verify(host_key_id, signature, payload)
        # end def

    def _holds(self, host_key_id: str) -> bool:
        """Whether the held key set has a key named `host_key_id`."""
        keys = self._snapshot.get('keys')
        return isinstance(keys, list) and any(
            isinstance(jwk, dict)
            and isinstance(jwk.get('kid'), str)
            and key_id_of(self._url, jwk['kid']) == host_key_id
            for jwk in keys
        )
        # end def

    # end class
