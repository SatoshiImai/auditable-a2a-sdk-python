"""§10.2: keys published as JWKS, and the a-MCP key registries a session verifies against.

Whose keys a set holds is known from where it was named (`attestationKeys` or `hostKeys`), not from the set.
"""

from collections.abc import Mapping
from typing import Any

from auditable_mcp import KeyRole
from auditable_mcp.l2 import REVOKED_MEMBER, ROLE_MEMBER, KeyRegistry, public_key_of


def key_id_of(jwks_url: str, kid: str) -> str:
    """Return a key's a-MCP identifier (`key_id` or `host_key_id`): the JWKS URL, `#`, and the `kid`.

    Args:
        jwks_url: The JWKS URL, which carries no fragment (§3.1, §7.1).
        kid: The JWK's `kid`.

    Returns:
        The key id.

    Raises:
        ValueError: The URL carries a fragment, so the first `#` would not separate URL from `kid`.
    """
    if '#' in jwks_url:
        raise ValueError(f'a JWKS URL carries no fragment (§10.2): {jwks_url}')
        # end if
    return f'{jwks_url}#{kid}'
    # end def


def registry_from_jwks(jwks_url: str, document: Mapping[str, Any], role: KeyRole) -> KeyRegistry:
    """Load the JWK Set fetched from `jwks_url` into a registry of `role`, keyed by `key_id_of` (§10.2).

    One non-conforming JWK refuses the whole set (a-MCP §5.1).

    Args:
        jwks_url: Where the set was fetched from.
        document: The JWK Set.
        role: Whose keys the set holds, from where it was named.

    Returns:
        The registry.

    Raises:
        ValueError: The set, or any key in it, is not a conforming registry entry.
    """
    keys = document.get('keys')
    if not isinstance(keys, list):
        raise ValueError('a JWK Set carries its keys under `keys` (RFC 7517)')
        # end if
    seen: set[str] = set()
    registry = KeyRegistry(role)
    for jwk in keys:
        if not isinstance(jwk, dict):
            raise ValueError("every member of a JWK Set's `keys` is a JWK object (RFC 7517)")
            # end if
        kid = jwk.get('kid')
        if not isinstance(kid, str) or kid == '':
            raise ValueError('every JWK carries a `kid` (§10.2)')
            # end if
        if kid in seen:
            raise ValueError(f'kid {kid!r} appears twice in {jwks_url}; a kid is unique within its set (§10.2)')
            # end if
        seen.add(kid)
        if not isinstance(jwk.get('alg'), str):
            raise ValueError(f'the JWK {kid!r} carries no `alg` (§10.2)')
            # end if
        # The role is where the set was named, so it is set, not read from the JWK.
        key_id, public_key, algorithm, _ = public_key_of({**jwk, 'kid': key_id_of(jwks_url, kid), ROLE_MEMBER: role})
        registry.register(key_id, public_key, algorithm)
        if jwk.get(REVOKED_MEMBER) is True:
            registry.revoke(key_id)
            # end if
        # end for
    return registry
    # end def
