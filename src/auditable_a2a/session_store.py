"""§5.1, §5.6: what an audit host keeps for each audit session, durably until it purges the session."""

import copy
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from auditable_mcp import SignerTracker

from auditable_a2a.models import Countersign, Level


class SessionStoreError(Exception):
    """A session's state was not stored; the audit host leaves the session as it was."""

    # end class


class EndCause(StrEnum):
    """How a session ended (§5.4): the first of these to happen."""

    CLOSE = 'close'
    CLIENT_NOTICE = 'client-notice'
    EXPIRY = 'expiry'
    # end class


@dataclass
class IssuedCredential:
    """One credential the audit host issued for a session (§5.7, §6.1)."""

    scheme: str
    credentials: str
    retired_for_attempts: bool = False
    """Set once a newer credential has been used: from then on it admits only records owed (§5.7)."""
    newest_until_seq: int | None = None
    """When it was retired, the last `seq` the session had sealed: it admits only what attempts up to it owe (§5.4)."""
    # end class


@dataclass(frozen=True)
class SessionAnomaly:
    """An entry of the session's anomaly set (§5.4, §6.3, §6.6)."""

    id: str
    kind: str
    detail: str
    # end class


@dataclass(frozen=True)
class SessionEnd:
    """The end of a session (§5.4)."""

    cause: EndCause
    at: str
    last_seq: int | None
    # end class


@dataclass
class SessionState:
    """Everything §5.1 and §5.6 require an audit host to keep for one session."""

    session_id: str
    version: str
    """The version the session was opened for: the URI of the specification (§4.1, §5.1)."""
    delegate: str
    """The URL of the Agent Card the Client delegated to (§5.1)."""
    level: Level
    countersign: Countersign
    expires_at: str
    host_keys: str | None = None
    attestation_keys: str | None = None
    """Under Level 2: the `attestationKeys` URL; `key_snapshot` is the JWKS fetched from it at open."""
    key_snapshot: dict[str, Any] | None = None
    credentials: list[IssuedCredential] = field(default_factory=list)
    bound_task_id: str | None = None
    """Bound by the first attempt that passes validation (§5.1), with `bound_key_id` under Level 2."""
    bound_key_id: str | None = None
    end: SessionEnd | None = None
    anomalies: list[SessionAnomaly] = field(default_factory=list)
    signers: SignerTracker | None = None
    """Under Level 2, the `signer_seq` values decided and the highest received, per key (§5.6, a-MCP §7.4)."""
    # end class


class SessionStore(Protocol):
    """The durable store of session states (§5.6)."""

    async def put(self, state: SessionState) -> None:
        """Store the session's state durably.

        Raises:
            SessionStoreError: The state was not stored.
        """
        ...

    async def all(self) -> list[SessionState]:
        """Every session the store holds, ended or not, until the audit host purges it."""
        ...

    async def delete(self, session_id: str) -> None:
        """Forget a purged session."""
        ...

    # end class


class InMemorySessionStore:
    """A process-local `SessionStore`; it does not survive the process, so it does not meet §5.6 alone."""

    def __init__(self) -> None:
        """Start empty."""
        self._states: dict[str, SessionState] = {}
        # end def

    async def put(self, state: SessionState) -> None:
        """Store a copy of the session's state."""
        self._states[state.session_id] = copy.deepcopy(state)
        # end def

    async def all(self) -> list[SessionState]:
        """Return copies of every stored state."""
        return [copy.deepcopy(state) for state in self._states.values()]
        # end def

    async def delete(self, session_id: str) -> None:
        """Forget the session's state."""
        self._states.pop(session_id, None)
        # end def

    # end class
