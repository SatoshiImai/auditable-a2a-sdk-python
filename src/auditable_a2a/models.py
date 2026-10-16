"""The structures this extension puts on the A2A wire and at the audit endpoint (§3.1, §6, §7).

Pydantic models of the vendored JSON Schemas (`spec/schema/`). Patterns shared with a-MCP are a-MCP's constants.
"""

from enum import StrEnum
from typing import Annotated, ClassVar, Final, Literal, get_args

from auditable_mcp import WireModel
from auditable_mcp.models import DATETIME_PATTERN as DATETIME_PATTERN
from auditable_mcp.models import SESSION_ID_PATTERN as SESSION_ID_PATTERN
from auditable_mcp.models import UUID_PATTERN
from pydantic import Field, StrictBool, model_validator

EXTENSION_URI: Final = 'https://timberlandchapel.com/a2a/extensions/auditable-a2a/0.1'
"""This version's extension URI (§4.1)."""

EVENT_ID_PATTERN: Final = UUID_PATTERN
"""A lowercase RFC 9562 UUID of versions 1-8, or the nil UUID: an a-MCP event id (a-MCP §4)."""
HTTPS_PATTERN: Final = r'^https://'
HTTPS_NO_FRAGMENT_PATTERN: Final = r'^https://[^#]+$'
"""An https URL without a fragment, which a key id joins to a `kid` with `#` (§10.2)."""
HEADER_VALUE_PATTERN: Final = r'^[^\x00-\x1f\x7f]+$'
"""No control characters (§7.1)."""
AUTH_SCHEME_PATTERN: Final = r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
"""An auth-scheme is a token (§6.1, RFC 9110 §11.4)."""
AUTH_CREDENTIALS_PATTERN: Final = r'^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$'
"""Credentials are visible ASCII with inner spaces, as an `Authorization` header carries them (§6.1)."""

_CHAIN_HASH_PATTERN: Final = r'^[0-9a-f]{64}$'
_BASE64URL_PATTERN: Final = r'^[A-Za-z0-9_-]+$'
_MAX_SAFE_INTEGER: Final = 2**53 - 1

AbortReason = Literal[
    'host-unavailable', 'host-rejected', 'host-uncountersigned', 'host-signature-invalid', 'hash-mismatch'
]
HostReason = Literal[
    'schema-invalid', 'replay-detected', 'signature-invalid', 'l2-unsigned', 'unknown-key', 'internal-error'
]

ABORT_REASONS: Final = get_args(AbortReason)
"""a-MCP Tier-1 abort codes (a-MCP §7.2, §7.6): why a Task is held (§7.3)."""
HOST_REASONS: Final = get_args(HostReason)
"""a-MCP Tier-1 host reject and unavailable codes (a-MCP §7.6): what the audit host answered (§7.3)."""

# A wire string ('L2', 'host') is read into the enum; the other members stay strict.
_LevelField = Annotated['Level', Field(strict=False)]
_CountersignField = Annotated['Countersign', Field(strict=False)]


class Level(StrEnum):
    """The a-MCP conformance levels (a-MCP §5)."""

    L1 = 'L1'
    L2 = 'L2'
    # end class


class Countersign(StrEnum):
    """The a-MCP countersignature axis (a-MCP §5.2)."""

    NONE = 'none'
    HOST = 'host'
    # end class


class AgentCardParams(WireModel):
    """§3.1: the Agent Card's `params`. A Level-2 Server Agent names its keys."""

    level: _LevelField
    countersign: _CountersignField
    selfChain: StrictBool | None = None
    attestationKeys: str | None = Field(default=None, pattern=HTTPS_NO_FRAGMENT_PATTERN)

    @model_validator(mode='after')
    def _level_2_names_its_keys(self) -> 'AgentCardParams':
        """A Level-2 Server Agent names its keys (§3.1)."""
        if self.level == Level.L2 and self.attestationKeys is None:
            raise ValueError('a Level-2 Server Agent names its keys (§3.1)')
            # end if
        return self
        # end def

    # end class


class AuthenticationInfo(WireModel):
    """A2A's AuthenticationInfo (A2A §4.3.2), with both members required and fit for an `Authorization` header."""

    scheme: str = Field(pattern=AUTH_SCHEME_PATTERN)
    credentials: str = Field(pattern=AUTH_CREDENTIALS_PATTERN)
    # end class


class AuditEndpoint(WireModel):
    """§7.1: where submissions are sent."""

    url: str = Field(pattern=HTTPS_PATTERN)
    authentication: AuthenticationInfo
    token: str | None = Field(default=None, pattern=HEADER_VALUE_PATTERN)
    # end class


class AuditRequest(WireModel):
    """§7.1: `SendMessageRequest.metadata[URI].auditRequest`. A countersigning audit host names its keys."""

    auditEndpoint: AuditEndpoint
    sessionId: str = Field(pattern=SESSION_ID_PATTERN)
    level: _LevelField
    countersign: _CountersignField
    hostKeys: str | None = Field(default=None, pattern=HTTPS_NO_FRAGMENT_PATTERN)
    expiresAt: str = Field(pattern=DATETIME_PATTERN)

    @model_validator(mode='after')
    def _countersigning_host_names_its_keys(self) -> 'AuditRequest':
        """A countersigning audit host names its keys (§7.1)."""
        if self.countersign == Countersign.HOST and self.hostKeys is None:
            raise ValueError('a countersigning audit host names its keys (§7.1)')
            # end if
        return self
        # end def

    # end class


class JournaledEndpoint(WireModel):
    """The audit endpoint as the Server Agent's own ledger keeps it: without its credentials (§13.2)."""

    url: str = Field(pattern=HTTPS_PATTERN)
    # end class


class JournaledRequest(AuditRequest):
    """The `auditRequest` as the Server Agent's own ledger keeps it: without the endpoint's credentials (§13.2)."""

    # Narrowed, not widened: every other member and the validator are `AuditRequest`'s.
    auditEndpoint: JournaledEndpoint  # type: ignore[assignment]
    # end class


class AuditSession(WireModel):
    """§7.2: `Task.metadata[URI].auditSession`."""

    sessionId: str = Field(pattern=SESSION_ID_PATTERN)
    level: _LevelField
    countersign: _CountersignField
    # end class


class AuditStatus(WireModel):
    """§7.3: the annotation on a held Task's status message."""

    reason: AbortReason
    hostReason: HostReason | None = None
    httpStatus: int | None = Field(default=None, ge=100, le=599)
    attemptId: str | None = Field(default=None, pattern=EVENT_ID_PATTERN)
    # end class


class AuditCredentials(WireModel):
    """§7.4: a replacement of the endpoint's credentials."""

    authentication: AuthenticationInfo
    token: str | None = Field(default=None, pattern=HEADER_VALUE_PATTERN)
    # end class


class AuditSubmission(WireModel):
    """§6.1: the body of one POST to the audit endpoint, carrying exactly one of event, position, close."""

    taskId: str = Field(min_length=1)
    token: str | None = Field(default=None, pattern=HEADER_VALUE_PATTERN)
    event: dict[str, object] | None = None
    position: Literal[True] | None = None
    close: Literal[True] | None = None

    @model_validator(mode='after')
    def _exactly_one_kind(self) -> 'AuditSubmission':
        """A submission carries exactly one of event, position, or close (§6.1)."""
        if [self.event, self.position, self.close].count(None) != 2:
            raise ValueError('a submission carries exactly one of event, position, or close (§6.1)')
            # end if
        return self
        # end def

    # end class


class SealedPosition(WireModel):
    """§6.5: a session's last sealed record, in the host-assigned fields of an a-MCP accept (a-MCP §7.1)."""

    seq: int = Field(ge=0, le=_MAX_SAFE_INTEGER)
    host_ts: str = Field(pattern=DATETIME_PATTERN)
    previous_hash: str = Field(pattern=_CHAIN_HASH_PATTERN)
    record_hash: str = Field(pattern=_CHAIN_HASH_PATTERN)
    log_id: str | None = Field(default=None, min_length=1)
    host_signature: str | None = Field(default=None, pattern=_BASE64URL_PATTERN)
    host_key_id: str | None = Field(default=None, min_length=1)

    @model_validator(mode='after')
    def _countersignature_fields_together(self) -> 'SealedPosition':
        """`log_id`, `host_signature`, and `host_key_id` appear together or not at all (a-MCP §7.1)."""
        if len({self.log_id is None, self.host_signature is None, self.host_key_id is None}) != 1:
            raise ValueError('log_id, host_signature, and host_key_id appear together or not at all (a-MCP §7.1)')
            # end if
        return self
        # end def

    # end class


class SessionPosition(WireModel):
    """§6.5: the answer to a position request. `last` is null when the session has no sealed record."""

    _NULLABLE_MEMBERS: ClassVar[frozenset[str]] = frozenset({'last'})

    last: SealedPosition | None
    # end class
