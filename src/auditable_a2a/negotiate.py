"""§4.3 conditions 3 and 4: whether a Server Agent's declaration meets a Client's audit request.

Conditions 1, 2 and 5 - the URI, a schema-valid request, a `sessionId` not used for another Task - are
checked before this comparison. Which field a refusal names when both fail is not fixed (§4.4).
"""

from dataclasses import dataclass
from typing import Literal, Protocol

from auditable_a2a.models import Countersign, Level


@dataclass(frozen=True)
class Negotiation:
    """The result of the comparison: negotiated, or the field that did not fit."""

    negotiated: bool
    field: Literal['level', 'countersign'] | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the result in the shape the vectors write it."""
        if self.negotiated:
            return {'negotiated': True}
            # end if
        return {'negotiated': False, 'field': self.field}
        # end def

    # end class


class Declaration(Protocol):
    """The two members the comparison reads: `AgentCardParams` and `AuditRequest` both have them."""

    @property
    def level(self) -> Level: ...

    @property
    def countersign(self) -> Countersign: ...

    # end class


def negotiate(params: Declaration, request: Declaration) -> Negotiation:
    """Compare the Server Agent's `params` with the Client's `auditRequest` (§4.3).

    Args:
        params: The Server Agent's declaration (`AgentCardParams`).
        request: The Client's request (`AuditRequest`).

    Returns:
        Negotiated, or the field that did not fit.
    """
    # Level 2 meets both levels; Level 1 meets only Level 1 (a-MCP §6.1).
    if request.level == Level.L2 and params.level != Level.L2:
        return Negotiation(negotiated=False, field='level')
        # end if
    # The countersignature axis runs the other way: the Server Agent requires, the audit host offers.
    if params.countersign == Countersign.HOST and request.countersign != Countersign.HOST:
        return Negotiation(negotiated=False, field='countersign')
        # end if
    return Negotiation(negotiated=True)
    # end def
