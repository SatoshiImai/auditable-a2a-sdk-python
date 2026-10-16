"""§5.5 step 3: whether the audit host's last position of a session agrees with the Server Agent's own ledger."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from auditable_mcp import compute_record_hash

from auditable_a2a.models import SessionPosition


@dataclass(frozen=True)
class HeldState:
    """What the Server Agent's own ledger holds for the session."""

    events: Sequence[Mapping[str, object]]
    """Every event it holds for the session, in the order it emitted them."""
    accepted_seqs: Sequence[int]
    """The `seq` of every accept it holds."""
    # end class


@dataclass(frozen=True)
class PositionCheck:
    """The result of the check: the event the position matched, or why it failed."""

    ok: bool
    matched: tuple[str, str] | None = None
    """The matched event's `id` and `outcome`, when it matched one."""
    reason: Literal['no-matching-event', 'later-accept', 'empty-with-accepts'] | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the result in the shape the vectors write it."""
        if not self.ok:
            return {'ok': False, 'reason': self.reason}
            # end if
        matched = None if self.matched is None else {'id': self.matched[0], 'outcome': self.matched[1]}
        return {'ok': True, 'matched': matched}
        # end def

    # end class


def check_position(position: SessionPosition, held: HeldState) -> PositionCheck:
    """Check the audit host's last position against the Server Agent's own ledger (§5.5 step 3).

    Args:
        position: The audit host's answer to a position request.
        held: What the Server Agent's own ledger holds.

    Returns:
        The event the position matched, or why it failed.
    """
    last = position.last
    if last is None:
        if held.accepted_seqs:
            return PositionCheck(ok=False, reason='empty-with-accepts')
            # end if
        return PositionCheck(ok=True)
        # end if
    if any(seq > last.seq for seq in held.accepted_seqs):
        return PositionCheck(ok=False, reason='later-accept')
        # end if
    for event in held.events:
        if compute_record_hash(dict(event), last.seq, last.host_ts, last.previous_hash) == last.record_hash:
            return PositionCheck(ok=True, matched=(str(event['id']), str(event['outcome'])))
            # end if
        # end for
    return PositionCheck(ok=False, reason='no-matching-event')
    # end def
