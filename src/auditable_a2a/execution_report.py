"""§8.6: the record by which a Server Agent states that it did not perform an accepted access.

It is an a-MCP attempt and its `success` outcome, in a fixed shape; the earlier attempt gets no outcome
and is recorded `unresolved-attempt` when the session ends.
"""

from collections.abc import Mapping
from enum import StrEnum
from typing import Final, Literal, TypedDict

from auditable_mcp import SPEC_VERSION

EXECUTION_REPORT_ACTION_TYPE: Final = 'a2a.execution-report'
AUDIT_SESSION_KIND: Final = 'a2a.audit-session'


class Execution(StrEnum):
    """What the Server Agent knows of an accepted access it did not resolve with an outcome (§8.6)."""

    NOT_PERFORMED = 'not-performed'
    INDETERMINATE = 'indeterminate'
    # end class


class ExecutionReportInput(TypedDict):
    """The values an execution report is built from."""

    id: str
    """The report's own event id, shared by its attempt and outcome."""
    ts: str
    sessionId: str
    attemptId: str
    """The `id` of the accepted attempt the report is about."""
    execution: Execution | str


def execution_report(report: ExecutionReportInput, outcome: Literal['attempted', 'success']) -> dict[str, object]:
    """Build the execution report's attempt (`attempted`) or outcome (`success`) event (§8.6).

    Args:
        report: The report's values.
        outcome: Which of the two events to build.

    Returns:
        The a-MCP event, as wire data.
    """
    return {
        'id': report['id'],
        'spec_version': SPEC_VERSION,
        'ts': report['ts'],
        'session_id': report['sessionId'],
        'action_type': EXECUTION_REPORT_ACTION_TYPE,
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': AUDIT_SESSION_KIND, 'ref': report['sessionId']},
        'outcome': outcome,
        # In the clear, not committed: the Client reads it (§8.6).
        'action_context': {'attemptId': report['attemptId'], 'execution': str(report['execution'])},
    }
    # end def


def is_execution_report(event: Mapping[str, object]) -> bool:
    """Whether `event` has every member §8.6 gives an execution report, not its `action_type` alone.

    Args:
        event: An a-MCP event, as wire data.

    Returns:
        True when it has the shape of §8.6.
    """
    target = event.get('target_resource')
    context = event.get('action_context')
    return (
        event.get('action_type') == EXECUTION_REPORT_ACTION_TYPE
        and event.get('mutates') is False
        and event.get('egress') is False
        and isinstance(target, Mapping)
        and set(target) == {'kind', 'ref'}
        and target.get('kind') == AUDIT_SESSION_KIND
        and target.get('ref') == event.get('session_id')
        and isinstance(context, Mapping)
        and set(context) == {'attemptId', 'execution'}
        and isinstance(context.get('attemptId'), str)
        and context.get('execution') in (Execution.NOT_PERFORMED, Execution.INDETERMINATE)
    )
    # end def
