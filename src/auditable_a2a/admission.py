"""The Server Agent's and the Client's decisions on the A2A messages (§3, §4, §7), on plain JSON.

It knows no A2A SDK's types; `auditable_a2a.a2a` maps it onto `a2a-sdk`.
"""

import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

from auditable_mcp import WIRE
from pydantic import BaseModel, ValidationError

from auditable_a2a.models import (
    EXTENSION_URI,
    AgentCardParams,
    AuditCredentials,
    AuditRequest,
    AuditSession,
    AuditStatus,
)
from auditable_a2a.negotiate import negotiate

AUDIT_SESSION_IN_USE: Final = 'AUDIT_SESSION_IN_USE'
"""The `auditReason` naming the Task a reused `sessionId` belongs to (§4.4)."""


@dataclass(frozen=True)
class Rejection:
    """A validation error's details (§4.4), carried in the `metadata` of A2A's `ErrorInfo`."""

    field: str
    description: str
    session_in_use: str | None = None
    """The id of the Task a reused `sessionId` belongs to, when the same Client used it."""
    # end class


@dataclass(frozen=True)
class SessionUse:
    """Who already uses a `sessionId`, as the Server Agent's Task store answers (§4.3 condition 5, §4.4)."""

    task_id: str
    same_client: bool
    """The Task was created by the same authenticated Client as this request."""
    # end class


@dataclass(frozen=True)
class NewTaskAdmission:
    """The decision on a request that creates a Task (§4.3 - §4.5).

    - `ordinary`: not activated; serve as an ordinary A2A agent (§4.5).
    - `unsupported`: not activated under the mandatory posture; `ExtensionSupportRequiredError`.
    - `invalid`: activated and not negotiated; a validation error, and no Task (§4.4).
    - `negotiated`: list the URI in the response and place `audit_session` in every Task returned (§4.3).
    """

    kind: Literal['ordinary', 'unsupported', 'invalid', 'negotiated']
    rejection: Rejection | None = None
    request: AuditRequest | None = None
    audit_session: AuditSession | None = None
    # end class


@dataclass(frozen=True)
class LaterRequestAdmission:
    """The decision on a request on an existing Task (§4.6).

    - `continue`: nothing of this extension to act on; `activate` says whether to list the URI (§4.3).
    - `credentials`: replace the endpoint's credentials and nothing else (§5.7).
    - `invalid`: a validation error.
    """

    kind: Literal['continue', 'credentials', 'invalid']
    activate: bool = False
    credentials: AuditCredentials | None = None
    rejection: Rejection | None = None
    # end class


def agent_card_extension(
    params: AgentCardParams | Mapping[str, object], *, required: bool, description: str | None = None
) -> dict[str, object]:
    """What the Server Agent declares in `capabilities.extensions` (§3); `required` is the mandatory posture (§4.5).

    Raises:
        ValidationError: `params` is not a valid declaration (§3.1).
    """
    validated = params if isinstance(params, AgentCardParams) else AgentCardParams.model_validate(params, context=WIRE)
    return {
        'uri': EXTENSION_URI,
        **({} if description is None else {'description': description}),
        'required': required,
        'params': validated.to_wire(),
    }
    # end def


def _field(member: str, path: Sequence[object] = ()) -> str:
    """The field a rejection names, as §4.4's example writes it."""
    return '.'.join(part for part in (f'metadata[{json.dumps(EXTENSION_URI)}]', member, *map(str, path)) if part)
    # end def


def _rejection_of(member: str, error: ValidationError) -> Rejection:
    """The field and message of the first failure."""
    first = error.errors()[0]
    return Rejection(field=_field(member, first['loc']), description=first['msg'])
    # end def


def _own(metadata: object) -> Mapping[str, object] | Rejection | None:
    """This extension's member of a request's `metadata`: absent (None), an object, or a rejection."""
    if not isinstance(metadata, Mapping) or EXTENSION_URI not in metadata:
        return None
        # end if
    own = metadata[EXTENSION_URI]
    return own if isinstance(own, Mapping) else Rejection(field=_field(''), description='must be an object')
    # end def


async def admit_new_task(
    *,
    required: bool,
    params: AgentCardParams,
    requested_extensions: Sequence[str],
    metadata: object,
    session_in_use: Callable[[str], Awaitable[SessionUse | None]],
) -> NewTaskAdmission:
    """Decide a request that creates a Task (§4.3 - §4.5).

    Args:
        required: The Server Agent's posture: mandatory when True (§4.5).
        params: What it declares (§3.1).
        requested_extensions: The URIs the request lists in `A2A-Extensions` (§4.2).
        metadata: The request's `SendMessageRequest.metadata`.
        session_in_use: Who already uses a `sessionId`, if anyone (§4.3 condition 5).

    Returns:
        The decision.
    """
    own = _own(metadata)
    if EXTENSION_URI not in requested_extensions:
        # §4.4: this extension's metadata without the activation shows audit was asked for and the activation lost.
        carried = next((m for m in ('auditRequest', 'auditCredentials') if isinstance(own, Mapping) and m in own), None)
        if carried is not None:
            return NewTaskAdmission('invalid', Rejection(_field(carried), 'requires this extension in A2A-Extensions'))
            # end if
        return NewTaskAdmission('unsupported' if required else 'ordinary')
        # end if
    if own is None:
        return NewTaskAdmission('invalid', Rejection(_field('auditRequest'), 'is required'))
    elif isinstance(own, Rejection):
        return NewTaskAdmission('invalid', own)
        # end if
    if 'auditCredentials' in own:
        return NewTaskAdmission(
            'invalid', Rejection(_field('auditCredentials'), 'replaces credentials of an existing Task only')
        )
        # end if
    if own.get('auditRequest') is None:
        return NewTaskAdmission('invalid', Rejection(_field('auditRequest'), 'is required'))
        # end if
    try:
        request = AuditRequest.model_validate(own['auditRequest'], context=WIRE)
    except ValidationError as error:
        return NewTaskAdmission('invalid', _rejection_of('auditRequest', error))
        # end try
    fit = negotiate(params, request)
    if not fit.negotiated:
        description = (
            f'the Server Agent attests at {params.level}'
            if fit.field == 'level'
            else 'the Server Agent requires countersign "host"'
        )
        return NewTaskAdmission('invalid', Rejection(_field('auditRequest', [str(fit.field)]), description))
        # end if
    use = await session_in_use(request.sessionId)
    if use is not None:
        # Another Client's Task is never named (A2A §3.3.2).
        return NewTaskAdmission(
            'invalid',
            Rejection(
                _field('auditRequest', ['sessionId']),
                'is already used for another Task',
                use.task_id if use.same_client else None,
            ),
        )
        # end if
    session = AuditSession(sessionId=request.sessionId, level=request.level, countersign=request.countersign)
    return NewTaskAdmission('negotiated', request=request, audit_session=session)
    # end def


def admit_later_request(
    *, requested_extensions: Sequence[str], metadata: object, audit_negotiated: bool
) -> LaterRequestAdmission:
    """Decide a request on an existing Task (§4.6).

    Args:
        requested_extensions: The URIs the request lists in `A2A-Extensions`.
        metadata: The request's `SendMessageRequest.metadata`.
        audit_negotiated: Whether the Task the request is on is audit-negotiated.

    Returns:
        The decision.
    """
    activated = EXTENSION_URI in requested_extensions
    own = _own(metadata)
    if own is None:
        return LaterRequestAdmission('continue', activate=activated and audit_negotiated)
    elif isinstance(own, Rejection):
        return LaterRequestAdmission('invalid', rejection=own)
        # end if
    if 'auditRequest' in own:
        return LaterRequestAdmission(
            'invalid', rejection=Rejection(_field('auditRequest'), 'negotiates a new Task only')
        )
        # end if
    if 'auditCredentials' not in own:
        return LaterRequestAdmission('continue', activate=activated and audit_negotiated)
        # end if
    if not activated or not audit_negotiated:
        description = 'the Task is not audit-negotiated' if activated else 'requires this extension in A2A-Extensions'
        return LaterRequestAdmission('invalid', rejection=Rejection(_field('auditCredentials'), description))
        # end if
    try:
        credentials = AuditCredentials.model_validate(own['auditCredentials'], context=WIRE)
    except ValidationError as error:
        return LaterRequestAdmission('invalid', rejection=_rejection_of('auditCredentials', error))
        # end try
    return LaterRequestAdmission('credentials', credentials=credentials)
    # end def


def _keyed(member: str, value: BaseModel) -> dict[str, object]:
    """`metadata` carrying `member` keyed by the extension URI (§7)."""
    return {EXTENSION_URI: {member: value.model_dump(mode='json', exclude_none=True)}}
    # end def


def audit_session_metadata(session: AuditSession) -> dict[str, object]:
    """The Task's `metadata` for an audit-negotiated Task (§7.2)."""
    return _keyed('auditSession', session)
    # end def


def audit_status_metadata(status: AuditStatus) -> dict[str, object]:
    """The held Task's status message `metadata` (§7.3)."""
    return _keyed('auditStatus', status)
    # end def


def audit_request_metadata(request: AuditRequest) -> dict[str, object]:
    """The Client's request `metadata` that negotiates a Task (§4.2, §7.1)."""
    return _keyed('auditRequest', request)
    # end def


def audit_credentials_metadata(credentials: AuditCredentials) -> dict[str, object]:
    """The Client's request `metadata` that replaces the endpoint's credentials (§5.7, §7.4)."""
    return _keyed('auditCredentials', credentials)
    # end def


def integral_json(value: object) -> object:
    """JSON with every integral double read back as an integer, which a protobuf Struct cannot tell apart (§7)."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    elif isinstance(value, Mapping):
        return {key: integral_json(item) for key, item in value.items()}
    elif isinstance(value, list):
        return [integral_json(item) for item in value]
        # end if
    return value
    # end def


def _member[T: BaseModel](metadata: object, name: str, model: type[T]) -> T | None:
    """This extension's `name` member of `metadata`, validated, or None."""
    if not isinstance(metadata, Mapping):
        return None
        # end if
    own = metadata.get(EXTENSION_URI)
    if not isinstance(own, Mapping) or name not in own:
        return None
        # end if
    try:
        return model.model_validate(integral_json(own[name]), context=WIRE)
    except ValidationError:
        return None
        # end try
    # end def


class HoldRemedy(StrEnum):
    """What the Client does about a held Task (§8.5)."""

    REPLACE_CREDENTIALS = 'replace-credentials'
    RESTORE_HOST = 'restore-host'
    DELEGATE_AGAIN = 'delegate-again'
    NOTHING_RESTORES = 'nothing-restores'
    NONE = 'none'
    INVESTIGATE_HOST = 'investigate-host'
    # end class


def hold_remedy(status: AuditStatus) -> HoldRemedy:
    """The row of §8.5's table an `auditStatus` falls in."""
    if status.reason == 'host-unavailable':
        return HoldRemedy.REPLACE_CREDENTIALS if status.httpStatus == 401 else HoldRemedy.RESTORE_HOST
    elif status.reason == 'host-rejected':
        if status.hostReason == 'unknown-key':
            return HoldRemedy.DELEGATE_AGAIN
        elif status.hostReason == 'replay-detected':
            return HoldRemedy.NOTHING_RESTORES
            # end if
        return HoldRemedy.NONE
        # end if
    return HoldRemedy.INVESTIGATE_HOST
    # end def


def read_audit_status(metadata: object) -> tuple[AuditStatus, HoldRemedy] | None:
    """The Client's reading of a held Task's status message `metadata` (§7.3), with what to do about it (§8.5)."""
    status = _member(metadata, 'auditStatus', AuditStatus)
    return None if status is None else (status, hold_remedy(status))
    # end def


def is_audited(request: AuditRequest, task_metadata: object) -> bool:
    """Whether the Task or direct Message answering an activated request carries `request`'s `auditSession` (§4.3)."""
    session = _member(task_metadata, 'auditSession', AuditSession)
    return session is not None and (session.sessionId, session.level, session.countersign) == (
        request.sessionId,
        request.level,
        request.countersign,
    )
    # end def
