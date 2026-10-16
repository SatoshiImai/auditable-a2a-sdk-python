"""The decisions on the A2A messages (§3, §4, §7), on plain JSON."""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from auditable_a2a.admission import (
    HoldRemedy,
    Rejection,
    SessionUse,
    admit_later_request,
    admit_new_task,
    agent_card_extension,
    audit_credentials_metadata,
    audit_request_metadata,
    audit_session_metadata,
    audit_status_metadata,
    is_audited,
    read_audit_status,
)
from auditable_a2a.models import (
    EXTENSION_URI,
    AgentCardParams,
    AuditCredentials,
    AuditRequest,
    AuditSession,
    AuditStatus,
    AuthenticationInfo,
    Countersign,
    Level,
)

_REQUEST = AuditRequest.model_validate(
    {
        'auditEndpoint': {
            'url': 'https://audit.client.example/a2a',
            'authentication': {'scheme': 'Bearer', 'credentials': 't'},
        },
        'sessionId': '0199a3e0-7c1f-7a4e-9b1d-5f2f7e0c4a11',
        'level': 'L2',
        'countersign': 'host',
        'hostKeys': 'https://audit.client.example/keys.json',
        'expiresAt': '2026-11-15T00:00:00Z',
    }
)
_PARAMS = AgentCardParams.model_validate(
    {'level': 'L2', 'countersign': 'host', 'attestationKeys': 'https://agent.example/jwks.json'}
)
_FIELD = f'metadata[{json.dumps(EXTENSION_URI)}]'


async def _unused(session_id: str) -> SessionUse | None:
    """No `sessionId` is in use."""
    return None
    # end def


async def _admit(**overrides: Any) -> Any:
    """`admit_new_task` with the defaults of these cases."""
    arguments: dict[str, Any] = {
        'required': False,
        'params': _PARAMS,
        'requested_extensions': [EXTENSION_URI],
        'metadata': audit_request_metadata(_REQUEST),
        'session_in_use': _unused,
        **overrides,
    }
    return await admit_new_task(**arguments)
    # end def


def test_the_agent_card_declares_the_uri_the_posture_and_validated_params() -> None:
    assert agent_card_extension(_PARAMS, required=True) == {
        'uri': EXTENSION_URI,
        'required': True,
        'params': {'level': 'L2', 'countersign': 'host', 'attestationKeys': 'https://agent.example/jwks.json'},
    }
    with pytest.raises(ValidationError):
        agent_card_extension({'level': 'L2', 'countersign': 'none'}, required=False)
        # end with
    # end def


class TestNewTask:
    """§4.3 - §4.5."""

    async def test_negotiates_and_gives_the_audit_session(self) -> None:
        admission = await _admit()
        assert admission.kind == 'negotiated'
        assert admission.request == _REQUEST
        assert admission.audit_session == AuditSession(
            sessionId=_REQUEST.sessionId, level=Level.L2, countersign=Countersign.HOST
        )
        # end def

    async def test_serves_unactivated_as_ordinary_or_refuses_under_the_mandatory_posture(self) -> None:
        assert (await _admit(requested_extensions=['https://other.example/ext'], metadata={})).kind == 'ordinary'
        assert (await _admit(requested_extensions=[], metadata={}, required=True)).kind == 'unsupported'
        # end def

    async def test_rejects_an_audit_request_whose_activation_was_lost_on_the_way(self) -> None:
        """§4.4."""
        assert (await _admit(requested_extensions=[])).rejection == Rejection(
            f'{_FIELD}.auditRequest', 'requires this extension in A2A-Extensions'
        )
        # end def

    async def test_rejects_an_activated_request_without_an_audit_request(self) -> None:
        assert (await _admit(metadata={})).rejection == Rejection(f'{_FIELD}.auditRequest', 'is required')
        assert (await _admit(metadata={EXTENSION_URI: 'x'})).rejection.field == _FIELD
        # end def

    async def test_rejects_a_schema_invalid_audit_request_at_the_field(self) -> None:
        wire = _REQUEST.to_wire() | {'expiresAt': '2026-11-15'}
        admission = await _admit(metadata={EXTENSION_URI: {'auditRequest': wire}})
        assert admission.rejection.field == f'{_FIELD}.auditRequest.expiresAt'
        # end def

    async def test_rejects_a_level_or_countersign_the_declaration_does_not_meet(self) -> None:
        l1 = AgentCardParams.model_validate({'level': 'L1', 'countersign': 'none'})
        assert (await _admit(params=l1)).rejection.field == f'{_FIELD}.auditRequest.level'
        uncountersigned = _REQUEST.model_copy(update={'countersign': Countersign.NONE, 'hostKeys': None})
        admission = await _admit(metadata=audit_request_metadata(uncountersigned))
        assert admission.rejection.field == f'{_FIELD}.auditRequest.countersign'
        # end def

    async def test_names_the_task_of_a_reused_session_id_to_the_same_client_only(self) -> None:
        async def same(session_id: str) -> SessionUse | None:
            return SessionUse('task-9', same_client=True)
            # end def

        async def other(session_id: str) -> SessionUse | None:
            return SessionUse('task-9', same_client=False)
            # end def

        assert (await _admit(session_in_use=same)).rejection == Rejection(
            f'{_FIELD}.auditRequest.sessionId',
            'is already used for another Task',
            'task-9',
        )
        refused = await _admit(session_in_use=other)
        assert refused.kind == 'invalid'
        assert 'task-9' not in repr(refused)
        # end def

    async def test_rejects_audit_credentials_on_a_request_that_creates_a_task(self) -> None:
        metadata = {
            EXTENSION_URI: {
                'auditRequest': _REQUEST.to_wire(),
                'auditCredentials': {'authentication': {'scheme': 'Bearer', 'credentials': 'u'}},
            }
        }
        assert (await _admit(metadata=metadata)).rejection.field == f'{_FIELD}.auditCredentials'
        # end def

    # end class


class TestLaterRequest:
    """§4.6."""

    _CREDENTIALS = AuditCredentials.model_validate({'authentication': {'scheme': 'Bearer', 'credentials': 'u'}})

    def test_continues_listing_the_uri_only_for_an_activated_audit_negotiated_task(self) -> None:
        on = admit_later_request(requested_extensions=[EXTENSION_URI], metadata=None, audit_negotiated=True)
        off = admit_later_request(requested_extensions=[], metadata=None, audit_negotiated=True)
        assert (on.kind, on.activate, off.activate) == ('continue', True, False)
        # end def

    def test_rejects_an_audit_request(self) -> None:
        admission = admit_later_request(
            requested_extensions=[EXTENSION_URI], metadata=audit_request_metadata(_REQUEST), audit_negotiated=True
        )
        assert admission.rejection is not None and admission.rejection.field == f'{_FIELD}.auditRequest'
        # end def

    def test_takes_audit_credentials_only_when_activated_on_an_audit_negotiated_task(self) -> None:
        metadata = audit_credentials_metadata(self._CREDENTIALS)
        taken = admit_later_request(requested_extensions=[EXTENSION_URI], metadata=metadata, audit_negotiated=True)
        assert (taken.kind, taken.credentials) == ('credentials', self._CREDENTIALS)
        assert admit_later_request(requested_extensions=[], metadata=metadata, audit_negotiated=True).kind == 'invalid'
        refused = admit_later_request(requested_extensions=[EXTENSION_URI], metadata=metadata, audit_negotiated=False)
        assert refused.kind == 'invalid'
        control = {EXTENSION_URI: {'auditCredentials': {'authentication': {'scheme': 'Bearer', 'credentials': 'a\nb'}}}}
        bad = admit_later_request(requested_extensions=[EXTENSION_URI], metadata=control, audit_negotiated=True)
        assert bad.rejection is not None
        assert bad.rejection.field == f'{_FIELD}.auditCredentials.authentication.credentials'
        # end def

    # end class


class TestClientReading:
    """§4.3, §7.3, §8.5."""

    def test_takes_a_task_as_audited_only_with_an_audit_session_matching_the_request(self) -> None:
        session = AuditSession(sessionId=_REQUEST.sessionId, level=Level.L2, countersign=Countersign.HOST)
        metadata = audit_session_metadata(session)
        assert is_audited(_REQUEST, metadata)
        assert not is_audited(_REQUEST, {})
        assert not is_audited(_REQUEST.model_copy(update={'level': Level.L1}), metadata)
        other = audit_session_metadata(session.model_copy(update={'sessionId': '0199a3e0-7c1f-7a4e-9b1d-5f2f7e0c4a12'}))
        assert not is_audited(_REQUEST, other)
        # end def

    def test_reads_a_hold_and_the_row_of_section_8_5(self) -> None:
        def remedy(status: dict[str, object]) -> HoldRemedy | None:
            read = read_audit_status(audit_status_metadata(AuditStatus.model_validate(status)))
            return None if read is None else read[1]
            # end def

        assert remedy({'reason': 'host-unavailable', 'httpStatus': 401}) == HoldRemedy.REPLACE_CREDENTIALS
        assert remedy({'reason': 'host-unavailable'}) == HoldRemedy.RESTORE_HOST
        assert remedy({'reason': 'host-rejected', 'hostReason': 'unknown-key'}) == HoldRemedy.DELEGATE_AGAIN
        assert remedy({'reason': 'host-rejected', 'hostReason': 'replay-detected'}) == HoldRemedy.NOTHING_RESTORES
        assert remedy({'reason': 'host-rejected', 'hostReason': 'signature-invalid'}) == HoldRemedy.NONE
        assert remedy({'reason': 'hash-mismatch'}) == HoldRemedy.INVESTIGATE_HOST
        assert read_audit_status({}) is None
        # end def

    def test_reads_an_http_status_carried_as_a_struct_double(self) -> None:
        metadata = {EXTENSION_URI: {'auditStatus': {'reason': 'host-unavailable', 'httpStatus': 401.0}}}
        read = read_audit_status(metadata)
        assert read is not None and read[1] == HoldRemedy.REPLACE_CREDENTIALS
        # end def

    # end class


def test_the_endpoint_credentials_are_what_an_authorization_header_carries() -> None:
    """§6.1."""
    AuthenticationInfo.model_validate({'scheme': 'Bearer', 'credentials': 'a b'})
    for bad in ({'scheme': 'Bear er', 'credentials': 'abc'}, {'scheme': 'Bearer', 'credentials': 'ä'}):
        with pytest.raises(ValidationError):
            AuthenticationInfo.model_validate(bad)
            # end with
        # end for
    # end def


def test_expires_at_requires_seconds_as_rfc_3339_does() -> None:
    """§7.1, a-MCP §4."""
    request = {
        'auditEndpoint': {
            'url': 'https://audit.example/a2a',
            'authentication': {'scheme': 'Bearer', 'credentials': 'a'},
        },
        'sessionId': '0199a3e1-0000-7000-8000-000000000001',
        'level': 'L1',
        'countersign': 'none',
        'expiresAt': '2026-11-15T00:00:00Z',
    }
    AuditRequest.model_validate(request)
    with pytest.raises(ValidationError):
        AuditRequest.model_validate({**request, 'expiresAt': '2026-11-15T00:00Z'})
        # end with
    # end def
