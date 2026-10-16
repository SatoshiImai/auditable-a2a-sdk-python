"""The pydantic models give the same verdict as the vendored JSON Schemas on every one-member mutation of a sample."""

from typing import Any

import pytest
from auditable_mcp import WIRE
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from auditable_a2a import (
    AgentCardParams,
    AuditCredentials,
    AuditRequest,
    AuditSession,
    AuditStatus,
    AuditSubmission,
    SessionPosition,
)
from tests.conftest import load_schema

_SESSION = '0199a3e0-7c1f-7a4e-9b1d-5f2f7e0c4a11'
_WRONG: list[object] = [
    '',
    'X',
    'http://a.example',
    'https://a.example',
    'https://a.example/k#f',
    'a\r\nb',
    'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA',
    '00000000-0000-0000-0000-000000000000',
    '2026-02-30T00:00:00Z',
    '2026-10-15T00:00:00+09:00',
    -1,
    99,
    600,
    1.5,
    0,
    True,
    False,
    None,
    {},
    [],
    'L1',
    'L2',
    'host',
    'none',
    'host-unavailable',
    'unknown-key',
]


def _mutations(base: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the sample, the sample with an extra member, and every one-member mutation of it."""
    out: list[dict[str, Any]] = [base, {**base, 'extra': 1}]
    for key in base:
        out.append({k: v for k, v in base.items() if k != key})
        for value in _WRONG:
            out.append({**base, key: value})
            # end for
        # end for
    return out
    # end def


_ENDPOINT = {'url': 'https://a.example', 'authentication': {'scheme': 'Bearer', 'credentials': 'c'}, 'token': 't'}
_REQUEST = {
    'auditEndpoint': _ENDPOINT,
    'sessionId': _SESSION,
    'level': 'L2',
    'countersign': 'host',
    'hostKeys': 'https://a.example/k',
    'expiresAt': '2026-11-15T00:00:00Z',
}
_LAST = {
    'seq': 1,
    'host_ts': '2026-10-15T00:00:00Z',
    'previous_hash': '0' * 64,
    'record_hash': '1' * 64,
    'log_id': 'l',
    'host_signature': 'c2ln',
    'host_key_id': 'h',
}

_CASES: list[tuple[str, type[BaseModel], list[dict[str, Any]]]] = [
    (
        'agent-card-params.schema.json',
        AgentCardParams,
        _mutations({'level': 'L2', 'countersign': 'host', 'selfChain': True, 'attestationKeys': 'https://a.example/j'}),
    ),
    (
        'audit-request.schema.json',
        AuditRequest,
        [*_mutations(_REQUEST), *({**_REQUEST, 'auditEndpoint': e} for e in _mutations(_ENDPOINT))],
    ),
    (
        'audit-session.schema.json',
        AuditSession,
        _mutations({'sessionId': _SESSION, 'level': 'L1', 'countersign': 'none'}),
    ),
    (
        'audit-status.schema.json',
        AuditStatus,
        _mutations({'reason': 'host-rejected', 'hostReason': 'unknown-key', 'httpStatus': 401, 'attemptId': _SESSION}),
    ),
    (
        'audit-credentials.schema.json',
        AuditCredentials,
        _mutations({'authentication': {'scheme': 'Bearer', 'credentials': 'c'}, 'token': 't'}),
    ),
    (
        'audit-submission.schema.json',
        AuditSubmission,
        [
            *_mutations({'taskId': 't', 'token': 'x', 'event': {}}),
            *_mutations({'taskId': 't', 'position': True}),
            *_mutations({'taskId': 't', 'close': True}),
        ],
    ),
    (
        'session-position.schema.json',
        SessionPosition,
        [*_mutations({'last': _LAST}), *({'last': p} for p in _mutations(_LAST)), {'last': None}],
    ),
]


def _model_accepts(model: type[BaseModel], sample: dict[str, Any]) -> bool:
    """Return whether the model accepts the sample as it arrives on the wire (JSON mode)."""
    try:
        model.model_validate(sample, context=WIRE)
    except ValidationError:
        return False
        # end try
    return True
    # end def


@pytest.mark.parametrize(('file', 'model', 'samples'), _CASES, ids=[c[0] for c in _CASES])
def test_models_agree_with_the_schemas(file: str, model: type[BaseModel], samples: list[dict[str, Any]]) -> None:
    validator = Draft202012Validator(load_schema(file))
    disagreements = [s for s in samples if _model_accepts(model, s) != validator.is_valid(s)]
    assert disagreements == []
    # end def
