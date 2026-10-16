"""The extension's computations reproduce the vendored conformance vectors."""

from typing import Any

import pytest
from auditable_mcp import WIRE, canonicalize, first_validation_error, sha256_hex

from auditable_a2a import (
    AgentCardParams,
    Countersign,
    HeldState,
    Level,
    SessionPosition,
    check_position,
    execution_report,
    key_id_of,
    negotiate,
)
from tests.conftest import load_vector


class _Request:
    """The two members of an audit request the comparison reads."""

    def __init__(self, level: str, countersign: str) -> None:
        self.level = Level(level)
        self.countersign = Countersign(countersign)
        # end def

    # end class


@pytest.mark.parametrize('vector', load_vector('negotiation.json'), ids=lambda v: v['name'])
def test_negotiation(vector: dict[str, Any]) -> None:
    params = AgentCardParams.model_validate(vector['params'], context=WIRE)
    request = _Request(vector['request']['level'], vector['request']['countersign'])
    assert negotiate(params, request).to_dict() == vector['expected']
    # end def


@pytest.mark.parametrize('vector', load_vector('key-id.json'), ids=lambda v: v['key_id'])
def test_key_id(vector: dict[str, Any]) -> None:
    assert key_id_of(vector['jwks'], vector['kid']) == vector['key_id']
    # end def


def test_key_id_refuses_a_fragment() -> None:
    with pytest.raises(ValueError, match='§10.2'):
        key_id_of('https://agent.example.com/jwks.json#x', 'k1')
        # end with
    # end def


@pytest.mark.parametrize('vector', load_vector('execution-report.json'), ids=lambda v: v['name'])
def test_execution_report(vector: dict[str, Any]) -> None:
    event = execution_report(vector['input'], vector['outcome'])
    assert event == vector['event']
    assert first_validation_error(event) is None
    assert canonicalize(event) == vector['canonical']
    assert sha256_hex(vector['canonical']) == vector['sha256']
    # end def


@pytest.mark.parametrize('vector', load_vector('position-check.json'), ids=lambda v: v['name'])
def test_position_check(vector: dict[str, Any]) -> None:
    position = SessionPosition.model_validate(vector['position'], context=WIRE)
    held = HeldState(events=vector['held']['events'], accepted_seqs=vector['held']['acceptedSeqs'])
    assert check_position(position, held).to_dict() == vector['expected']
    # end def
