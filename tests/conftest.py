"""Shared fixtures: the vendored spec schemas and conformance vectors."""

import json
from pathlib import Path
from typing import Any

_SPEC_DIR = Path(__file__).resolve().parents[1] / 'spec'


def load_vector(name: str) -> Any:
    """Read and parse one vendored conformance vector file."""
    return json.loads((_SPEC_DIR / 'vectors' / name).read_text(encoding='utf-8'))
    # end def


def load_schema(name: str) -> Any:
    """Read and parse one vendored JSON Schema."""
    return json.loads((_SPEC_DIR / 'schema' / name).read_text(encoding='utf-8'))
    # end def
