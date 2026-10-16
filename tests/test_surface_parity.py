"""This SDK and the TypeScript SDK export the same public surface, apart from the differences listed here.

The TypeScript SDK is read from a sibling checkout; without it the tests skip.
"""

import re
from pathlib import Path
from typing import Final

import pytest

import auditable_a2a
import auditable_a2a.a2a

_TS_SRC: Final = Path(__file__).resolve().parents[2] / 'auditable-a2a-sdk-ts' / 'src'
_TS_INDEX: Final = _TS_SRC / 'index.ts'
_TS_A2A: Final = _TS_SRC / 'a2a' / 'index.ts'

# Every name one SDK exports and the other does not, and why.
_ONLY_IN_PYTHON: Final[dict[str, str]] = {
    '__version__': 'package metadata; the TypeScript SDK reads it from package.json',
    'AbortReason': 'a Literal type for the pydantic field; TypeScript derives it from `ABORT_REASONS`',
    'HostReason': 'a Literal type for the pydantic field; TypeScript derives it from `HOST_REASONS`',
    'AuditEndpoint': 'the nested pydantic model of `auditRequest.auditEndpoint`; Zod nests it inline',
    'Declaration': 'the Protocol `negotiate` reads; TypeScript takes a `Pick` of the two types',
    'SessionEnd': 'the dataclass of `SessionState.end`; TypeScript types it inline',
    'DEFAULT_TIMEOUT_SECONDS': 'the POST bound in seconds; TypeScript bounds it in milliseconds',
    'Post': 'the injected HTTP POST; TypeScript injects the platform `fetch`',
    'Journal': "the own ledger's write, as `AuditEndpointClient` takes it; TypeScript types the option inline",
    'ResumeContinue': 'one state of `ResumeResult`; TypeScript writes the union of object types inline',
    'ResumeDelivered': 'one state of `ResumeResult`; TypeScript writes the union of object types inline',
    'ResumeClosed': 'one state of `ResumeResult`; TypeScript writes the union of object types inline',
    'ResumeHeld': 'one state of `ResumeResult`; TypeScript writes the union of object types inline',
    'ResumeFailed': 'one state of `ResumeResult`; TypeScript writes the union of object types inline',
    'ResumeState': "the type of `ResumeResult.state`; TypeScript reads it as `ResumeResult['state']`",
    'TrackedAction': 'what `AuditedTask.action` returns, entered with `async with`; TypeScript awaits the action',
    'SessionStoreError': 'the exception a `SessionStore` raises; TypeScript catches whatever `put` throws',
}
_ONLY_IN_TYPESCRIPT: Final[dict[str, str]] = {
    'VERSION': 'the package version; Python exposes it as `__version__`',
    'agent_card_params_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_credentials_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_request_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_session_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_status_schema': 'a Zod schema; Python validates through the pydantic model',
    'audit_submission_schema': 'a Zod schema; Python validates through the pydantic model',
    'authentication_info_schema': 'a Zod schema; Python validates through the pydantic model',
    'sealed_position_schema': 'a Zod schema; Python validates through the pydantic model',
    'session_position_schema': 'a Zod schema; Python validates through the pydantic model',
    'A2aAuditHostOptions': 'an options object; Python takes keyword arguments',
    'AuditEndpointHandlerOptions': 'an options object; Python takes keyword arguments',
    'OpenSessionInput': 'an options object; Python takes keyword arguments',
    'AuditedTaskOptions': 'an options object; Python takes keyword arguments',
    'AuditEndpointClientOptions': 'an options object; Python takes keyword arguments',
    'DEFAULT_TIMEOUT_MS': 'the POST bound in milliseconds; Python bounds it in seconds',
    'VerifyA2aOptions': 'an options object; Python takes keyword arguments',
    'ResumeOptions': 'an options object; Python takes keyword arguments',
    'NewTaskInput': 'an options object; Python takes keyword arguments',
    'LaterRequestInput': 'an options object; Python takes keyword arguments',
    'AgentExtensionDeclaration': "the declaration's type; Python returns the JSON object",
    'JournaledRequest': "the session entry's request type; Python keeps the entry a JSON object",
    'fetch_host_keys_with': 'a fetcher over the platform `fetch`; Python has no HTTP client in its core, and '
    '`httpx_fetch_host_keys` is in the `http` extra',
    'HostKeySet': 'the JWK Set type; Python takes a `Mapping`',
}


def _typescript_exports(entry: Path = _TS_INDEX) -> set[str]:
    """Read the names a TypeScript entry point exports, in this SDK's spelling."""
    names: set[str] = set()
    text = entry.read_text('utf-8')
    for declared in re.findall(r'^export\s+(?:async\s+)?(?:function|const|class|interface|type)\s+(\w+)', text, re.M):
        names.add(declared if declared[:1].isupper() else re.sub(r'(?<!^)(?=[A-Z])', '_', declared).lower())
        # end for
    for block in re.findall(r'export\s+(?:type\s+)?\{([^}]*)\}', text):
        for item in block.split(','):
            name = re.sub(r'^type\s+', '', item.strip()).split(' as ')[-1].strip()
            if name:
                names.add(name if name[:1].isupper() else re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower())
                # end if
            # end for
        # end for
    return names
    # end def


@pytest.mark.skipif(not _TS_INDEX.is_file(), reason='the TypeScript SDK is not checked out beside this one')
def test_the_two_ports_export_the_same_surface() -> None:
    """Any name one SDK has and the other lacks is either explained above or a defect."""
    python = set(auditable_a2a.__all__)
    typescript = _typescript_exports()
    assert sorted(python - typescript - set(_ONLY_IN_PYTHON)) == []
    assert sorted(typescript - python - set(_ONLY_IN_TYPESCRIPT)) == []
    # end def


@pytest.mark.skipif(not _TS_INDEX.is_file(), reason='the TypeScript SDK is not checked out beside this one')
def test_every_explained_difference_is_still_a_difference() -> None:
    """An explanation for a gap that has closed would hide the next real gap."""
    python = set(auditable_a2a.__all__)
    typescript = _typescript_exports()
    assert sorted(name for name in _ONLY_IN_PYTHON if name in typescript or name not in python) == []
    assert sorted(name for name in _ONLY_IN_TYPESCRIPT if name in python or name not in typescript) == []
    # end def


# The binding to each language's official A2A SDK: the same roles, each in its SDK's idiom.
_A2A_ONLY_IN_PYTHON: Final[dict[str, str]] = {
    'ActivationMiddleware': 'a2a-sdk has no activated extensions; the JS SDK echoes them itself',
    'ActivationContextBuilder': "hands ActivationMiddleware's set to the call context; not needed in JS",
    'activated_extensions': "the call's activation set; JS has ServerCallContext.addActivatedExtension",
    'metadata_of': "a Struct's numbers are doubles; JS metadata is plain JSON",
    'AuditedRequestHandler': "a subclass of the SDK's handler; JS wraps the handler interface",
    'AuditedExecutor': 'an AgentExecutor subclass; JS returns one from auditedExecutor',
}
_A2A_ONLY_IN_TYPESCRIPT: Final[dict[str, str]] = {
    'audited_request_handler': 'a function wrapping the handler interface; Python subclasses the handler',
    'AuditedRequestHandlerOptions': 'an options object; Python takes keyword arguments',
    'audited_executor': 'a function returning an AgentExecutor; Python has the AuditedExecutor class',
}


@pytest.mark.skipif(not _TS_A2A.is_file(), reason='the TypeScript SDK is not checked out beside this one')
def test_the_two_bindings_to_the_official_sdks_export_the_same_surface() -> None:
    """Any name one binding has and the other lacks is either explained above or a defect."""
    python = set(auditable_a2a.a2a.__all__)
    typescript = _typescript_exports(_TS_A2A)
    assert sorted(python - typescript - set(_A2A_ONLY_IN_PYTHON)) == []
    assert sorted(typescript - python - set(_A2A_ONLY_IN_TYPESCRIPT)) == []
    assert sorted(name for name in _A2A_ONLY_IN_PYTHON if name in typescript or name not in python) == []
    assert sorted(name for name in _A2A_ONLY_IN_TYPESCRIPT if name in python or name not in typescript) == []
    # end def
