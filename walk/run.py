"""Drive a Client, its audit host, and a Server Agent as separate processes, and check what the ledger holds.

Each party is this SDK's or the TypeScript SDK's, over HTTPS at Level 2 with countersignatures, and both SDKs'
verifiers check the ledger.

    python -m walk.run                 # every case, every pairing of Client, audit host, and Server Agent
    python -m walk.run resume          # the cases whose name contains `resume`

`WALK_PAIRS=py-py-ts,ts-py-py` runs only those pairings (Client-host-agent). `WALK_TS_REPO` points at another
checkout of the TypeScript SDK; by default it is the sibling one.
"""

from __future__ import annotations

import base64
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx
from a2a.client import ClientCallContext, ClientConfig, ClientFactory
from a2a.client.service_parameters import ServiceParametersFactory, with_a2a_extensions
from a2a.types import AgentCard, InvalidParamsError, Message, Part, Role, SendMessageRequest, Task, TaskState
from a2a.utils.signing import SignatureVerificationError, create_signature_verifier
from auditable_mcp import SealedRecord
from auditable_mcp.l2 import CountersignatureRegistryVerifier
from auditable_mcp.l2.algorithms import KeyRole
from google.protobuf import json_format
from jwt import PyJWK

from auditable_a2a import (
    EXTENSION_URI,
    AuditRequest,
    EndCause,
    SessionAnomaly,
    SessionEnd,
    SessionEvidence,
    registry_from_jwks,
    verify_a2a_ledger,
)
from auditable_a2a.a2a import metadata_of, read_rejection, send_audited
from walk.common import URL_LINE

ROOT = Path(__file__).resolve().parents[1]
TS_REPO = Path(os.environ.get('WALK_TS_REPO') or ROOT.parent / 'auditable-a2a-sdk-ts')
STARTUP_BOUND = 30.0
TABLE_READ = 'db.read'


def _certificates(directory: Path) -> dict[str, str]:
    """A certificate authority and a certificate for 127.0.0.1 it signed, as strict TLS clients accept them."""

    def run(*args: str) -> None:
        subprocess.run(['openssl', *args], cwd=directory, check=True, capture_output=True)
        # end def

    run(
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '2',
        '-keyout',
        'ca.key',
        '-out',
        'ca.pem',
        '-subj',
        '/CN=walk ca',
        '-addext',
        'basicConstraints=critical,CA:TRUE',
        '-addext',
        'keyUsage=critical,keyCertSign,cRLSign',
    )
    run(
        'req',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-keyout',
        'key.pem',
        '-out',
        'leaf.csr',
        '-subj',
        '/CN=127.0.0.1',
    )
    (directory / 'leaf.ext').write_text(
        'subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n'
        'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
    )
    run(
        'x509',
        '-req',
        '-in',
        'leaf.csr',
        '-CA',
        'ca.pem',
        '-CAkey',
        'ca.key',
        '-CAcreateserial',
        '-out',
        'cert.pem',
        '-days',
        '2',
        '-extfile',
        'leaf.ext',
    )
    return {
        'WALK_CA': str(directory / 'ca.pem'),
        'WALK_TLS_CERT': str(directory / 'cert.pem'),
        'WALK_TLS_KEY': str(directory / 'key.pem'),
        'NODE_EXTRA_CA_CERTS': str(directory / 'ca.pem'),
    }
    # end def


@dataclass
class Party:
    """A walk process and the URL it announced."""

    process: subprocess.Popen[str]
    url: str
    lines: list[str]

    def wait_for(self, prefix: str, bound: float = STARTUP_BOUND) -> str:
        """The rest of the first stdout line starting with `prefix`."""
        for line in self.lines:
            if line.startswith(prefix):
                return line[len(prefix) :]
                # end if
            # end for
        deadline = time.monotonic() + bound
        stdout = self.process.stdout
        assert stdout is not None
        while time.monotonic() < deadline:
            ready, _, _ = select.select([stdout], [], [], 0.1)
            if ready:
                line = stdout.readline().strip()
                if line == '' and self.process.poll() is not None:
                    break
                    # end if
                self.lines.append(line)
                if line.startswith(prefix):
                    return line[len(prefix) :]
                    # end if
                # end if
            # end while
        raise RuntimeError(f'no {prefix} line within {bound}s; exit {self.process.poll()}, saw {self.lines}')
        # end def

    def kill(self) -> None:
        """Kill the process at once, as a crash does: its whole group, as `npx` runs the TypeScript one as a child."""
        os.killpg(self.process.pid, signal.SIGKILL)
        self.process.wait(timeout=10)
        # end def

    # end class


def _start(language: str, role: str, env: dict[str, str]) -> Party:
    """Start `role` (`audit_host` or `agent`) in `language` (`py` or `ts`), and wait for its URL."""
    if language == 'py':
        command, cwd = [sys.executable, '-m', f'walk.{role}'], ROOT
    else:
        command, cwd = ['npx', 'tsx', f'walk/{role.replace("_", "-")}.ts'], TS_REPO
        # end if
    process = subprocess.Popen(
        command, cwd=cwd, env={**os.environ, **env}, stdout=subprocess.PIPE, text=True, start_new_session=True
    )
    party = Party(process, '', [])
    party.url = party.wait_for(URL_LINE)
    return party
    # end def


@dataclass(frozen=True)
class Delegation:
    """What the Client got for a delegation, the same from either SDK's Client."""

    state: str | None = None
    """The Task's state as A2A names it, or `message` for a direct Message."""
    audited: bool = False
    task_id: str | None = None
    rejected_field: str | None = None
    """The field a §4.4 refusal named, when the request was refused."""
    audit_status: dict[str, Any] | None = None
    """The `auditStatus` of a held Task's status message (§7.3)."""
    context_id: str | None = None
    # end class


@dataclass
class World:
    """One pairing: the audit host, the Server Agent, and the Client - its HTTPS client, and its language."""

    host: Party
    agent: Party
    host_language: str
    agent_language: str
    client_language: str
    env: dict[str, str]
    http: httpx.AsyncClient
    a2a_log: list[dict[str, Any]] = field(default_factory=list)
    """The Python Client's A2A requests and responses, for the end-to-end example (§16)."""

    async def card(self) -> dict[str, Any]:
        """The Server Agent's Agent Card, after verifying its signature, as Level 2 requires (§3.1, §5.1)."""
        card = (await self.http.get(f'{self.agent.url}/.well-known/agent-card.json')).json()
        signatures = card.get('signatures') or []
        assert signatures, 'the Agent Card is not signed'
        header = json.loads(_b64url(signatures[0]['protected']))
        jwks = (await self.http.get(header['jku'])).json()
        keys = {jwk['kid']: jwk for jwk in jwks['keys']}

        def key_provider(kid: str | None, jku: str | None) -> PyJWK:
            return PyJWK.from_dict(keys[str(kid)])
            # end def

        parsed = json_format.ParseDict(card, AgentCard(), ignore_unknown_fields=True)
        create_signature_verifier(key_provider, ['EdDSA'])(parsed)
        return card  # type: ignore[no-any-return]
        # end def

    async def open(self, *, countersign: str = 'host') -> AuditRequest:
        """Ask the audit host for a session for the Server Agent, as the Client does before it delegates (§5.1)."""
        card = await self.card()
        extension = next(e for e in card['capabilities']['extensions'] if e['uri'] == EXTENSION_URI)
        attestation_keys = extension['params']['attestationKeys']
        snapshot = (await self.http.get(attestation_keys)).json()
        expires_at = (datetime.now(UTC) + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        opened = (
            await self.http.post(
                f'{self.host.url}/admin/sessions',
                json={
                    'delegate': f'{self.agent.url}/.well-known/agent-card.json',
                    'expiresAt': expires_at,
                    'attestationKeys': attestation_keys,
                    'keySnapshot': snapshot,
                },
            )
        ).json()
        return AuditRequest.model_validate(
            {
                'auditEndpoint': {'url': f'{self.host.url}/a2a', 'authentication': opened['authentication']},
                'sessionId': opened['sessionId'],
                'level': 'L2',
                'countersign': countersign,
                **({'hostKeys': opened['hostKeys']} if countersign == 'host' else {}),
                'expiresAt': expires_at,
            }
        )
        # end def

    async def delegate(self, request: AuditRequest, text: str = 'Count them.') -> Delegation:
        """Delegate one Task to the Server Agent with this extension (§4.2), from this pairing's Client."""
        if self.client_language == 'ts':
            return _delegate_in_typescript(self.agent.url, request, text, self.env)
            # end if
        client = await ClientFactory(ClientConfig(httpx_client=self.http, streaming=False)).create_from_url(
            self.agent.url
        )
        message = Message(message_id=str(uuid.uuid4()), role=Role.ROLE_USER, parts=[Part(text=text)])
        try:
            result, audited = await send_audited(client, SendMessageRequest(message=message), request)
        except InvalidParamsError as error:
            rejection = read_rejection(error)
            assert rejection is not None, error
            return Delegation(rejected_field=rejection.field)
            # end try
        if isinstance(result, Task):
            return Delegation(
                TaskState.Name(result.status.state),
                audited,
                result.id,
                None,
                _audit_status_of(result),
                result.context_id,
            )
            # end if
        return Delegation('message', audited)
        # end def

    async def follow_up(self, task_id: str, context_id: str, text: str) -> Delegation:
        """Send a later message on a Task, listing this extension, from the Python Client (§4.6, §8.5)."""
        client = await ClientFactory(ClientConfig(httpx_client=self.http, streaming=False)).create_from_url(
            self.agent.url
        )
        message = Message(
            message_id=str(uuid.uuid4()),
            task_id=task_id,
            context_id=context_id,
            role=Role.ROLE_USER,
            parts=[Part(text=text)],
        )
        context = ClientCallContext(
            service_parameters=ServiceParametersFactory.create([with_a2a_extensions([EXTENSION_URI])])
        )
        result = None
        async for response in client.send_message(SendMessageRequest(message=message), context=context):
            result = response.task if response.HasField('task') else result
            # end async for
        assert result is not None, 'no Task in answer to the later message'
        return Delegation(TaskState.Name(result.status.state), task_id=result.id, audit_status=_audit_status_of(result))
        # end def

    async def refuse_attempts(self, action_type: str | None) -> None:
        """Make the audit host answer attempts of one kind `503`, or stop."""
        await self.http.post(f'{self.host.url}/admin/attempts', json={'refuse': action_type})
        # end def

    async def exchanges(self) -> list[dict[str, Any]]:
        """Every submission the audit host received, and its answer."""
        return (await self.http.get(f'{self.host.url}/admin/exchanges')).json()['exchanges']  # type: ignore[no-any-return]
        # end def

    async def ledger(self) -> dict[str, Any]:
        """The audit host's records and sessions."""
        return (await self.http.get(f'{self.host.url}/admin/ledger')).json()  # type: ignore[no-any-return]
        # end def

    async def refuse_outcomes(self, refuse: bool) -> None:
        """Make the audit host answer outcomes `503`, or stop."""
        await self.http.post(f'{self.host.url}/admin/outcomes', json={'refuse': refuse})
        # end def

    def restart_agent(self, state: Path) -> None:
        """Kill the Server Agent and start it again on the same port and state, resuming (§5.5)."""
        port = self.agent.url.rsplit(':', 1)[1]
        self.agent.kill()
        env = {**self.env, 'WALK_STATE_DIR': str(state), 'WALK_PORT': port, 'WALK_RESUME': '1'}
        self.agent = _start(self.agent_language, 'agent', env)
        # end def

    # end class


def _audit_status_of(task: Task) -> dict[str, Any] | None:
    """The `auditStatus` of a Task's status message, if it is held (§7.3)."""
    own = metadata_of(task.status.message.metadata).get(EXTENSION_URI) if task.status.HasField('message') else None
    return own.get('auditStatus') if isinstance(own, dict) else None
    # end def


def _delegate_in_typescript(agent_url: str, request: AuditRequest, text: str, env: dict[str, str]) -> Delegation:
    """Delegate from the TypeScript SDK's Client, which verifies the Agent Card itself too."""
    done = subprocess.run(
        ['npx', 'tsx', 'walk/client.ts'],
        cwd=TS_REPO,
        input=json.dumps({'agentUrl': agent_url, 'auditRequest': request.to_wire(), 'text': text}),
        capture_output=True,
        text=True,
        env={**os.environ, **env},
    )
    if done.returncode != 0:
        raise RuntimeError(f'walk/client.ts failed: {done.stderr[-2000:]}')
        # end if
    answer = json.loads(done.stdout)
    if 'rejected' in answer:
        return Delegation(rejected_field=answer['rejected']['field'])
        # end if
    return Delegation(
        answer['state'], answer['audited'], answer['taskId'], None, answer.get('auditStatus'), answer.get('contextId')
    )
    # end def


def _b64url(text: str) -> bytes:
    """Decode unpadded base64url."""
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    # end def


def _verify_in_python(ledger: dict[str, Any]) -> dict[str, Any]:
    """This SDK's verifier over the ledger (§11)."""
    records = [SealedRecord.from_dict(record) for record in ledger['records']]
    sessions = [
        SessionEvidence(
            session_id=s['sessionId'],
            level=s['level'],
            version=s.get('version'),
            countersign=s.get('countersign'),
            attestation_keys=s.get('attestationKeys'),
            key_snapshot=s.get('keySnapshot'),
            bound_key_id=s.get('boundKeyId'),
            end=None
            if 'end' not in s
            else SessionEnd(EndCause(s['end']['cause']), s['end']['at'], s['end']['lastSeq']),
            anomalies=[SessionAnomaly(a['id'], a['kind'], a['detail']) for a in s['anomalies']],
        )
        for s in ledger['sessions']
    ]
    checker = CountersignatureRegistryVerifier(
        registry_from_jwks(ledger['hostKeys'], ledger['hostKeySnapshot'], KeyRole.HOST)
    ).check
    report = verify_a2a_ledger(records, sessions, countersignature_checker=checker)
    return {'complete': report.complete, 'findings': [f.code for f in report.findings], 'unchecked': report.unchecked}
    # end def


def _verify_in_typescript(ledger: dict[str, Any]) -> dict[str, Any]:
    """The TypeScript SDK's verifier over the same ledger."""
    done = subprocess.run(
        ['npx', 'tsx', 'walk/verify.ts'], cwd=TS_REPO, input=json.dumps(ledger), capture_output=True, text=True
    )
    if done.returncode != 0:
        raise RuntimeError(f'walk/verify.ts failed: {done.stderr}')
        # end if
    return json.loads(done.stdout)  # type: ignore[no-any-return]
    # end def


async def _verified(world: World, request: AuditRequest) -> dict[str, Any]:
    """The ledger, with the host keys, after both verifiers found it complete."""
    ledger = await world.ledger()
    ledger['hostKeys'] = str(request.hostKeys)
    ledger['hostKeySnapshot'] = (await world.http.get(str(request.hostKeys))).json()
    for name, report in (('python', _verify_in_python(ledger)), ('typescript', _verify_in_typescript(ledger))):
        assert report['complete'], f'{name} verifier: {report}'
        # end for
    return ledger
    # end def


def _outcomes(ledger: dict[str, Any], session_id: str) -> list[tuple[str, str]]:
    """The (action_type, outcome) of every record of the session, in order."""
    return [
        (r['event']['action_type'], r['event']['outcome'])
        for r in ledger['records']
        if r['event']['session_id'] == session_id
    ]
    # end def


async def case_negotiated(world: World, state: Path) -> None:
    """A delegated Task records its access in the Client's ledger before it, and closes its session."""
    request = await world.open()
    result = await world.delegate(request)
    assert result.audited, 'the Task does not carry the auditSession of the request'
    assert result.state == 'TASK_STATE_COMPLETED', result
    ledger = await _verified(world, request)
    assert _outcomes(ledger, request.sessionId) == [(TABLE_READ, 'attempted'), (TABLE_READ, 'success')]
    session = next(s for s in ledger['sessions'] if s['sessionId'] == request.sessionId)
    assert session['end']['cause'] == 'close', session
    # end def


async def case_rejected(world: World, state: Path) -> None:
    """A request the Server Agent cannot negotiate is refused at the field, and nothing is recorded (§4.4)."""
    request = await world.open(countersign='none')
    result = await world.delegate(request)
    assert result.rejected_field == f'metadata[{json.dumps(EXTENSION_URI)}].auditRequest.countersign', result
    assert _outcomes(await world.ledger(), request.sessionId) == []
    # end def


async def case_resume(world: World, state: Path) -> None:
    """A Server Agent killed with an outcome owed delivers it after its restart, once, and closes (§5.5)."""
    request = await world.open()
    await world.refuse_outcomes(True)
    result = await world.delegate(request)
    assert result.audited, result
    assert result.state == 'TASK_STATE_AUTH_REQUIRED', result
    await world.refuse_outcomes(False)
    world.restart_agent(state)
    resumed = world.agent.wait_for('WALK_RESUMED=')
    assert resumed == f'{result.task_id} continue closed', resumed
    ledger = await _verified(world, request)
    assert _outcomes(ledger, request.sessionId) == [(TABLE_READ, 'attempted'), (TABLE_READ, 'success')]
    session = next(s for s in ledger['sessions'] if s['sessionId'] == request.sessionId)
    assert session['end']['cause'] == 'close', session
    # end def


RECONCILE = 'Reconcile the September settlement report against the ledger.'


async def case_example(world: World, state: Path) -> None:
    """The end-to-end example (§16): a Task held while its audit host cannot record, and taken up again."""
    request = await world.open()
    await world.refuse_attempts('report.fetch')
    held = await world.delegate(request, RECONCILE)
    assert held.audited, held
    assert held.state == 'TASK_STATE_AUTH_REQUIRED', held
    assert held.audit_status is not None, held
    assert held.audit_status['reason'] == 'host-unavailable' and held.audit_status['httpStatus'] == 503, held
    assert held.task_id is not None and held.context_id is not None
    # The Client restores its audit host (§8.5), and says so on the Task, which prompts the resend.
    await world.refuse_attempts(None)
    done = await world.follow_up(held.task_id, held.context_id, 'The audit host is restored.')
    assert done.state == 'TASK_STATE_COMPLETED', done
    ledger = await _verified(world, request)
    assert _outcomes(ledger, request.sessionId) == [
        ('ledger.read', 'attempted'),
        ('ledger.read', 'success'),
        ('report.fetch', 'aborted'),
        ('report.fetch', 'attempted'),
        ('report.fetch', 'success'),
    ], _outcomes(ledger, request.sessionId)
    session = next(s for s in ledger['sessions'] if s['sessionId'] == request.sessionId)
    assert session['end']['cause'] == 'close', session
    out = os.environ.get('WALK_EXAMPLE_OUT')
    if out and world.client_language == 'py':
        transcript = {
            'pairing': {'client': 'py', 'host': world.host_language, 'agent': world.agent_language},
            'a2a': world.a2a_log,
            'audit': await world.exchanges(),
            'ledger': ledger,
            'verification': {'python': _verify_in_python(ledger), 'typescript': _verify_in_typescript(ledger)},
        }
        Path(out).write_text(json.dumps(_redacted(transcript, request), indent=2, ensure_ascii=False) + '\n')
        # end if
    # end def


def _redacted(value: Any, request: AuditRequest) -> Any:
    """The transcript with the endpoint's credentials replaced, as an example shows none (§13.2)."""
    secret = request.auditEndpoint.authentication.credentials
    text = json.dumps(value, ensure_ascii=False).replace(secret, '<credential>')
    return json.loads(text)
    # end def


CASES: dict[str, Callable[[World, Path], Awaitable[None]]] = {
    'negotiated': case_negotiated,
    'rejected': case_rejected,
    'resume': case_resume,
    'example': case_example,
}
PAIRINGS = [(client, host, agent) for client in ('py', 'ts') for host in ('py', 'ts') for agent in ('py', 'ts')]
SELECTED_PAIRS = os.environ.get('WALK_PAIRS', '')


def _recorder(log: list[dict[str, Any]]) -> Callable[[httpx.Response], Awaitable[None]]:
    """An httpx hook that keeps each A2A JSON-RPC call to the Server Agent: request, response, and the extensions."""

    async def record(response: httpx.Response) -> None:
        if response.request.method != 'POST' or '/admin/' in response.request.url.path:
            return
            # end if
        await response.aread()
        log.append(
            {
                'request': {
                    'A2A-Extensions': response.request.headers.get('a2a-extensions'),
                    'body': json.loads(response.request.content),
                },
                'response': {
                    'A2A-Extensions': response.headers.get('a2a-extensions'),
                    'body': response.json(),
                },
            }
        )
        # end def

    return record
    # end def


async def _run(
    case: Callable[[World, Path], Awaitable[None]], client: str, host: str, agent: str, tls: dict[str, str]
) -> None:
    """One case on one pairing, in fresh processes and a fresh state directory."""
    state = Path(tempfile.mkdtemp(prefix='walk-agent-'))
    host_party = _start(host, 'audit_host', tls)
    agent_party = _start(agent, 'agent', {**tls, 'WALK_STATE_DIR': str(state)})
    try:
        log: list[dict[str, Any]] = []
        hooks = {'request': [], 'response': [_recorder(log)]}
        async with httpx.AsyncClient(verify=tls['WALK_CA'], timeout=20, event_hooks=hooks) as http:
            world = World(host_party, agent_party, host, agent, client, tls, http, log)
            await case(world, state)
            agent_party = world.agent
            # end async with
    finally:
        for party in (host_party, agent_party):
            try:
                party.kill()
            except ProcessLookupError:
                pass
                # end try
                # end if
            # end for
        shutil.rmtree(state, ignore_errors=True)
        # end try
    # end def


async def main(selected: str) -> int:
    """Run every selected case on every pairing; return the number that failed."""
    certificates = Path(tempfile.mkdtemp(prefix='walk-tls-'))
    tls = _certificates(certificates)
    failed = 0
    try:
        for name, case in CASES.items():
            if selected not in name:
                continue
                # end if
            for client, host, agent in PAIRINGS:
                if SELECTED_PAIRS and f'{client}-{host}-{agent}' not in SELECTED_PAIRS.split(','):
                    continue
                    # end if
                label = f'{name} client={client} host={host} agent={agent}'
                try:
                    await _run(case, client, host, agent, tls)
                except (AssertionError, RuntimeError, httpx.HTTPError, SignatureVerificationError) as error:
                    failed += 1
                    sys.stdout.write(f'FAIL {label}: {error}\n')
                else:
                    sys.stdout.write(f'ok   {label}\n')
                    # end try
                sys.stdout.flush()
                # end for
            # end for
    finally:
        shutil.rmtree(certificates, ignore_errors=True)
        # end try
    return failed
    # end def


if __name__ == '__main__':
    sys.exit(1 if anyio.run(main, sys.argv[1] if len(sys.argv) > 1 else '') else 0)
    # end if
