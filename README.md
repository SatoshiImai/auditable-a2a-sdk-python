# Auditable A2A SDK (Python)

A protocol machine for [Auditable A2A](https://github.com/SatoshiImai/auditable-a2a) (`auditable-a2a/0.1`), the
[A2A](https://a2a-protocol.org/) extension under which **no act a Server Agent records on a Client's behalf proceeds
unless it was first recorded in the Client's audit ledger**. It gives each party its part: the Client's audit host
that seals the records, the Server Agent that records before it acts, the Client that delegates and reads the
answer, and the verifier that checks the Client's ledger.

It builds on [`auditable-mcp-sdk`](https://github.com/SatoshiImai/auditable-mcp-sdk-python), whose event,
canonicalization, ledger, signatures, and verifier it uses unchanged, and binds to the official
[A2A Python SDK](https://github.com/a2aproject/a2a-python) (`a2a-sdk`). It is the Python counterpart of the
[TypeScript SDK](https://github.com/SatoshiImai/auditable-a2a-sdk-ts) and shares its vendored schemas and vectors, so
both reproduce the same bytes, and each one's parties work with the other's.

**The specification is the source of truth.** For what is on the wire, when a Task is held, and what a verifier
reports, read [`spec/auditable-a2a.md`](https://github.com/SatoshiImai/auditable-a2a/blob/master/spec/auditable-a2a.md);
this SDK implements it, and section numbers below (§) are its.

## Scope

What this SDK does:

- **The audit host** (§5, §6): `A2aAuditHost` wraps the Auditable MCP host for a session as long as a Task. It keeps
  what §5.1 asks of each session, binds the session to a Task and a key, takes the end from a message and still
  seals outcomes and execution reports after it, survives its own restart through a `SessionStore` (§5.6), and
  rotates credentials (§5.7). `create_audit_endpoint_handler` serves it as an ASGI app.
- **The Server Agent** (§6, §8): `AuditedTask` records each access before it over the HTTPS binding - one submission
  at a time, a bounded wait, no redirects, outcomes owed until acknowledged - with Polluted Stop at both levels and
  countersignatures verified against the host's key snapshot. It gives the `auditStatus` of a hold, sends execution
  reports, and says whether the Task may end.
- **Resumption** (§5.5): given a `SelfLedger`, its own ledger, `AuditedTask` writes ahead what §5.5 lists, and
  `resume_task` restores the Task from that ledger alone after a restart, without performing any access again.
- **The decisions on the A2A messages** (§3, §4, §7), on plain JSON: the Agent Card declaration, whether a request
  is audit-negotiated, ordinary, or rejected at a named field, `auditCredentials`, the extension's `metadata`, and
  what a Client does about a hold (§8.5).
- **The binding to the official A2A SDK** (`auditable_a2a.a2a`): a request handler that decides each request before
  the SDK takes it, an executor that places `auditSession` in every Task, the middleware that lists the activated
  extension in the response, and a Client's delegation.
- **The verifier** (§11): a-MCP's verification of the partition, with each Level-2 record checked against its own
  session's key snapshot, and this extension's checks per session.

What it does not do (your concern, behind interfaces):

- No storage backend. `SessionStore` and `LedgerRepository` are protocols; in-memory implementations are included
  for tests.
- No HTTP client in the core. `AuditedTask` takes an injected `Post`; `auditable_a2a.httpx_post` builds one on httpx.
- No agent logic, and no in-process private keys in production: sign through a KMS or HSM, as
  `auditable-mcp-sdk` provides.

## Status

Alpha, tracking `auditable-a2a/0.1`. The public API is unstable while the specification is a draft.

## Compatibility

| | Version |
| :-- | :-- |
| Auditable A2A | `auditable-a2a/0.1` |
| A2A Protocol | [v1.0.0](https://a2a-protocol.org/v1.0.0/specification/) |
| Auditable MCP | `auditable-mcp/0.4`, through `auditable-mcp-sdk` 0.4 |
| `a2a-sdk` (the `a2a` extra) | 1.2.x |
| Python | 3.12+ |

| A2A binding | Client | Server Agent |
| :-- | :--: | :--: |
| **JSON-RPC** | ✅ | ✅ |
| **HTTP+JSON/REST** | not yet tested | not yet tested |
| **gRPC** | not yet tested | not yet tested |

The extension's `metadata` is the same JSON object on every binding (§7), and the request handler and executor this
SDK wraps are the ones the SDK serves every binding with. The tests and the walk run over JSON-RPC.

## Install

Releases are published as tags of this repository, not to PyPI:

```bash
pip install 'auditable-a2a-sdk @ git+https://github.com/SatoshiImai/auditable-a2a-sdk-python.git@v0.1.1'            # the core
pip install 'auditable-a2a-sdk[http] @ git+https://github.com/SatoshiImai/auditable-a2a-sdk-python.git@v0.1.1'      # with httpx
pip install 'auditable-a2a-sdk[a2a] @ git+https://github.com/SatoshiImai/auditable-a2a-sdk-python.git@v0.1.1'       # with a2a-sdk
```

It depends on [`auditable-mcp-sdk`](https://github.com/SatoshiImai/auditable-mcp-sdk-python) `v0.4.0`, which pip installs
from its tag.

| Module | Contents | Extra |
| :-- | :-- | :-- |
| `auditable_a2a` | The core: the audit host, `AuditedTask`, resumption, the decisions on the A2A messages, the verifier. Imports no A2A SDK and no HTTP client. | - |
| `auditable_a2a.endpoint_handler` | The audit endpoint as an ASGI app. | - |
| `auditable_a2a.httpx_post` | A `Post` on httpx. | `http` |
| `auditable_a2a.a2a` | The binding to `a2a-sdk`. | `a2a` |

## Concepts

- **Audit session.** The Client's audit host opens one per delegation and issues its `sessionId` and the endpoint's
  credentials (§5.1). The first attempt binds it to the Task and, under Level 2, to the Server Agent's key. It lasts
  as long as the Task, through restarts of either side (§5.2).
- **Write-ahead.** Before each access it records, the Server Agent sends an attempt and acts only on an accept it
  has verified (§8.1, §8.3). `async with task.action(...)` does both: entering raises `AmcpAbortedError` before the
  body runs when the access cannot be recorded, and leaving sends the outcome - `success`, or `failed` if the body
  raised.
- **A hold, not a failure.** An access that cannot be recorded is not performed, and the Task is held in
  `TASK_STATE_AUTH_REQUIRED` with an `auditStatus` (§8.4). `task.status_of(error)` gives it, and `hold_remedy`
  tells the Client which row of §8.5 it is in.
- **The answer is in the Task.** A Client takes an answer as audited only when its Task, or direct `Message`,
  carries an `auditSession` matching its `auditRequest` (§4.3). Its assurance is its own ledger.
- **Levels and countersignatures.** Level 1 is self-reporting; Level 2 adds the Server Agent's signature and a
  per-session sequence. A countersigning audit host signs every record it seals. These are a-MCP's, unchanged.

## Quickstart

### 1. The audit host

```python
from auditable_mcp import InMemoryLedgerRepository
from auditable_mcp.l2 import Ed25519Countersigner, generate_tool_key

from auditable_a2a import A2aAuditHost, Countersign, InMemorySessionStore, Level
from auditable_a2a.endpoint_handler import create_audit_endpoint_handler

host_key = generate_tool_key('https://audit.client.example/keys.json#h1')
host = A2aAuditHost.create(
    'client-a',
    Level.L2,
    Countersign.HOST,
    store=InMemorySessionStore(),  # implement SessionStore over your store (§5.6)
    repository=InMemoryLedgerRepository(),  # and LedgerRepository for the ledger itself
    countersigner=Ed25519Countersigner(host_key.key_id, host_key.private_key),
)

# Before delegating: one session per delegation, with the delegate's key snapshot (§5.1).
session_id, authentication = await host.open_session(
    delegate='https://agent.example/.well-known/agent-card.json',
    expires_at='2026-11-15T00:00:00Z',
    attestation_keys='https://agent.example/.well-known/jwks.json',
    key_snapshot=delegate_jwks,  # fetched after verifying the delegate's Agent Card signature
    host_keys='https://audit.client.example/keys.json',
)

# The audit endpoint (§6), as an ASGI app.
app = create_audit_endpoint_handler(host)
```

`A2aAuditHost.resume(...)` brings the host back after a restart, with every session that has not ended open again
(§5.6). A `SessionStore` implements `put`, `all`, and `delete`; `put` must be durable before it returns, and raise
`SessionStoreError` when it is not, since the host stores a change before it acts on it.

Each session is opened for one version of this extension (§4.1), `version` in `open_session`, defaulting to the one
this SDK implements, and the host records it. A Client that lists several versions of the URI puts an `auditRequest`
under each, with a session of each. Call `host.sweep()` periodically to end the sessions whose expiry has passed and
that receive nothing more (§5.3), and `host.purge(session_id)` to forget an ended one under your retention policy;
its records stay in the ledger.

The Client places the session in its request as the `auditRequest` (§7.1); the issued credential goes in as it is:

```python
from auditable_a2a import AuditEndpoint, AuditRequest

audit_request = AuditRequest(
    auditEndpoint=AuditEndpoint(url='https://audit.client.example/a2a', authentication=authentication),
    sessionId=session_id,
    level=Level.L2,
    countersign=Countersign.HOST,
    hostKeys='https://audit.client.example/keys.json',
    expiresAt='2026-11-15T00:00:00Z',
)
```

### 2. The Server Agent: record, then act

```python
from auditable_mcp import AmcpAbortedError
from auditable_mcp.l2 import Ed25519Signer

from auditable_a2a import AuditedTask
from auditable_a2a.httpx_post import httpx_fetch_host_keys, httpx_post

task = AuditedTask(
    task_id=task_id,
    request=request,  # the validated auditRequest the Task was negotiated with
    post=httpx_post(http),
    signer=Ed25519Signer.from_tool_key(agent_key),  # Level 2
    host_key_snapshot=host_key_snapshot,  # fetched from request.hostKeys, under countersign: "host"
    fetch_host_keys=httpx_fetch_host_keys(http),  # and how to fetch it again when the host rotates its keys
)

try:
    async with task.action(
        'ledger.read',
        {'kind': 'ledger', 'ref': 'general-ledger/2026-09'},
        mutates=False,
        egress=False,
        disclose={'period': '2026-09'},
    ):
        await read_the_ledger()
except AmcpAbortedError as error:
    # Not recorded, so not performed: hold the Task with this as its auditStatus (§7.3, §8.4).
    audit_status = task.status_of(error)

# Nothing in flight and every outcome acknowledged: close, then move the Task to its terminal state (§5.4).
if await task.finish():
    ...  # TASK_STATE_COMPLETED
```

The outcome is `success` when the body completes and `failed` when it raises. An access after the session's expiry raises `SessionExpiredError` without sending anything; the Task is not continued
(§5.3).

`task.may_end()` is true when nothing is outstanding: no attempt on its way, no accept without its outcome or an
execution report, no outcome unacknowledged. `task.may_end(bound)` states that one of §5.4's bounds has passed - a
cancel, the hold's timeout, the expiry, a decision not to resume, a revoked key - and the Task may end with records
still outstanding; the method takes the caller's word for it. While an outcome cannot be delivered,
`task.held_status()` gives the `auditStatus` of the hold, of the earliest one owed.

Under `countersign: "host"`, an accept or a position that names a `kid` the snapshot does not hold fetches
`request.hostKeys` again (§10.2) through `fetch_host_keys`, which such a Task requires; `httpx_fetch_host_keys` in
`auditable_a2a.httpx_post` is one. A fetch that fails is a failure to record, and the access is not performed.

`disclose` records context in the clear; `commit_salted` commits to it by its salted hash instead, for what the
Client may see only that it was there (§10.3). An access the Server Agent decides not to perform, or cannot say it
performed, is stated with an execution report (§8.6):

```python
await task.report_execution(attempt_id, 'not-performed')
```

A transition, a question or an answer is a record that is not an access (§8.1). `task.record(...)` sends it with
`mutates` and `egress` both `false` and waits for the accept on entering, so nothing goes past what it describes
before the record is made. It ends `success` however its body ends, and a resumption completes an accepted one with
`success` rather than reporting on it:

```python
async with task.record('agent.step', {'kind': 'task', 'ref': task_id}, commit_salted={'plan': plan}):
    pass
```

### 3. Resuming after a restart

Give the Task its own ledger and it writes ahead what §5.5 lists. The `LedgerRepository` behind a `SelfLedger` must
commit each append durably before it returns: resumption trusts an entry as written, and the audit host's position
reveals only what it received, not an entry the Server Agent's own storage lost (§5.5). After a restart, `resume_task` restores it from
that ledger alone: it resends what was not acknowledged, checks the audit host's last position, and resolves every
accept it holds without performing any again.

```python
from auditable_a2a import (
    AuditedTask,
    ResumeClosed,
    ResumeContinue,
    ResumeDelivered,
    ResumeFailed,
    ResumeHeld,
    SelfLedger,
    resume_task,
)

task = AuditedTask(
    task_id=task_id,
    request=request,
    post=post,
    signer=signer,
    host_key_snapshot=host_key_snapshot,
    fetch_host_keys=fetch_host_keys,
    self_ledger=await SelfLedger.open(own, task_id),
)

# After a restart:
resumed = await resume_task(
    self_ledger=await SelfLedger.open(own, task_id),
    credentials=credentials,  # an AuditCredentials, kept as a secret and never in the ledger (§13.2)
    post=post,
    signer=signer,
    fetch_host_keys=fetch_host_keys,
)
match resumed:
    case ResumeContinue(task=task, not_performed=again):
        ...  # carry on with task; what `again` names may be attempted again
    case ResumeDelivered() | ResumeClosed():
        ...  # the Task was already terminal, or its close is in the ledger: complete the move to the terminal state
    case ResumeHeld(status=status):
        ...  # hold the Task with status, and resume again later
    case ResumeFailed():
        ...  # TASK_STATE_FAILED
```

`resume_task` raises `SelfLedgerError` when an entry cannot be written while resuming; nothing it would have preceded
was done, and resuming again repeats no step whose effect the ledger holds.

### 4. On the official A2A SDK

```python
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentExtension
from starlette.applications import Starlette

from auditable_a2a import AgentCardParams, agent_card_extension
from auditable_a2a.a2a import (
    ActivationContextBuilder,
    ActivationMiddleware,
    AuditContext,
    AuditedExecutor,
    AuditedRequestHandler,
    held_for_audit,
)

params = AgentCardParams.model_validate(
    {'level': 'L2', 'countersign': 'host', 'selfChain': True, 'attestationKeys': attestation_keys}
)
declaration = agent_card_extension(params, required=True)  # the Agent Card entry (§3)
card = AgentCard(
    # ...
    capabilities=AgentCapabilities(
        extensions=[AgentExtension(uri=str(declaration['uri']), required=True, params=declaration['params'])],
    ),
)


class Agent:
    async def execute(self, context, event_queue, audit: AuditContext | None) -> None:
        # audit is None for an ordinary request; audit.request is there on the one that created the Task.
        # Record each access with an AuditedTask, and enqueue held_for_audit(...) when one cannot be recorded.
        ...

    async def cancel(self, context, event_queue) -> None: ...


handler = AuditedRequestHandler(
    required=True,
    params=params,
    session_in_use=session_in_use,  # look up and reserve the sessionId in one step (§4.3)
    on_credentials=on_credentials,  # hand them to the running AuditedTask (§5.7)
    agent_executor=AuditedExecutor(Agent()),
    task_store=InMemoryTaskStore(),
    agent_card=card,
)
app = ActivationMiddleware(
    Starlette(
        routes=[
            *create_agent_card_routes(card),
            *create_jsonrpc_routes(handler, '/', context_builder=ActivationContextBuilder()),
        ]
    )
)
```

`AuditedRequestHandler` decides each request before the SDK takes it - an executor that raises still leaves a
stored failed Task, and a rejected request must create none (§4.4). The SDK has no notion of an activated extension,
so `ActivationMiddleware` and `ActivationContextBuilder` carry it and list this extension's URI in the response.
Under `required=True` it refuses every request that does not list the URI, not only the first (§4.6). A later
request on an audited Task reaches the executor with that Task's audit even when it does not list the URI.
`AuditedExecutor` places `auditSession` in every Task the executor enqueues, and in a direct `Message`.

`session_in_use` must look up and reserve the `sessionId` in one atomic step - a conditional write in your Task
store, or the requests that carry one serialized: two requests that both read "unused" would bind one session to two
Tasks. When the executor answers without creating a Task, discard the `auditRequest`'s credentials with that answer
(§13.2).

On the Client:

```python
from a2a.types import InvalidParamsError, SendMessageRequest

from auditable_a2a.a2a import read_rejection, send_audited

try:
    result, audited = await send_audited(client, SendMessageRequest(message=message), audit_request)
    if not audited:
        ...  # not audited (§4.3)
except InvalidParamsError as error:
    rejection = read_rejection(error)  # §4.4: the field, and the Task a reused sessionId belongs to
```

`read_audit_status(metadata_of(task.status.message.metadata))` reads a hold and the remedy §8.5 gives for it.

### 5. Verifying the Client's ledger

```python
from auditable_a2a import verify_a2a_ledger

report = verify_a2a_ledger(
    await repository.read_all('client-a'), sessions, countersignature_checker=countersignature_checker
)
report.complete  # a-MCP's verification and this extension's checks, with nothing left unchecked
report.findings  # each with the Tier-1 code a consumer that knows only a-MCP reads it as
report.records_after_close  # records the host sealed after a session's close: listed, not findings (§11)
report.unchecked  # what could not be checked: a session of a version not implemented, an input missing
```

Pass the sessions as the audit host stores them (`SessionState`), or as `SessionEvidence`: each is read by the
rules of the version it was opened for, and whether its records must be countersigned comes from its own
`countersign`. A session of a version this verifier does not implement is reported as unchecked, not as a
finding.

### Notes

- `a2a-sdk` carries `metadata` as a `google.protobuf.Struct`, whose numbers are doubles: `httpStatus` arrives as
  `503.0`. `metadata_of` returns a Struct as JSON with integral numbers as integers; read the extension's `metadata`
  through it.
- A request carrying this extension's `auditRequest` or `auditCredentials` without listing the URI is rejected: the
  activation was lost on the way, and serving it would act outside the Client's ledger (§4.4).
- The SDK's client does not show a rejection's details beyond A2A's `ErrorInfo` `metadata` (`INVALID_PARAMS`,
  `a2a-protocol.org`), which is where `read_rejection` finds them (§4.4). The SDK's gRPC transport does not carry that
  `metadata`, so over gRPC a Client learns only that the request was refused.

## The walk

The suite runs every party in one process. `make walk` runs the Client, the audit host, and the Server Agent as
**separate processes** over HTTPS under a certificate authority it makes, each this SDK's or the
[TypeScript SDK's](https://github.com/SatoshiImai/auditable-a2a-sdk-ts) checked out beside this one, on the official
A2A SDK of its language. Every case runs on every pairing of the three, at Level 2 with countersignatures and with
signed Agent Cards, and both SDKs' verifiers check every ledger it produces.

| Case | What the Client's ledger shows |
| :-- | :-- |
| `negotiated` | The access recorded before it, and the session closed. |
| `rejected` | Nothing: a request the Server Agent cannot negotiate is refused at the field (§4.4). |
| `resume` | A Server Agent killed with an outcome owed delivers it once after its restart, and closes (§5.5). |
| `example` | The specification's end-to-end example (§16): a Task held while its audit host cannot record, and resumed. |

```bash
make walk                                   # every case, every pairing
make walk CASE=resume                       # the cases whose name contains `resume`
WALK_PAIRS=py-ts-py make walk               # one pairing: Client, audit host, Server Agent
```

With `WALK_EXAMPLE_OUT=<file>` and the Python Client, the `example` case writes what each party exchanged and the
ledger with both verifiers' verdicts; §16 quotes one such capture.

## Conformance

The normative JSON Schema and conformance vectors are vendored under
[`spec/`](https://github.com/SatoshiImai/auditable-a2a-sdk-python/tree/master/spec) from the
[specification repository](https://github.com/SatoshiImai/auditable-a2a), byte-identical to the TypeScript SDK's
copy. A conforming implementation reproduces every vector.

```bash
make spec/check    # fail if the vendored spec drifted from its source
make test          # includes the conformance vectors
```

## Development

```bash
make env/init      # create the virtualenv and install the project, its extras, and the dev tools
make test          # pytest
make lint          # ruff check + ruff format --check + mypy
```

## Note on AI Assistance

The core architecture, design decisions, and core implementations in this project are entirely my own. I used AI tools (Claude, Gemini) strictly under my explicit direction for code generation, text formatting, edge-case verification, and polishing my English prose. All outputs were heavily reviewed, corrected, and finalized by me.

## License

Apache-2.0 (c) Satoshi Imai
