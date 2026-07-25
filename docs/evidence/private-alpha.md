# CoCodex private-alpha evidence

- Evidence date: 2026-07-25
- Implementation commits: foundation `37d344d4`, recovery and trust hardening
  `72ce0f41` / `cc206faa` / `5230f979`, shared-prompt and lifecycle work
  `644a76e8` / `109503d5`, direct-connect and approval work `7e47ccb3` /
  `d730d3dd`, authoritative cancellation `bc7951cb`, and revisioned project
  context `b70f5675`.
- Branch: `feat/cocodex-foundation`
- Platform: Windows
- Status: focused private-alpha path passes; release gate remains incomplete

## Focused three-process path

Test:
`three-process CoCodex private alpha > two resident clients recover chat,
local execution, and private ciphertext across restart`

Command:

```powershell
.\node_modules\bun\bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 60000
```

Exit status: `0`

Relevant output:

```text
1 pass
0 fail
13 expect() calls
Ran 1 test across 1 file.
```

The test compiles and launches one real `cocodex-server.exe`, one resident
Stephen `cocodex-client.exe`, and one resident Kai `cocodex-client.exe` with
separate temporary state roots, workspaces, identities, account fixtures, and
a selected TLS/WSS loopback port. It records both client PIDs, force-stops and
restarts the server on the same port and state root, and asserts that the
original client PIDs reconnect.

The exercised path includes:

- invitation generation, proof-of-possession enrollment, approval, and
  reconnect without reenrollment;
- identical project discovery and authoritative chronological chat;
- signed reciprocal agent routing through each host's production local
  adapter;
- streamed result events and local usage callbacks;
- explicitly supplied, Ed25519-signed recipient key certificates,
  signed/sealed private messages, and protected fingerprint verification;
- server ciphertext-only persistence;
- durable offline chat queues, stable IDs, restart recovery, and duplicate-ID
  checks.

The current hardening suite also covers malformed-frame rejection, loopback GUI
capability/origin checks, cancellation of in-flight local execution on client
disconnect, expiry of queued/running agent tasks, and recipient-key certificate
binding. Remote agent execution now follows a host-owned policy: cryptographically
pinned trusted devices run directly by default, while hosts can select an
`always` mode that displays the complete prompt for an allow-once decision. The
same WSS path carries bounded mouse-cursor and text-caret presence, and clears
it on disconnect. Authenticated requester/host cancellation records an
authoritative final task event and aborts the host process. `cocodex-server init` attempts the Windows Firewall rule and prints
the single-port manual router-forwarding instructions when automatic setup is
unavailable. Initialization now performs a bounded UPnP discovery and
`AddPortMapping` attempt; if no gateway responds or the mapping fails, the JSON
result explains that manual forwarding or CGNAT troubleshooting is required.

The separate server CLI now also exposes `status`, `stop`, `restart`, `migrate`,
`backup`, and `restore`. Backups are signed by the server's Ed25519 identity,
include a SHA-256 database checksum, and are rejected if tampered with or
presented to a different server identity. The lifecycle test exercises status
and graceful stop against the real TLS server process.

Files:

- `tests/cocodex-private-alpha-process.test.ts`
- `tests/fixtures/codex-runtime-fixture.ts`
- `src/cocodex/session.ts`
- `src/cocodex/agent-bridge.ts`
- `src/cocodex/agent-journal.ts`
- `src/cocodex/outbox.ts`
- `apps/cocodex-server/src/server.ts`

The deterministic runtime fixture is evidence for process isolation,
production adapter invocation, routing, streaming, local workspace
side-effects, and per-client usage attribution. It is not evidence that two
distinct real OpenAI accounts were billed.

## Focused CoCodex suite and builds

Command:

```powershell
.\node_modules\bun\bin\bun.exe run test:cocodex
.\node_modules\bun\bin\bun.exe run lint:gui
.\node_modules\bun\bin\bun.exe run build:gui
.\node_modules\bun\bin\bun.exe run build:cocodex-server
.\node_modules\bun\bin\bun.exe run build:cocodex-client
```

Exit status: `0`

Relevant output:

```text
41 pass
0 fail
301 expect() calls
Ran 41 tests across 21 files.
dist/cocodex-server.exe compiled
dist/cocodex-client.exe compiled
GUI production build completed
```

The GUI lint reported one pre-existing hook dependency warning and no errors.
The production GUI build reported a bundle-size warning and completed.

The server transfer slice is covered by signed encrypted export/import: the
transfer file uses an AES-256-GCM envelope derived from a user passphrase,
binds the database to the server identity and current epoch, and rejects wrong
passphrases. Passphrases are supplied through a protected file or the
`COCODEX_TRANSFER_PASSPHRASE` environment variable rather than process
arguments. `transfer-import` restores a verified snapshot and advances the
persisted epoch. The server exposes that epoch through `/v1/server-info`,
enrollment, and `auth.ok`; clients persist the highest authenticated epoch and
reject a stale server. The real WSS collaboration suite also publishes and
lists a project artifact, then routes a reciprocal agent request whose signed
dependency names the completed prior task.

Additional successful gates:

```text
bun run typecheck                    exit 0
bun run typecheck:cocodex            exit 0
privacy scan with bundled Git        exit 0: Privacy scan passed
anthropic-image-retry-e2e.test.ts     exit 0: 3 pass, 0 fail
```

Private-message replay protection is covered by the server shared-state tests:
the same ciphertext cannot be accepted again under a different message ID,
while approved-device checks continue to gate both sender and recipient.

## Revisioned shared project context

Commit: `b70f5675`

Command:

```powershell
.\node_modules\bun\bin\bun.exe test --max-concurrency=1 `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\apps\cocodex-server\tests\shared-state.test.ts `
  .\apps\cocodex-server\tests\collaboration-server.test.ts `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\tests\cocodex-outbox.test.ts
```

Exit status: `0`

Relevant output:

```text
19 pass
0 fail
111 expect() calls
Ran 19 tests across 5 files.
```

This run proves migration v8, default and revision-one Final Goal/context
state, stale-writer rejection, membership enforcement, strict protocol and
serialized-size bounds, real authenticated WSS get/update/broadcast, context
recovery after a server restart, offline outbox replay, and removal of a
non-retryable stale update so it cannot block later events. The server routes
context broadcasts to clients that explicitly requested that project's context;
chat subscription alone is not treated as context authorization.

The post-change rerun of the full three-process harness was attempted with:

```powershell
.\node_modules\bun\bin\bun.exe test --timeout 60000 `
  .\tests\cocodex-private-alpha-process.test.ts
```

It exited `124` after the outer 120-second command timeout without test output
and left no live CoCodex process. This is recorded as an incomplete rerun, not
as evidence of a private-alpha pass; the previously recorded isolated
three-process result above remains the last successful process-harness result.

Automatic direct hosting now attempts UPnP first and NAT-PMP as a bounded UDP
fallback; packet encoding/response validation and diagnostic classification are
covered by the port-mapping tests. PCP remains a later compatibility extension.

## Official Codex runtime smoke

Runtime discovered from the installed Codex desktop application:

```text
codex.exe 0.146.0-alpha.3.1
source: app
```

Command shape:

```powershell
"Reply with exactly: COCODEX_OFFICIAL_RUNTIME_OK" |
  codex.exe -C . exec --json --ephemeral --sandbox read-only -
```

Exit status: `0`

Relevant sanitized output:

```json
{"type":"item.completed","item":{"type":"agent_message","text":"COCODEX_OFFICIAL_RUNTIME_OK"}}
{"type":"turn.completed","usage":{"input_tokens":16034,"cached_input_tokens":8960,"output_tokens":11,"reasoning_output_tokens":0}}
```

This proves that the installed official runtime can authenticate, execute, and
return real usage on Stephen's current local account. A second independently
authenticated Kai account was not available in this environment, so mandatory
claims 15 and 18 are not fully evidenced with two real accounts.

## Incomplete release gate

The complete inherited `bun test` run does not pass reliably under full Windows
load. The final run exited `1` after approximately 672 seconds while progress
stopped around `anthropic-image-retry-e2e.test.ts`; that exact test file then
passed independently (`3 pass`, `0 fail`). The pristine upstream baseline had
already shown load-sensitive duplicated timeout failures, but the required
"all existing tests pass" gate is still not green and must not be represented
as complete.

The following also remain deferred or insufficiently evidenced:

- two separately authenticated real Stephen and Kai Codex accounts;
- complete cross-PC transfer orchestration for installing the transferred server
  identity/endpoint, reconnecting both clients, and retiring the old authority;
- a dedicated 501-event network recovery test for both chat and private
  message pagination;
- NAT-PMP/PCP, robust CGNAT detection, relay, libp2p,
  forward-secret ratcheted messaging, multi-device messaging, and revocation
  UI. The current GUI/server path includes a bounded Yjs shared-prompt
  document, but it does not yet provide a full Hocuspocus deployment or
  network pagination-gap UX.

Accordingly, the connected deterministic private-alpha path works, but this
report does not authorize a production or complete-private-alpha release claim.
