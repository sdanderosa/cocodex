# CoCodex private-alpha evidence

- Evidence date: 2026-07-25
- Implementation commits: foundation `37d344d4`, recovery and trust hardening
  `72ce0f41` / `cc206faa` / `5230f979`, shared-prompt and lifecycle work
  `644a76e8` / `109503d5`, direct-connect and approval work `7e47ccb3` /
  `d730d3dd`, authoritative cancellation `bc7951cb`, and revisioned project
  context `b70f5675`, client Final Goal/docs `7010d6ec`, and signed usage
  reports `b2c124f9`, encrypted project chat/key lifecycle `02d24e16`,
  encrypted shared prompt updates `2be9f7d0` / teardown hardening `e15cc537`,
  private-message hardening `63b552a6`, and PCP direct-hosting fallback
  `943388d4`, encrypted-project restart recovery `92d98950`, and Windows
  lifecycle timeout hardening `0f09345f`, encrypted project artifacts
  `ba32d995`, and keyed encrypted-agent prompts/results `3259c21f`, with the
  authoritative roster and revocation-safe key hardening in `7942452f`, and
  atomic project-key initialization in `f80dc082`, followed by durable key
  recovery and offline-recipient replay hardening in `f58490be`, with atomic
  local key-store persistence in `90f03548`, and local full-computer safety
  controls in `b07923db`.
- authenticated prompt presence and lifecycle hardening `203dc406`, with
  evidence `0cd1ec49` and client/server guidance `48f8aef3`; protocol, stale
  presence, and disconnected-UI hardening `76647c34`.
- Branch: `feat/cocodex-foundation`
- Platform: Windows
- Status: focused private-alpha path passes; release gate remains incomplete

## Latest authoritative agent-roster and encryption-hardening slice

This recovery checkpoint adds a bounded, server-derived named-agent roster and
status card plus revocation-safe project-key rotation. It is committed in
`7942452f`, based on durable `HEAD` `917f29b8` (`docs: record presence
hardening evidence`).

Focused command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\apps\cocodex-server\tests\collaboration-server.test.ts `
  .\tests\cocodex-gui-bridge.test.ts
```

Exit status: `0`

Relevant output:

```text
24 pass
0 fail
192 expect() calls
Ran 24 tests across 4 files.
```

The server's `agent.list.result` frame is strict and project-scoped. It joins
approved host devices to registered agents, derives readiness from authenticated
`agent.ready` sockets, and derives active/queued/terminal state from persisted
tasks. The GUI refreshes the roster while connected and hides it after a
disconnect. The slice does not claim persistent activity history, task editing,
co-agent graphs, full computer/browser helpers, or privileged execution.

The same focused run covers `agent.task.list.result`: task status,
dependencies, timestamps, event counts, and encrypted-vs-legacy routing are
server-derived, while prompts and ciphertext are absent from the frame.

Files:

- `packages/cocodex-protocol/src/collaboration.ts`
- `packages/cocodex-protocol/src/index.ts`
- `apps/cocodex-server/src/agent-routing.ts`
- `apps/cocodex-server/src/encrypted-agent-routing.ts`
- `apps/cocodex-server/src/server.ts`
- `src/cocodex/agent-bridge.ts`
- `src/cocodex/session.ts`
- `src/cocodex/gui-bridge.ts`
- `gui/src/pages/CoCodex.tsx`
- `gui/src/styles-cocodex.css`
- `gui/src/i18n/*.ts`
- `apps/cocodex-server/tests/agent-routing.test.ts`
- `apps/cocodex-server/tests/collaboration-server.test.ts`
- `packages/cocodex-protocol/tests/protocol.test.ts`
- `tests/cocodex-gui-bridge.test.ts`
- `docs/adr/0018-cocodex-authoritative-agent-roster-and-status.md`

The full CoCodex suite was rerun after the slice and encryption hardening:

```text
87 pass
0 fail
801 expect() calls
Ran 87 tests across 29 files.  (exit 0)
test:cocodex-dependencies             (exit 0: 7 pass, 0 fail, 46 expectations)
typecheck:cocodex                 (exit 0)
lint:gui                          (exit 0; one pre-existing warning)
build:gui                         (exit 0; bundle-size warning)
privacy:scan                      (exit 0: Privacy scan passed)
```

The existing OpenCodex suite was also run from the same worktree:

```powershell
.\node_modules\.bin\bun.exe run test
```

The command reached the existing CLI model/help/provider tests but did not
complete within the 240-second command ceiling (`exit 124`, no failing
assertion was emitted in the captured tail). The test-started child processes
were cleaned up, and no CoCodex listener remained. This keeps the overall
release gate incomplete; it is not reported as an existing-suite pass.

The revocation hardening adds migration 18 (`rotation_required`), atomically
invalidates a removed host's queued work and key envelopes, rejects legacy
plaintext project routes after encrypted mode is active, and broadcasts a
strict `project.key.rotation-required` notice to remaining members. The focused
WSS test proves that the owner cannot write at the old epoch until a complete
new-epoch rotation succeeds. Client reconnects migrate the legacy project
context projection before switching to encrypted reads; competing migration
retries are terminally discarded from the durable outbox.

Historical plaintext chat, prompt, artifact, and task rows created before a
project's first key initialization are not retroactively rewritten in this
slice. They are no longer served through keyed legacy routes; complete
historical content migration remains a release-gate item and is not claimed as
finished here.

## Atomic project-key initialization checkpoint

Commits `f80dc082`, `f58490be`, and `90f03548` replace the client's one-envelope-at-a-time initializer
with a strict `project.key.initialize` batch. The server requires one
owner-signed epoch-1 envelope for every approved project member and inserts the
complete set plus the epoch row in one immediate SQLite transaction. The
`project.key.initialized` response is idempotent by project-scoped request ID;
the client reports success only after that acknowledgement, persists the signed
batch and local key across a process restart, replays it before encrypted
outbox traffic, validates the returned envelope set exactly, and removes the
staged local key when the batch is rejected or mismatched. The server also
re-delivers envelopes addressed to a device after authenticated reconnect and
on initialization replay, covering an offline recipient.

Focused command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\project-encryption-storage.test.ts `
  .\tests\cocodex-project-encryption.test.ts `
  .\tests\cocodex-project-encryption-session.test.ts
```

Exit status: `0`

Relevant output:

```text
32 pass
0 fail
224 expect() calls
Ran 32 tests across 4 files.
```

The focused run includes the durable pending-intent store test and a
project-scoped idempotency test. The full CoCodex suite after this checkpoint
is green: `87 pass`, `0 fail`, `801 expect() calls` across 29 files (exit `0`).
This checkpoint does not close
the documented whole-project historical migration, ratcheted private messaging,
file-reference encryption, or full-computer/browser requirements.

## Focused three-process path

Test:
`three-process CoCodex private alpha > two resident clients recover chat,
local execution, and private ciphertext across restart`

Command:

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 60000
```

Exit status: `0`

Relevant output:

```text
1 pass
0 fail
45 expect() calls
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
- keyed reciprocal agent routing whose prompts and streamed results stay
  opaque in SQLite, including encrypted cancellation and post-restart result
  recovery;
- streamed result events and local usage callbacks;
- explicitly supplied, Ed25519-signed recipient key certificates,
  signed/sealed private messages, and protected fingerprint verification;
- server ciphertext-only persistence;
- durable offline chat queues, stable IDs, restart recovery, and duplicate-ID
  checks;
- revisioned server-authoritative Final Goal/context get, update, broadcast,
  and recovery after the server restart;
- signed sanitized usage reports from both isolated clients, membership-scoped
  usage cards, and usage recovery after the server restart.

The current hardening suite also covers malformed-frame rejection, loopback GUI
capability/origin checks, cancellation of in-flight local execution on client
disconnect, expiry of queued/running agent tasks, and recipient-key certificate
binding. Remote agent execution now follows a host-owned policy: cryptographically
pinned trusted devices run directly by default, while hosts can select an
`always` mode that displays the complete prompt for an allow-once decision. The
same WSS path carries bounded mouse-cursor, text-caret/selection, and ephemeral
typing presence, and clears it on disconnect. Authenticated requester/host
cancellation records an
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

## Authenticated prompt awareness

Implementation commit: `203dc406`; hardening commit: `76647c34`

Test names:

- `CoCodex protocol > bounds presence cursor and caret frames`
- `CoCodex protocol > strictly validates server presence snapshots, updates, and leaves`
- `authenticated WSS collaboration > two members share authoritative chat order and recover history by cursor`
- `authenticated WSS collaboration > encrypted chat subscriptions also carry independent presence awareness`

Command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\collaboration-server.test.ts
```

Exit status: `0`

Relevant output:

```text
17 pass
0 fail
130 expect() calls
Ran 17 tests across 2 files.
```

The WSS coverage exercises both the legacy and encrypted chat subscription
routes. It proves that cursor, caret/selection, and typing state are delivered
without clobbering one another; typing-only updates remain visible; duplicate
sockets for one device do not clear the surviving device state; and removing a
project member emits the strict minimal `presence.leave` frame. The server now
validates every emitted presence frame, enforces both per-device and per-project
update limits, caps runtime members at 128, prunes stale or revoked members on
a bounded timer, and the resident client rejects malformed presence frames.
The protocol schemas bound coordinates, caret offsets, display names, timestamps,
member counts, and unknown fields.
The GUI keeps local channels merged, batches typing updates at 100 ms, clears
typing after 1.5 seconds of inactivity or blur, resends the cached state after
reconnect, filters events from an old project, and renders advisory named
caret/selection/typing status chips. It intentionally does not claim a rich
inline caret overlay or stable Yjs RelativePosition mapping yet.

Files:

- `packages/cocodex-protocol/src/collaboration.ts`
- `apps/cocodex-server/src/server.ts`
- `src/cocodex/session.ts`
- `gui/src/pages/CoCodex.tsx`
- `gui/src/styles-cocodex.css`
- `apps/cocodex-server/tests/collaboration-server.test.ts`

Files:

- `tests/cocodex-private-alpha-process.test.ts`
- `tests/fixtures/codex-runtime-fixture.ts`
- `src/cocodex/session.ts`
- `src/cocodex/agent-bridge.ts`
- `src/cocodex/agent-journal.ts`
- `src/cocodex/outbox.ts`
- `apps/cocodex-server/src/server.ts`
- `apps/cocodex-server/src/encrypted-agent-routing.ts`
- `packages/cocodex-protocol/src/project-agent.ts`

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
77 pass
0 fail
717 expect() calls
Ran 77 tests across 27 files.
dist/cocodex-server.exe compiled
dist/cocodex-client.exe compiled
GUI production build completed
Typecheck completed; privacy scan passed
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
and left no live CoCodex process. A subsequent immediate retry completed and is
recorded below; the cold-start timeout remains a known Windows load-sensitivity
issue.

Current retry command:

```powershell
$env:COCODEX_TEST_TRACE='1'; .\node_modules\bun\bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-private-alpha-process.test.ts
```

Retry exit status: `0`.

```text
1 pass
0 fail
21 expect() calls
Ran 1 test across 1 file. [8.44s]
```

The trace reached artifact build, both client connections, reciprocal local
agent execution, private-message decryption, server stop, offline queueing,
reconnect, recovered snapshots, and clean client shutdown. No CoCodex process
remained afterward.

## Client Final Goal surface and operator documentation

Commit: `7010d6ec`

The CoCodex page now loads the shared project context after project selection,
renders the server revision, queues bounded `context.update` requests through
the GUI bridge, and applies authoritative update/change frames. The bridge test
asserts that context commands are capability-gated and forwarded without
surfacing private ciphertext. `docs/cocodex-client.md` and
`docs/cocodex-server.md` document separate builds, enrollment, direct hosting,
manual forwarding, security boundaries, offline behavior, and deferred
features; `docs/README.md` links them with the architecture references and
evidence report.

## Signed sanitized usage reports

Commit: `b2c124f9`

Commands:

```powershell
.\node_modules\bun\bin\bun.exe run typecheck:cocodex
.\node_modules\bun\bin\bun.exe run --cwd gui build
.\node_modules\bun\bin\bun.exe run --cwd gui lint
.\node_modules\bun\bin\bun.exe run test:cocodex
```

Exit status: `0` for every command.

The protocol test covers bounded report fields and transcript binding. The
server usage test covers Ed25519 verification, stale revision rejection,
membership filtering, idempotent persistence, and explicit missing reports.
The real WSS collaboration test covers report, project-scoped get, broadcast,
and reconnect. The three-process harness proves both isolated clients publish
local token summaries and recover them after a server restart. The server
stores `report_json` plus the signature in migration v9; it never receives
provider credentials or raw account records. Optional quota percentages/reset
times remain absent when the local runtime has not supplied them.

Automatic direct hosting now attempts UPnP first, NAT-PMP, and PCP as bounded
UDP fallbacks; packet encoding/response validation and diagnostic classification
are covered by the port-mapping tests. Manual one-port forwarding remains the
guaranteed baseline, and failures still explain likely CGNAT or firewall/router
blocks instead of pretending that a mapping succeeded.

## Private-message crypto boundary and hardening

Implementation commit: `63b552a6`

The private-alpha sealed-box path now rejects non-canonical or undersized
ciphertexts, bounds decrypted payloads before JSON parsing, and fails closed on
malformed payloads. The device certificate still binds the recipient's X25519
messaging key to its Ed25519 fingerprint. ADR 0014 records the deliberate
single-device boundary: no forward-secret or multi-device claim is made until a
maintained compatible Matrix/vodozemac-style state machine is selected.

Focused command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-private-messaging.test.ts `
  .\apps\cocodex-server\tests\collaboration-server.test.ts
```

Exit status: `0`; relevant output: `4 pass`, `0 fail`, `64 expect() calls`.

## Project-wrap identity and encrypted Final Goal/context

Implementation commit: `81532e6e`

The first project-encryption slice is now connected end to end. Each client
creates a separate X25519 project-wrap keypair; the owner can send signed,
per-device sealed project-key envelopes. The server validates owner authority,
approved membership, signatures, replay/idempotency, and revision conflicts,
then persists opaque envelope JSON only. The client unwraps the project key and
decrypts the Final Goal/context locally with libsodium XChaCha20-Poly1305.

Focused command:

```powershell
.\node_modules\bun\bin\bun.exe test `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\apps\cocodex-server\tests\project-encryption-storage.test.ts `
  .\apps\cocodex-server\tests\project-encryption-server.test.ts `
  .\tests\cocodex-project-encryption.test.ts `
  .\tests\cocodex-project-encryption-session.test.ts
```

Exit status: `0`.

Relevant output:

```text
20 pass
0 fail
111 expect() calls
```

The real session test runs two enrolled clients against a real TLS/WSS server,
initializes a project key, writes encrypted context, verifies the SQLite row
does not contain the plaintext goal, and recovers the goal by local decryption
on the other client. This does not generalize to all project records yet.

## Encrypted shared chat and project-key lifecycle

Implementation commit: `02d24e16`

The project-key epoch state is now monotonic and server-authoritative. Owner
rotations are compare-and-swap operations that require one signed envelope for
every approved member; replayed rotations are idempotent. Removing a member
deletes its project membership and key envelopes, sends a revocation notice,
and the removed client marks its local key ring unusable for new writes.

The new `project.chat.*` transport encrypts the chat body on the client with
the current project key, signs the envelope, assigns authoritative server
sequence, and stores only opaque envelope JSON in `project_chat_events`. The
client decrypts and verifies the envelope before emitting the normal local
`chat.event` shape. Existing `chat.*` fixtures remain compatible when no local
project key exists.

Focused command and evidence:

```powershell
.\node_modules\.bin\bun.exe test `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\apps\cocodex-server\tests\project-encryption-storage.test.ts `
  .\apps\cocodex-server\tests\project-encryption-server.test.ts `
  .\tests\cocodex-project-encryption.test.ts `
  .\tests\cocodex-project-encryption-session.test.ts `
  .\tests\cocodex-outbox.test.ts `
  .\tests\cocodex-gui-bridge.test.ts
```

Exit status: `0`; relevant output: `32 pass`, `0 fail`, `218 expect() calls`.
The complete `bun run test:cocodex` command also passed with `66 pass`, `0
fail`, and `555 expect() calls`. The focused WSS test includes tampered
signature rejection and a SQLite canary proving that the chat plaintext is
absent.

## Encrypted shared prompt updates

Implementation commits: `2be9f7d0`, `e15cc537`

The new `project.prompt.*` transport encrypts each bounded Yjs update on the
client with the current project key and signs the envelope. The server checks
membership, the current key epoch, the enrolled sender key, the record binding,
and replay/idempotency, then assigns an authoritative sequence and stores only
the opaque envelope in `project_prompt_updates`. It never applies Yjs. Both
clients decrypt the accepted/changed update locally and feed it to the existing
prompt document; the durable outbox and reconnect cursor cover offline replay.

Focused command and evidence:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\apps\cocodex-server\tests\project-encryption-storage.test.ts `
  .\apps\cocodex-server\tests\project-encryption-server.test.ts `
  .\tests\cocodex-project-encryption.test.ts `
  .\tests\cocodex-project-encryption-session.test.ts `
  .\tests\cocodex-outbox.test.ts `
  .\tests\cocodex-gui-bridge.test.ts
```

Exit status: `0`; relevant output: `33 pass`, `0 fail`, `239 expect() calls`.
The session test creates a real Yjs document, encrypts its binary update, and
applies the decrypted update on the receiving client. The WSS test also proves
that the stored prompt envelope contains ciphertext but neither the update
bytes nor prompt text. The encrypted-session teardown uses bounded Windows
cleanup retries so concurrent test files do not turn a passed assertion into a
spurious `EBUSY` failure. The same session test stops and restarts the real
TLS/WSS server, then recovers encrypted chat, prompt, and context snapshots
from SQLite on both clients.

Full CoCodex command:

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status: `0`; relevant output: `68 pass`, `0 fail`, `594 expect() calls`.

## Encrypted project artifacts

Implementation commit: `ba32d995`

The `project.artifact.*` transport encrypts the complete artifact record on the
client when a project key is available. The server stores only a signed opaque
envelope plus project/task/author routing metadata in `project_artifacts`.
Client-side decryption validates the envelope sender, key epoch, artifact ID,
project ID, task binding, type, title, summary, status, and body before the
normal artifact frame is exposed. The existing protected outbox carries an
offline publish, and a subscribed list is reissued after reconnect.

Focused command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\apps\cocodex-server\tests\project-encryption-storage.test.ts `
  .\tests\cocodex-project-encryption-session.test.ts
```

Exit status: `0`; relevant output: `19 pass`, `0 fail`, `138 expect() calls`.
The session test uses two enrolled clients and a real TLS/WSS server, confirms
that the SQLite artifact envelope contains neither the title nor body, and
recovers the decrypted artifact from a post-restart list on both clients.

The complete CoCodex command was rerun after this change:

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status: `0`; relevant output: `72 pass`, `0 fail`, `663 expect() calls`
across 26 files.

## Encrypted agent prompts and streamed results

Implementation decision: ADR 0016. The keyed agent transport uses the existing
signed project-content envelope: `task` for the requester prompt and
`agent-response` for each host result. The server stores `[encrypted]` and
opaque envelopes only; the host client decrypts, authorizes, executes locally,
and journals result replay. Encrypted cancellation is routed as control and the
host emits the encrypted terminal failure event.

Focused command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\tests\cocodex-agent-bridge-recovery.test.ts `
  .\tests\cocodex-private-alpha-process.test.ts
```

Exit status: `0`; relevant output: `22 pass`, `0 fail` for the focused protocol,
routing, migration, bridge, and three-process files (the three-process test
alone reports `1 pass`, `0 fail`, `45 expect() calls`). The process harness
builds and launches one real server plus isolated Stephen and Kai clients,
initializes a project key, executes reciprocal tasks through the production
Codex adapter, checks prompt/result canaries are absent from SQLite, exercises
encrypted cancellation in the bridge suite, restarts the server, and recovers
the encrypted result events by cursor.

Files: `packages/cocodex-protocol/src/project-agent.ts`,
`apps/cocodex-server/src/encrypted-agent-routing.ts`,
`apps/cocodex-server/src/encrypted-chat.ts`, `src/cocodex/agent-bridge.ts`,
`src/cocodex/session.ts`, and `tests/cocodex-private-alpha-process.test.ts`.

## Signed CoCodex Server authority handoff

Implementation commit: `8361f7d6`

Test name: `hands a live server to a prepared process and reconnects a resident client`

Focused command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-server-transfer-process.test.ts
```

Exit status: `0`; relevant output: `1 pass`, `0 fail`, `24 expect()` calls.

The test launches separate source and destination `cocodex-server` CLI
processes with isolated temporary state roots, ports, identities, TLS
certificates, and SQLite databases. It enrolls a client over the real HTTPS
enrollment endpoints and WSS authentication, creates a project, stops the
source, exports a destination-bound AES-GCM transfer, proves the source status
is `retired` and that a new source start is refused, imports into the prepared
destination, starts the destination, accepts the source-signed
`ccx-transfer1.` certificate in the client, and reads the surviving project
through a real `project.list` WebSocket frame at authority epoch 2.

The complete CoCodex command was rerun after this change:

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status: `0`; relevant output: `75 pass`, `0 fail`, `698 expect() calls`
across 27 files. Typecheck, separate server/client compile builds, and the
privacy scan also exited `0`.

Files: `packages/cocodex-protocol/src/server-transfer.ts`,
`apps/cocodex-server/src/backup.ts`, `apps/cocodex-server/src/server-state.ts`,
`apps/cocodex-server/src/cli.ts`, `apps/cocodex-server/src/server.ts`,
`src/cocodex/client.ts`, `src/cocodex/cli.ts`,
`tests/cocodex-server-transfer-process.test.ts`,
`apps/cocodex-server/tests/backup.test.ts`, and ADR 0017.

## Offline encrypted private-message round trip

Implementation commit: `0792469f`

The three-process private-alpha test now queues one encrypted private message
in each direction while the server is stopped. Both messages remain in the
protected client outboxes, are acknowledged after the server restarts, and are
decrypted only by the intended recipient. The same test still proves the
resident client processes retain their PIDs, recover shared chat and encrypted
agent results, and recover after restart.

Focused command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-private-alpha-process.test.ts
```

Exit status: `0`; relevant output: `1 pass`, `0 fail`, `45 expect() calls`.
The observed trace reached `offline queues accepted`, `clients reconnected`,
and `recovered snapshots received` before clean shutdown.

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

## Local full-computer access profile and emergency controls

Implementation scope: the Client now has a durable `project-only` /
`full-computer` access profile. Full-computer mode is an explicit local opt-in
to the official Codex `danger-full-access` sandbox; the Server protocol is
unchanged and never receives a shell capability. Atomic local safety state
supports emergency stop, resume, and separate full-computer enable/disable.

Focused command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-agent-safety.test.ts `
  .\tests\cocodex-agent-safety-cli.test.ts `
  .\tests\cocodex-codex-agent-adapter.test.ts `
  .\tests\cocodex-agent-bridge-recovery.test.ts `
  .\tests\cocodex-gui-bridge.test.ts
```

Exit status: `0`; relevant output: `13 pass`, `0 fail`, `88 expect()` calls.
The adapter test proves absent opt-in never spawns Codex, the safety test proves
atomic persistence and downgrade fail-closed behavior, the bridge test proves
an active task is aborted by emergency stop, and the GUI test proves the local
safety commands are allowlisted and private ciphertext remains redacted.

Files: `src/cocodex/agent-policy.ts`, `src/cocodex/agent-safety.ts`,
  `src/cocodex/codex-agent-adapter.ts`, `src/cocodex/agent-bridge.ts`,
`src/cocodex/session.ts`, `src/cocodex/cli.ts`, `src/cocodex/gui-bridge.ts`,
`src/cocodex/paths.ts`, ADR 0021, and the five focused test files.

Implementation commit: `b07923db`.

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
- whole-project encryption is not implemented yet: keyed task prompts and
  agent results now use explicit encrypted frames, but file references remain
  server-readable and legacy plaintext compatibility routes remain for
  projects without a key. Final Goal/context, shared chat, shared prompt
  updates, keyed artifacts, and keyed agent events are encrypted only through
  their explicit new frames. Automatic post-removal rotation orchestration and
  revocation UI are still incomplete.
- robust CGNAT detection, relay, libp2p,
  forward-secret ratcheted messaging, multi-device messaging, and revocation
  UI. The current GUI/server path includes a bounded Yjs shared-prompt
  document, but it does not yet provide a full Hocuspocus deployment or
  network pagination-gap UX.

Accordingly, the connected deterministic private-alpha path works, but this
report does not authorize a production or complete-private-alpha release claim.

## Private mailbox delivery hardening checkpoint

Implementation commit: `8ca7c5e8f675181e7e317559dcf360e6d8f25e5b`

This checkpoint keeps the private-alpha sealed-box format while adding strict
canonical ciphertext/frame bounds, an immediate SQLite transaction for the
message and replay index, a protected atomic client mailbox cursor with bounded
receipts, serialized snapshot/live delivery, GUI ciphertext redaction for
accepted frames, and an active WSS authorization-revocation sweep. The
mailbox test also proves that a client's own sent messages advance its cursor,
so reconnects do not replay sender history indefinitely.

Focused protocol, crypto, mailbox, and real three-process harness:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\tests\cocodex-private-mailbox.test.ts `
  .\tests\cocodex-private-messaging.test.ts `
  .\tests\cocodex-private-alpha-process.test.ts
```

Exit status: `0`; relevant output: `25 pass`, `0 fail`, `156 expect()` calls.
The alpha harness launched one compiled CoCodex Server process and isolated
Stephen and Kai Client processes with separate roots, identities, databases,
ports, and workspaces. It observed local agent execution, encrypted private
delivery, server termination, offline queueing, reconnect, and recovery while
both client PIDs remained resident.

Focused WSS authorization/revocation test:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\apps\cocodex-server\tests\collaboration-server.test.ts
```

Exit status: `0`; relevant output: `3 pass`, `0 fail`, `74 expect()` calls.
The revocation case uses a real authenticated socket, revokes its device in
SQLite, and observes close code `1008` with the revocation reason without
requiring another client frame.

Complete CoCodex suite (serialized to avoid the known Windows process-load
race):

```powershell
.\node_modules\.bin\bun.exe run test:cocodex -- --max-concurrency=1
```

Exit status: `0`; relevant output: `91 pass`, `0 fail`, `823 expect()` calls
across 30 files. The same suite's unbounded parallel invocation is not used as
release evidence: it reached `89 pass` and exposed two load-sensitive failures
(the repository's existing 20-second agent-safety CLI timeout and a mailbox
timing assertion); the serial retry reached `90 pass` with only the CLI
timeout, and a clean serialized retry then passed. The CLI test passes alone
in `1.3s`.

Build and static checks:

```powershell
.\node_modules\.bin\bun.exe run typecheck
.\node_modules\.bin\bun.exe run typecheck:cocodex
.\node_modules\.bin\bun.exe run build:cocodex-client
.\node_modules\.bin\bun.exe run build:cocodex-server
.\node_modules\.bin\bun.exe run privacy:scan
.\node_modules\.bin\bun.exe run lint:gui
```

Every command exited `0`. The GUI lint produced one existing
`react-hooks/exhaustive-deps` warning and no errors. The separate client and
server compile artifacts were produced, and the privacy scan found no private
plaintext leak.

Files: `packages/cocodex-protocol/src/collaboration.ts`,
`packages/cocodex-protocol/src/index.ts`,
`packages/cocodex-protocol/tests/protocol.test.ts`,
`apps/cocodex-server/src/private-messages.ts`,
`apps/cocodex-server/src/server.ts`,
`apps/cocodex-server/tests/collaboration-server.test.ts`,
`src/cocodex/private-mailbox.ts`, `src/cocodex/session.ts`,
`src/cocodex/gui-bridge.ts`, `src/cocodex/paths.ts`,
`tests/cocodex-private-mailbox.test.ts`,
`tests/cocodex-private-alpha-process.test.ts`, ADR 0014, ADR 0022, and the
open-source reference matrix.

The Matrix binding audit is recorded in ADR 0022. The evaluated packages were
Apache-2.0 references only and were removed from `package.json`/`bun.lock`
because the Bun durable-store and packaged native-runtime gates were not met.
The alpha therefore makes no forward-secrecy, ratchet, or multi-device claim.

## Dependency-bound agent dispatch and private delivery retry checkpoint

Implementation commit: `c55c1ac5`

The local plaintext-agent verifier now includes the complete dependency list in
both requester and server dispatch transcripts. Server task creation
canonicalizes duplicate dependency IDs, makes replay idempotent under that
canonical form, and rejects dependency cycles with a bounded graph walk. The
encrypted task path applies the same checks. Private delivery now acknowledges
only successfully opened or self-authored messages; an unknown sender or
decryption failure advances the server cursor while retaining the ciphertext in
the protected, bounded local mailbox for retry after trust/key recovery. The
client also processes `private.accepted` frames so self-sent messages are
durably accounted for without waiting for a later snapshot.

Focused verification:

```powershell
.\node_modules\.bin\bun.exe run typecheck:cocodex
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\tests\cocodex-agent-bridge-recovery.test.ts `
  .\tests\cocodex-private-mailbox.test.ts
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\tests\cocodex-private-mailbox.test.ts `
  .\tests\cocodex-private-messaging.test.ts `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status: `0` for every command. Relevant output: typecheck passed;
agent-routing `3 pass`, bridge recovery `6 pass`, mailbox `4 pass`; combined
protocol/private-alpha verification `27 pass`, `0 fail`, `164 expect()` calls.
The alpha test used one real compiled server and two resident isolated client
processes, exercised server restart and offline queues, and verified private
mailbox recovery across both directions. The tests also cover duplicate
dependency replay, cycle rejection, signed dependency verification, bounded
deferred ciphertext, and deferred-message removal after a successful receipt.

Files: `apps/cocodex-server/src/agent-routing.ts`,
`apps/cocodex-server/src/encrypted-agent-routing.ts`,
`src/cocodex/agent-bridge.ts`, `src/cocodex/private-mailbox.ts`,
`src/cocodex/session.ts`, and their focused server/client tests.

The serialized full-suite rerun after this checkpoint was also attempted:

```powershell
.\node_modules\.bin\bun.exe run test:cocodex -- --max-concurrency=1
```

It exited `1` after `92 pass`, `2 fail`, `799 expect()` calls. The failures are
the known Windows load-sensitive `cocodex-agent-safety-cli` 20-second timeout
and one intermittent private-alpha mailbox timing failure. The private-alpha
test then passed twice when run alone (each run `1 pass`, `0 fail`, `48
expect()` calls), and the focused combined command above passed. The complete
existing-suite gate therefore remains open and is not claimed as green.

## Final verification after recovery checkpoint

Implementation checkpoint for this verification: `c55c1ac5`. The final focused
integration/security command was:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\apps\cocodex-server\tests\collaboration-server.test.ts `
  .\tests\cocodex-agent-bridge-recovery.test.ts `
  .\tests\cocodex-private-mailbox.test.ts `
  .\tests\cocodex-private-messaging.test.ts `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status: `0`; relevant output: `39 pass`, `0 fail`, `287 expect()` calls
across seven files. This includes the real WSS revocation test, dependency
cycle/idempotency and signed-host tests, bounded deferred-mailbox tests, and
the three-process restart/offline/private-alpha harness.

The final static/build commands were:

```powershell
.\node_modules\.bin\bun.exe run typecheck
.\node_modules\.bin\bun.exe run typecheck:cocodex
.\node_modules\.bin\bun.exe run build:cocodex-client
.\node_modules\.bin\bun.exe run build:cocodex-server
.\node_modules\.bin\bun.exe run privacy:scan
.\node_modules\.bin\bun.exe run lint:gui
```

Every command exited `0`. The separate Client and Server executables compiled,
the privacy scan passed, and GUI lint reported one existing
`react-hooks/exhaustive-deps` warning with no errors. No CoCodex server/client
process or listener was left running after verification.
