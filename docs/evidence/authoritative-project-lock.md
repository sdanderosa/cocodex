# Authoritative project-lock evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `536cf864d1928353a1797e35af187fcc07b3c8e2`
- Implementation commit: `e33ebbf8a30f718bd2377d3ff9aac08b31260ac5`
- Evidence commit: recorded by the commit containing this file
- Status: focused, complete CoCodex, GUI, build, privacy, and inherited
  regression gates pass

## Behaviors proved

- An approved project owner signs every lock and unlock transition with the
  resident device's Ed25519 key.
- The signature transcript binds the project, action, expected revision,
  reason, server fingerprint and epoch, validity window, and a canonical
  32-byte nonce.
- The Server validates the current owner device, signature, authority, time
  window, nonce, operation identity, and expected revision.
- SQLite migration 30 stores one authoritative lock state, an immutable
  transition history, and durable task-cancellation deliveries.
- The Server rechecks mutable owner authorization inside an immediate
  transaction and every shared mutation path rechecks the project state inside
  its write transaction. A lock committed on a second SQLite connection is
  therefore visible before a competing write can commit.
- Locking atomically rejects new shared writes, expires pending project
  invitations, fails queued or running remote tasks, records cancellation
  deliveries, clears presence, and broadcasts the monotonic state.
- A cancellation arriving before a local task controller exists remains
  authoritative and prevents the task from starting, for encrypted and legacy
  plaintext compatibility requests.
- Exact retries of the current transition are idempotent even after the
  original request expires. Replays of a superseded transition and
  same-revision equivocation are rejected.
- Resident Clients maintain a monotonic per-project lock state, pause remote
  agent execution before encrypted prompt decryption, block shared mutation
  commands, and disconnect on stale or equivocating authority state.
- The GUI bridge projects only a bounded safe lock DTO. The interface shows the
  locked state and disables prompt, chat, goal, artifact, invitation, agent
  configuration, and remote-run controls until an authoritative unlock.
- Local OpenCodex-compatible behavior remains independent of the collaboration
  lock and continues to pass the inherited suite.

## Test and build evidence

```powershell
.\node_modules\.bin\bun.exe run test:cocodex-lock
```

Exit status `0`: `17 pass`, `0 fail`, `188 expect()` calls across five files.
This includes canonical protocol validation, owner authorization, replay and
tamper rejection, cross-connection SQLite visibility, monotonic Client state,
pre-controller cancellation, pause-before-decrypt, and safe GUI projection.

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status `0`: `155 pass`, `0 fail`, `1510 expect()` calls across 35 files.
The real private-alpha harness, TLS/WSS collaboration server, encrypted project
sessions, revocation recovery, offline outbox, and local execution recovery all
passed.

```powershell
.\node_modules\.bin\bun.exe run test:batched
```

Exit status `0`: all `346` inherited test files completed across 14 fresh
workers. The historically load-sensitive `cli-models.test.ts` batch and the
three-process private-alpha test both passed in this stable-tree run.

```powershell
.\node_modules\.bin\bun.exe run --cwd gui test
```

Exit status `0`: `118 pass`, `0 fail`, `573 expect()` calls across 21 files.

The following commands also exited `0`:

- `bun run typecheck`
- `bun run typecheck:cocodex`
- `bun run build:cocodex-client`
- `bun run build:cocodex-server`
- `bun run build:gui`
- `bun run lint:gui` (one pre-existing React hook warning, zero errors)
- `bun run privacy:scan`
- `git diff --check`

The GUI build emitted its existing bundle-size advisory and completed.

## Process and network evidence

- `apps/cocodex-server/tests/collaboration-server.test.ts` starts a real TLS/WSS
  Server, authenticates isolated devices, locks the project, observes blocked
  network mutations and cancellation, restarts the Server, recovers the durable
  lock, unlocks monotonically, and resumes writes.
- `tests/cocodex-private-alpha-process.test.ts` runs one Server process and
  isolated Stephen and Kai Client processes over the real network transport.
  It passed in both `test:cocodex` and the clean 346-file inherited run.
- `apps/cocodex-server/tests/project-locks.test.ts` opens independent SQLite
  connections to the same file-backed database and proves that the
  transaction-local write guard observes a committed lock.

## Primary files

- `docs/adr/0041-cocodex-authoritative-project-lock.md`
- `packages/cocodex-protocol/src/project-lock.ts`
- `apps/cocodex-server/src/project-locks.ts`
- `apps/cocodex-server/src/project-invitation-lifecycle.ts`
- `apps/cocodex-server/src/migrations.ts`
- `apps/cocodex-server/src/server.ts`
- `src/cocodex/project-lock-state.ts`
- `src/cocodex/session.ts`
- `src/cocodex/agent-bridge.ts`
- `src/cocodex/outbox.ts`
- `src/cocodex/gui-bridge.ts`
- `gui/src/pages/CoCodex.tsx`
- `packages/cocodex-protocol/tests/project-lock.test.ts`
- `apps/cocodex-server/tests/project-locks.test.ts`
- `apps/cocodex-server/tests/collaboration-server.test.ts`
- `tests/cocodex-project-lock-state.test.ts`
- `tests/cocodex-agent-bridge-recovery.test.ts`
- `tests/cocodex-gui-bridge.test.ts`

## Explicit limits

- A project lock is an authoritative collaboration and remote-execution freeze;
  it is not cryptographic revocation and does not rotate an existing project
  key.
- Queued shared mutations that receive an authoritative `PROJECT_LOCKED`
  rejection are removed from the outbox and require an explicit user resubmit
  after unlock.
- Task cancellation delivery is at least once and bounded to the newest 512
  durable records per reconnect query. Foreign-key cleanup follows the task and
  project lifecycle.
- This slice implements owner-signed project lock and unlock, not a separate
  server-admin override.
- Automatic NAT traversal, relay infrastructure, server migration automation,
  and other later product requirements remain outside this slice and are not
  claimed here.
