# Device revocation incident-response evidence

- **Date:** 2026-07-27
- **Implementation commit:** `dc587ed45ac92dee364b3932e28f223e90990288`
- **Base commit:** `086f3ea626d95307baeee51ceaa9415aba2de818`
- **Branch:** `feat/cocodex-foundation`
- **Scope:** keyed-project quarantine, owner promotion, task and envelope
  invalidation, resident-session eviction, explicit survivor rotation, safe
  renderer state, restart recovery, and incident resolution

## Completion claims

### Atomic server-side quarantine

Tests:

- `device enrollment > atomically quarantines every keyed project when a
  device is revoked`
- `opaque project-encryption server storage > quarantines more than one
  incident page without starving later projects`
- `opaque project-encryption server storage > keeps an owner-only project
  quarantined until an approved recovery owner exists`

The revocation transaction expires invitations, promotes the deterministic
approved survivor when an owner is revoked, disables agents hosted by the
revoked device, terminally fails queued or running tasks in either direction,
deletes envelopes to and from the device, marks each affected keyed project
`rotation_required`, and persists a durable unresolved incident. A project
with no approved survivor remains quarantined without inventing a recovery
owner. The survivor query is intentionally unpaginated so a large incident set
cannot starve later projects.

Files:

- `apps/cocodex-server/src/enrollment.ts`
- `apps/cocodex-server/src/migrations.ts`
- `apps/cocodex-server/src/project-encryption-storage.ts`
- `apps/cocodex-server/tests/enrollment.test.ts`
- `apps/cocodex-server/tests/project-encryption-storage.test.ts`
- `apps/cocodex-server/tests/database-migration.test.ts`

### Real TLS/WSS eviction, rotation, and restart recovery

Test:
`device revocation incident response > evicts the revoked owner, quarantines
the survivor, rotates explicitly, and stays resolved after restart`

Command:

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-device-revocation-session.test.ts
```

- Exit status: `0`
- Relevant output: `1 pass`, `0 fail`, `21 expect() calls`

Process and network evidence:

- one real CoCodex TLS/WSS server binds an ephemeral TCP port;
- two isolated resident client sessions use separate state roots and
  cryptographic identities;
- Stephen creates and keys a project, invites Kai, and Kai accepts;
- Stephen's owner device is revoked while both clients are connected;
- Stephen's authenticated socket closes with policy status, while Kai receives
  a durable incident, becomes the approved owner, and enters quarantine;
- a stale epoch-1 write is rejected and creates no chat row;
- Kai explicitly removes the revoked member and rotates to epoch 2;
- the matching incident resolves only after that exact operation;
- an epoch-2 encrypted write succeeds;
- after a server restart on the same state, the resolved incident is not
  replayed and new writes continue to work.

Files:

- `apps/cocodex-server/src/server.ts`
- `apps/cocodex-server/src/shared-state.ts`
- `src/cocodex/session.ts`
- `tests/cocodex-device-revocation-session.test.ts`
- `apps/cocodex-server/tests/collaboration-server.test.ts`

### Bounded protocol and complete task cancellation

The strict `project.device-revoked` frame carries only bounded incident
metadata. Its task summary is capped at 256 entries, while storage retains the
complete cancelled-task list and the server sends every required per-task
cancellation to surviving authenticated targets.

Tests:

- `CoCodex protocol > strictly validates bounded device-revocation incidents`
- `authenticated WSS collaboration > evicts a revoked device and notifies
  surviving project members`

Files:

- `packages/cocodex-protocol/src/collaboration.ts`
- `packages/cocodex-protocol/src/index.ts`
- `packages/cocodex-protocol/tests/protocol.test.ts`
- `apps/cocodex-server/src/server.ts`
- `apps/cocodex-server/tests/collaboration-server.test.ts`

### Client quarantine and renderer containment

Tests:

- `CoCodex project revocation client > excludes every revoked roster device
  from the replacement key epoch`
- `CoCodex GUI bridge > exposes only safe device-revocation incident fields`
- `owner roster renders quarantine recovery and revoked membership safely`

The resident client marks its local key store `rotationRequired`, does not
silently rotate, refreshes authoritative project metadata, excludes every
revoked device from the replacement epoch, and requires an approved local
owner. The GUI bridge reconstructs an allowlisted incident DTO and withholds
certificates, envelopes, keys, task payloads, and other server-frame fields.
The UI shows the quarantine, renders revoked roster entries without trust
actions, and clears the incident only after a matching removal plus a newer
key epoch.

Files:

- `src/cocodex/session.ts`
- `src/cocodex/gui-bridge.ts`
- `tests/cocodex-project-revocation-client.test.ts`
- `tests/cocodex-gui-bridge.test.ts`
- `gui/src/cocodex-member-state.ts`
- `gui/src/pages/CoCodex.tsx`
- `gui/tests/cocodex-member-roster-ui.test.tsx`

## Commands and results

### Focused server and protocol suites

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\enrollment.test.ts `
  .\apps\cocodex-server\tests\project-encryption-storage.test.ts `
  .\apps\cocodex-server\tests\shared-state.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts
```

- Exit status: `0`
- Relevant output: `44 pass`, `0 fail`, `410 expect() calls`

The storage suite was rerun after adding the 129-incident starvation case:
`12 pass`, `0 fail`, `184 expect() calls` (exit `0`).

The full real WSS collaboration suite was rerun after Windows temporary TLS
cleanup hardening: `7 pass`, `0 fail`, `128 expect() calls` (exit `0`).

### Focused client and GUI suites

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-project-revocation-client.test.ts `
  .\tests\cocodex-gui-bridge.test.ts
```

- Exit status: `0`
- Relevant output: `2 pass`, `0 fail`, `91 expect() calls`

```powershell
cd gui
..\node_modules\.bin\bun.exe test `
  .\tests\cocodex-member-roster-ui.test.tsx
```

- Exit status: `0`
- Relevant output: `7 pass`, `0 fail`, `29 expect() calls`

### Three-process private alpha

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

- Exit status: `0`
- Relevant output: `1 pass`, `0 fail`, `267 expect() calls`
- The test launches one real server executable and isolated Kai and Stephen
  client executables across the production TLS/WSS transport.
- A stale queued epoch-1 chat is terminally discarded after revocation; Kai
  rotates to epoch 2 and sends a fresh encrypted message.

### Full CoCodex and GUI gates

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

- Exit status: `0`
- Relevant output: `152 pass`, `0 fail`, `1474 expect() calls`, 35 files

```powershell
cd gui
..\node_modules\.bin\bun.exe test tests
```

- Exit status: `0`
- Relevant output: `118 pass`, `0 fail`, `573 expect() calls`, 21 files

### Static, privacy, and production-build gates

Commands:

```powershell
.\node_modules\.bin\bun.exe run typecheck:cocodex
.\node_modules\.bin\bun.exe run privacy:scan
.\node_modules\.bin\bun.exe run build:cocodex-server
.\node_modules\.bin\bun.exe run build:cocodex-client
cd gui
..\node_modules\.bin\bun.exe run lint
..\node_modules\.bin\bun.exe run build
```

- Exit status: `0` for every command
- Privacy output: `Privacy scan passed`
- Lint output: no errors and one pre-existing
  `react-hooks/exhaustive-deps` warning in `gui/src/use-app-route-state.ts`
- Build output includes `apps/cocodex-server/dist/cocodex-server.exe`,
  `dist/cocodex-client.exe`, and the production GUI; Vite emits only its
  existing large-chunk advisory.

### Complete inherited OpenCodex suite

```powershell
.\node_modules\.bin\bun.exe run test:batched
```

- Exit status: `0`
- Relevant output: all `345` files completed across `14` fresh workers
- No aggregate assertion count is claimed because the checked-in batched
  runner reports completion by file and worker.

## Architecture and review result

The architecture decision is recorded in
`docs/adr/0040-cocodex-device-revocation-incident-response.md`. The design
adapts Syncthing-style device identity, Matrix-style key withholding, and
MeshCentral-style authoritative routing without copying source code or adding
a dependency. Architecture, server, client, security, and integration reviews
found no remaining P1 or P2 blocker in this slice.

This evidence is limited to keyed-project revocation incident response. It
does not claim completion of deferred relay, automatic NAT traversal, remote
desktop, failover, or the full long-term product vision.
