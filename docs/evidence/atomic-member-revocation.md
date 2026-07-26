# Atomic member revocation evidence

- **Date:** 2026-07-26
- **Implementation commit:** `b3b132860583ad1d3bcceb7e0127a6b2349a176b`
- **Base commit:** `51e915638ac24460b36fbe967fa87f8d163f4e54`
- **Branch:** `feat/cocodex-foundation`
- **Scope:** device-certificate trust, atomic removal/key rotation, durable replay,
  online/offline revocation recovery, owner UI, and renderer containment

## Completion claims

### Atomic owner removal and immutable replay

Test:
`opaque project-encryption server storage > atomically removes a member,
cancels both task directions, and rotates to the exact remaining roster`

The test injects a SQLite trigger failure at the final operation-record insert
and proves membership, agents, tasks, and epoch all roll back. It then proves
the successful transaction, exact survivor envelope set, agent disabling,
bidirectional task cancellation, replay conflict detection, exact replay after
a later epoch-3 rotation, and an empty `PRAGMA foreign_key_check`.

Files:

- `apps/cocodex-server/src/project-encryption-storage.ts`
- `apps/cocodex-server/src/migrations.ts`
- `apps/cocodex-server/src/server.ts`
- `apps/cocodex-server/tests/project-encryption-storage.test.ts`
- `apps/cocodex-server/tests/database-migration.test.ts`

### Real TLS/WSS revocation, survivor write, and restart replay

Test:
`CoCodex encrypted project context session > initializes a project key,
encrypts context on the wire, and decrypts it on another client`

Process/network evidence:

- one real CoCodex TLS/WSS server bound to an ephemeral TCP port;
- three independently enrolled and approved client identities and state roots
  for Stephen, Kai, and Angela;
- epoch 1 initialized for all three devices;
- Kai removed while Stephen and Angela receive epoch 2;
- Angela authors and signs an epoch-2 encrypted chat write, Stephen decrypts
  it, and SQLite records `keyEpoch = 2` and Angela's sender device ID;
- a second atomic removal is queued while the server is offline;
- Stephen's resident session is stopped and recreated from the same protected
  disk state;
- the server restarts on the same TLS/WSS port;
- the exact durable operation replays, the queue empties, and Kai is revoked.

Files:

- `src/cocodex/session.ts`
- `src/cocodex/outbox.ts`
- `src/cocodex/project-key-store.ts`
- `tests/cocodex-project-encryption-session.test.ts`
- `tests/cocodex-outbox.test.ts`

### Device-bound survivor keys and renderer containment

Tests:

- `CoCodex private-message encryption > binds the recipient messaging key to
  its trusted signing identity`
- `CoCodex GUI bridge > runs the resident session without exposing private
  ciphertext`

Evidence:

- each device publishes a signed certificate binding its enrolled Ed25519
  identity to messaging and project-wrap X25519 keys;
- the server accepts it only when every key and fingerprint matches enrollment;
- a recipient uses a survivor wrap key only after certificate verification and
  an explicit local trusted-fingerprint match;
- unknown server frame types are withheld;
- known renderer frames are recursively reconstructed from an explicit field
  allowlist;
- allowed-frame canaries for `workspaceRoot`, `senderPublicKeyPem`,
  `signature`, and `token` are removed while legitimate chat content remains.

Files:

- `packages/cocodex-protocol/src/device-certificate.ts`
- `apps/cocodex-server/src/server.ts`
- `src/cocodex/identity.ts`
- `src/cocodex/session.ts`
- `src/cocodex/gui-bridge.ts`
- `tests/cocodex-gui-bridge.test.ts`

### Owner UI and direct revocation cleanup

Tests:

- `owner roster exposes verification before atomic member removal`
- `non-owner roster never renders trust or removal controls`
- `owner roster invokes enabled controls and disables every action offline`
- `removal confirmation can cancel and the accepted command is exact`
- `revocation removes the project and moves or clears the selected project`

The production handler uses the tested exact
`project.member.remove-and-rotate` command. Direct revocation removes the
project from the sidebar, switches to another authorized project or empty
selection, and clears decrypted chat, prompt/Yjs, context, presence, member,
usage, agent, task, artifact, and file-reference state before refreshing the
authoritative project list.

Files:

- `gui/src/cocodex-member-state.ts`
- `gui/src/pages/CoCodex.tsx`
- `gui/tests/cocodex-member-roster-ui.test.tsx`

## Commands and results

### CoCodex gate

Command:

```powershell
bun run test:cocodex
```

- Exit status: `0`
- Output: `119 pass`, `0 fail`, `1118 expect() calls`, 30 files
- Includes the three-process private-alpha process test and real TLS/WSS suites.

### GUI gate

Command:

```powershell
cd gui
bun test
```

- Exit status: `0`
- Output: `112 pass`, `0 fail`, `550 expect() calls`, 19 files

### Type checks

Command:

```powershell
bun run typecheck:cocodex
```

- Exit status: `0`
- Protocol, server, and root TypeScript checks completed without diagnostics.

### Production builds

Commands:

```powershell
bun run build:cocodex-client
bun run build:cocodex-server
cd gui
bun run build
```

- Exit status: `0` for all three
- Output includes compiled `dist/cocodex-client.exe`,
  `apps/cocodex-server/dist/cocodex-server.exe`, and the Vite production GUI.
- Vite reports only its existing large-chunk advisory.

### Privacy and lint

Commands:

```powershell
bun run privacy:scan
cd gui
bun run lint
```

- Exit status: `0` for both
- Privacy output: `Privacy scan passed`
- Lint output: `0 errors`, one pre-existing
  `react-hooks/exhaustive-deps` warning in `gui/src/use-app-route-state.ts`

### Whole upstream OpenCodex suite

Command:

```powershell
bun run test
```

- Exit status: `124`
- Result: harness timeout after 900 seconds while legacy OpenCodex tests were
  still progressing; no final suite summary was produced.
- This is **not** recorded as a pass or a product failure. The same upstream
  gate was already documented as load-sensitive and incomplete in
  `docs/evidence/private-alpha.md`.

## Review result

The requested architecture, security, and integration/test reviewers each
re-reviewed the repaired diff. Their final scoped result was no remaining P1
or P2 blocker. This evidence does not expand the implementation beyond the
private-alpha architecture or claim deferred production features.
