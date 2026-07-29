# Trusted-device enrollment approval evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `50f866ce023d20a8fc9612ece3b14986ce176c78`
- Implementation commit: `359bcf7f772f131dd6929766cb03d6878d116fdd`
- Evidence commit: recorded by the commit containing this file
- Status: focused approval, complete CoCodex, real three-process, GUI, build,
  privacy, and inherited regression gates pass

## Behaviors proved

- Only Stephen's first device can use the local one-shot bootstrap operation.
  The durable marker remains consumed after revocation.
- Kai's invitation is consumed during proof-of-possession enrollment and the
  resulting pending record expires after 15 minutes.
- The immutable enrollment digest binds the pinned TLS endpoint, stable Server
  identity, invitation commitment and expiry, target ID/name/fingerprint,
  complete Ed25519/X25519 public-key bundle, timestamps, and revision.
- Stephen's authenticated resident Client recomputes that attestation, exposes
  only safe identity fields and a 16-word comparison phrase to the GUI, and
  signs the decision locally.
- The signed operation binds the target attestation, decision, Server epoch,
  validity window, operation ID, revision, and a 32-byte nonce.
- The Server rechecks current approved actor and target state inside one
  immediate SQLite transaction. Decision history, device transition,
  approver, revision, and audit evidence commit together.
- Exact retry is idempotent. Tampering, self-approval, stale authority,
  expired pending enrollment, concurrent decisions, and altered replay fail
  closed.
- The renderer never receives enrollment public keys, invitation token hashes,
  enrollment digests, signatures, or nonces and cannot supply any of those
  fields in an approval command.
- Existing approved devices reconnect without enrollment repetition. Local
  OpenCodex behavior remains independent of Server availability.

## Focused approval evidence

```powershell
.\node_modules\.bin\bun.exe run test:cocodex-approval
```

Exit status `0`: `27 pass`, `0 fail`, `273 expect()` calls across protocol,
authoritative Server, and GUI bridge tests.

The focused tests cover transcript binding, 64-bit comparison-phrase shape,
atomic exact replay, tamper rejection, permanent bootstrap consumption, and
renderer redaction/command allowlisting.

## Real three-process evidence

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status `0`: `1 pass`, `0 fail`, `273 expect()` calls.

The harness builds and launches one standalone Server executable and isolated
Stephen and Kai Client executables with separate state, identities, databases,
accounts, workspaces, and a real TLS/WSS transport. It now:

1. enrolls and one-shot bootstraps Stephen;
2. starts Stephen's authenticated resident Client;
3. enrolls Kai as pending;
4. observes Kai's safe phrase/fingerprint projection in Stephen's process;
5. sends Stephen's resident-signed approval over WSS;
6. starts Kai only after authoritative approval; and
7. completes the existing bidirectional remote-agent, ordered shared chat,
   ciphertext-only private message, offline queue, and Server restart path.

The harness asserts that the Stephen-visible pending event contains no public
key PEM, enrollment digest, invitation token hash, or signature.

## Complete CoCodex regression

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status `0`: `156 pass`, `0 fail`, `1434 expect()` calls across 35 files.
This includes real TLS/WSS collaboration, encrypted project sessions,
revocation recovery, authority transfer, local execution recovery, private
messaging, offline queues, and the three-process private-alpha path.

```powershell
.\node_modules\.bin\bun.exe run --cwd gui test
```

Exit status `0`: `118 pass`, `0 fail`, `573 expect()` calls across 21 files.

```powershell
.\node_modules\.bin\bun.exe run test:batched
```

Exit status `0`: all `346` inherited test files completed across 14 fresh
workers. An initial run reached the final worker with passing output but the
outer command wrapper expired at 300 seconds, so it was not counted. The clean
rerun used a 600-second bound, completed in approximately 334 seconds, and
printed the final success marker.

## Build and static evidence

The following commands exited `0`:

- `bun run typecheck`
- `bun run typecheck:cocodex`
- `bun run build:cocodex-client`
- `bun run build:cocodex-server`
- `bun run build:gui`
- `bun run lint:gui` (one pre-existing hook dependency warning, zero errors)
- `bun run privacy:scan`
- `git diff --check`

The GUI build emitted its existing bundle-size advisory and completed.

## Process and network evidence

- The three-process harness exercised the real compiled executables and actual
  TLS/WSS enrollment/approval transport, not direct protocol function calls.
- The authoritative WSS suites exercised signed multi-device fixtures against
  the same production approval service.
- After the timed-out inherited wrapper and again after the successful rerun,
  process and listener inspection found no CoCodex, OpenCodex, or Bun test
  worker left running and no test listener in the inspected port range.

## Primary files

- `docs/adr/0042-cocodex-signed-device-enrollment-approval.md`
- `packages/cocodex-protocol/src/device-approval.ts`
- `apps/cocodex-server/src/device-approvals.ts`
- `apps/cocodex-server/src/enrollment.ts`
- `apps/cocodex-server/src/migrations.ts`
- `apps/cocodex-server/src/server.ts`
- `src/cocodex/client.ts`
- `src/cocodex/session.ts`
- `src/cocodex/gui-bridge.ts`
- `gui/src/pages/CoCodex.tsx`
- `tests/cocodex-private-alpha-process.test.ts`
- `apps/cocodex-server/tests/device-approvals.test.ts`
- `packages/cocodex-protocol/tests/protocol.test.ts`
- `tests/cocodex-gui-bridge.test.ts`

## Explicit limits

- The comparison phrase is an out-of-band review aid; the full 256-bit
  cryptographic fingerprint remains identity.
- A compromised approved device can authorize another device. Administrative
  revocation and per-project removal/key rotation remain required incident
  responses.
- Automatic NAT traversal, relay infrastructure, multi-device ratchets,
  remote desktop, and other later product requirements are not claimed by
  this slice.
