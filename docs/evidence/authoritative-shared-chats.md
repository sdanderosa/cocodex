# Authoritative shared-chat evidence

- Evidence date: 2026-07-27
- Implementation commit: `3bf90fe9`
- Branch: `feat/cocodex-foundation`
- Platform: Windows
- Status: shared-chat slice passes; overall release gate remains incomplete

## Delivered boundary

This slice replaces the single implicit project conversation with
server-authoritative shared chats. Every encrypted message, prompt update,
context revision, task, execution report, agent result, artifact, and local
file reference is bound to a `(projectId, chatId)` scope.

The deterministic General chat keeps existing projects compatible. New chats
use signed, expiring creation requests and Server-assigned metadata. Version-2
content envelopes bind the chat ID into both XChaCha20-Poly1305 associated data
and Ed25519 signing transcripts. Version-1 records can be read only from
General and cannot be transplanted into another chat.

The GUI can list, create, and switch shared chats. Selection clears and reloads
chat-scoped state rather than projecting another chat's prompt, messages,
tasks, artifacts, file references, context, or presence.

## Focused protocol, storage, transport, and recovery tests

Command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\collaboration-server.test.ts `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\apps\cocodex-server\tests\project-encryption-server.test.ts `
  .\apps\cocodex-server\tests\project-encryption-storage.test.ts `
  .\tests\cocodex-outbox.test.ts `
  .\tests\cocodex-agent-bridge-recovery.test.ts `
  .\tests\cocodex-project-encryption.test.ts `
  .\tests\cocodex-private-alpha-process.test.ts `
  --timeout 120000
```

The first post-recovery run found one stale plaintext-task fixture. After the
fixture was corrected, its focused regression command passed:

```text
8 pass
0 fail
27 expect() calls
Ran 8 tests across 1 file.  (exit 0)
```

The client lifetime regression and complete private-alpha process path were
then run together:

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-client.test.ts `
  .\tests\cocodex-private-alpha-process.test.ts `
  --timeout 120000
```

```text
6 pass
0 fail
282 expect() calls
Ran 6 tests across 2 files.  (exit 0)
```

The three-process test starts one real headless CoCodex Server and two isolated
resident Clients using separate temporary identities, databases, account
fixtures, and workspaces. It proves bidirectional local-agent execution,
ciphertext-only private delivery, authoritative shared results, server
restart, ordered queued-event recovery, and resident-client restart.

## Complete CoCodex gate

Command:

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Relevant output:

```text
143 pass
0 fail
1377 expect() calls
Ran 143 tests across 33 files.  (exit 0)
```

The run includes real TLS/WSS chat creation and isolated recovery, migration
from supported historical schemas, cross-chat encrypted-dispatch rejection,
cross-chat ciphertext transplant rejection, dependency and artifact
validation, offline queue ordering, and the three-process private-alpha path.

## Type, build, GUI, and privacy gates

```text
typecheck:cocodex       exit 0
build:cocodex-client   exit 0; dist/cocodex-client.exe
build:cocodex-server   exit 0; apps/cocodex-server/dist/cocodex-server.exe
lint:gui               exit 0; one pre-existing use-app-route-state warning
build:gui              exit 0; production Vite bundle built
privacy:scan           exit 0; Privacy scan passed
git diff --check       exit 0
```

The production GUI build reported only the existing chunk-size advisory. No
dependency was added by this slice.

## Inherited OpenCodex suite

Command:

```powershell
.\node_modules\.bin\bun.exe run test
```

The suite continued advancing through upstream proxy, Claude, and CLI tests
without a captured failing assertion, but the command exceeded the
900-second execution ceiling:

```text
exit 124
command timed out after 900350 milliseconds
```

No `bun` or `opencodex` process and no listener in the test port range remained
after the timeout. This command is not reported as passing. Because the
inherited suite did not complete, the overall product release gate remains
incomplete even though the focused and complete CoCodex gates pass.

## Security and review findings resolved

- Plaintext request and Server dispatch transcripts now bind the exact chat.
- The local execution report is validated against the persisted task chat.
- A caller cannot re-route a signed request through a different queue chat.
- Cross-chat encrypted dispatch substitution is rejected before decryption.
- Re-signing ciphertext after changing its chat metadata still fails AEAD.
- Agent task projections expose and filter by the Server-authoritative chat.
- Task issuance and expiry derive from one clock sample, avoiding an
  intermittent 300,001 ms lifetime rejection at the five-minute boundary.
- Windows private mailbox and history persistence use the repository's atomic
  rename helper, avoiding transient reconnect-time `EPERM` failures.

## Principal files

- `docs/adr/0039-cocodex-authoritative-shared-chats.md`
- `packages/cocodex-protocol/src/shared-chat.ts`
- `packages/cocodex-protocol/src/project-encryption.ts`
- `packages/cocodex-protocol/src/agent-signing.ts`
- `apps/cocodex-server/src/shared-chats.ts`
- `apps/cocodex-server/src/migrations.ts`
- `apps/cocodex-server/src/server.ts`
- `apps/cocodex-server/src/encrypted-*.ts`
- `src/cocodex/client.ts`
- `src/cocodex/session.ts`
- `src/cocodex/agent-bridge.ts`
- `src/cocodex/project-encryption.ts`
- `src/cocodex/gui-bridge.ts`
- `gui/src/pages/CoCodex.tsx`
- `apps/cocodex-server/tests/*.test.ts`
- `packages/cocodex-protocol/tests/protocol.test.ts`
- `tests/cocodex-*.test.ts`

