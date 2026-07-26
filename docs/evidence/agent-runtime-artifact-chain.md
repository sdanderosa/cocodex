# Agent runtime and artifact-chain evidence

- Date: 2026-07-26
- Branch: `feat/cocodex-foundation`
- Commit: recorded by the commit containing this evidence
- Status: focused gates and real three-process private-alpha path pass

## Behaviors proved

- Lucas, Angela, and Sue have signed, server-authoritative primary model and
  reasoning-effort settings.
- Lucas's official runtime is numerically bounded to three concurrent child
  threads and receives Luna/medium spawn guidance; the fixture does not spawn a
  child and therefore does not claim that model/effort guidance is enforced.
  Angela and Sue are configured with a one-thread runtime limit.
- Model identifiers reject argument, config, and prompt delimiters.
- Server migration 22 gives legacy definitions explicit compatible defaults.
- Worker readiness repeats the complete runtime definition and is rejected
  when it differs from the immutable server registration.
- The local Client invokes official Codex shell-free with the configured model,
  effort, catalog-selected multi-agent generation, explicit feature mode, and
  thread limit.
- Local definitions cannot exceed a 16-thread aggregate device budget.
- Sue's full-computer profile remains disabled until Kai sends a separate
  explicit local confirmation. The fixture then observes the real
  `danger-full-access` argument.
- One real Server process and isolated Stephen and Kai Client processes route
  an encrypted dependency chain over TLS/WSS. The target device publishes
  task-linked fixture artifacts while each predecessor is running; dependent
  workers remain undispatched until prerequisites complete. This proves
  authority, ordering, provenance, and artifact delivery, not autonomous
  semantic artifact generation by the fixture agent.
- Task rows retain the authoritative dependency and input-artifact IDs.
- Requester-encrypted task plaintext independently binds those routing IDs and
  the private-share ID, so a server cannot substitute them.
- Task-linked artifacts are accepted only from the task's target device, and
  artifact markup delimiters are escaped before prompt composition.
- Both local accounts report their own usage.
- Both resident clients reconnect after a Server restart, flush offline chat
  and private-message queues, and recover encrypted task results.

## Focused commands

```powershell
.\node_modules\bun\bin\bun.exe run typecheck:cocodex
```

Exit status `0`.

```powershell
.\node_modules\bun\bin\bun.exe test `
  .\tests\cocodex-codex-agent-adapter.test.ts `
  .\tests\cocodex-agent-safety.test.ts `
  .\tests\cocodex-agent-safety-cli.test.ts
```

Exit status `0`: `9 pass`, `0 fail`, `59 expect()` calls.

```powershell
packages\cocodex-protocol:
  ..\..\node_modules\bun\bin\bun.exe test tests\protocol.test.ts
```

Exit status `0`: the focused run passed before the final model-delimiter
assertion was added. The complete gate below includes that assertion.

```powershell
apps\cocodex-server:
  ..\..\node_modules\bun\bin\bun.exe test `
    tests\database-migration.test.ts `
    tests\agent-routing.test.ts `
    tests\collaboration-server.test.ts
```

Exit status `0`: `11 pass`, `0 fail`, `166 expect()` calls.

```powershell
$env:COCODEX_TEST_TRACE='1'
.\node_modules\bun\bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status `0`: the final complete gate run passed this harness with
`1 pass`, `0 fail`, `241 expect()` calls in `12.53s`.
The trace reached every checkpoint through
`Lucas to Angela to Sue artifact chain completed`, offline queue acceptance,
client reconnection, recovered snapshots, and clean process shutdown.

The following also exited `0`:

- `bun run test:cocodex -- --max-concurrency=1`: `110 pass`, `0 fail`,
  `967 expect()` calls across 30 files; the included private-alpha harness
  passed with `241` assertions.
- `bun run typecheck`
- `bun run typecheck:cocodex`
- `bun run build:cocodex-client`
- `bun run build:cocodex-server`
- `bun run build:gui`
- `bun run lint:gui` (one existing hook warning, zero errors)
- `bun run --cwd gui lint:i18n`
- `bun run privacy:scan`
- `git diff --check`

The GUI build emitted its existing bundle-size advisory and completed.

## Files

- `docs/adr/0027-cocodex-agent-runtime-configuration.md`
- `packages/cocodex-protocol/src/collaboration.ts`
- `packages/cocodex-protocol/src/agent-signing.ts`
- `apps/cocodex-server/src/migrations.ts`
- `apps/cocodex-server/src/agent-routing.ts`
- `src/cocodex/agent-policy.ts`
- `src/cocodex/model-multi-agent-version.ts`
- `src/cocodex/agent-bridge.ts`
- `src/cocodex/codex-agent-adapter.ts`
- `src/cocodex/session.ts`
- `src/cocodex/cli.ts`
- `src/cocodex/gui-bridge.ts`
- `gui/src/pages/CoCodex.tsx`
- `tests/cocodex-private-alpha-process.test.ts`
- `tests/fixtures/codex-runtime-fixture.ts`
- `apps/cocodex-server/src/artifacts.ts`
- `apps/cocodex-server/src/encrypted-artifacts.ts`

The compiled Codex fixture proves process boundaries, exact invocation policy,
artifact/dependency routing, streaming, and per-device usage attribution. It
does not claim billing against two independently authenticated live OpenAI
accounts.
