# Concurrent local-agent evidence

- Date: 2026-07-26
- Branch: `feat/cocodex-foundation`
- Commit: recorded by the commit containing this evidence
- Status: connected slice and complete CoCodex gate pass

## Behaviors proved

- A version-1 local policy migrates without overwrite into a bounded
  version-2 multi-agent store.
- One resident Stephen Client opens independent authenticated workers for
  Lucas and Angela.
- The Server acknowledges each strict agent-scoped ready lease.
- Angela's worker cannot submit a result for Lucas's task; Lucas's worker can.
- The real three-process harness starts one Server, one Stephen Client, and one
  Kai Client with isolated state.
- Kai dispatches Lucas and Angela simultaneously. A deterministic barrier
  observes both official-runtime fixture processes enter their distinct
  workspaces before either is released, proving real overlap rather than
  sequential completion.
- Both results stream through the shared authoritative chat path.
- After a Server restart, both Stephen workers and Kai's worker reconnect
  without reenrollment.

## Focused commands

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\tests\cocodex-agent-safety.test.ts `
  .\tests\cocodex-agent-bridge-recovery.test.ts `
  .\tests\cocodex-gui-bridge.test.ts
```

Exit status `0`: `16 pass`, `0 fail`, `125 expect()` calls.

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-project-encryption-session.test.ts
```

Exit status `0`: `2 pass`, `0 fail`, `38 expect()` calls.

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status `0`: `1 pass`, `0 fail`, `71 expect()` calls.

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\apps\cocodex-server\tests\collaboration-server.test.ts
```

Exit status `0`: `5 pass`, `0 fail`, `98 expect()` calls.

## Complete gate

```powershell
.\node_modules\.bin\bun.exe run test:cocodex -- --max-concurrency=1
```

Exit status `0`: `106 pass`, `0 fail`, `936 expect()` calls across 30 files.
The included private-alpha process test passed with `71` assertions.

The following also exited `0`:

- `bun run typecheck`
- `bun run typecheck:cocodex`
- `bun run build:cocodex-client`
- `bun run build:cocodex-server`
- `bun run build:gui`
- `bun run lint:gui`
- `bun run --cwd gui lint:i18n`
- `bun run privacy:scan`
- `git diff --check`

GUI lint reported the existing `use-app-route-state.ts:84`
`react-hooks/exhaustive-deps` warning and no errors. The GUI build reported its
existing bundle-size advisory and completed.

The inherited OpenCodex `bun run test` command was also attempted. It reached
the 600-second command ceiling after continuing through passing provider,
Claude, and CLI tests; no failing assertion appeared in the captured output.
Because the command did not finish, this document does not claim a fresh green
inherited-suite gate. No Bun process or high-port test listener remained after
the timeout. The repository's earlier chunked upstream audit remains the
available baseline.

## Files

- `src/cocodex/agent-policy.ts`
- `src/cocodex/agent-runtime-paths.ts`
- `src/cocodex/agent-safety.ts`
- `src/cocodex/agent-bridge.ts`
- `src/cocodex/session.ts`
- `src/cocodex/cli.ts`
- `src/cocodex/gui-bridge.ts`
- `apps/cocodex-server/src/agent-routing.ts`
- `apps/cocodex-server/src/server.ts`
- `packages/cocodex-protocol/src/collaboration.ts`
- `gui/src/pages/CoCodex.tsx`
- the focused tests named above

This fixture proves process isolation, routing, overlap, streaming, and local
usage attribution. It does not prove billing against two independently
authenticated real OpenAI accounts.
