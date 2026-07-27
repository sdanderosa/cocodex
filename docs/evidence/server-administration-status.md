# Server administration status evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `0bf61ed307312d2f3ab05526ea75e27ae80cc9c1`
- Implementation commit: recorded by the commit containing this file
- Status: complete CoCodex, inherited OpenCodex, GUI, build, privacy, and
  focused real-process gates pass

## Behavior proved

The public liveness endpoint remains minimal. The authenticated administration
endpoint reports the running authority, one-port TLS/WSS endpoint, certificate
validity, live Client and agent-worker connections, active presence-project
count, and bounded SQLite integrity/storage/count aggregates.

The same database projection is available from the stopped Server's local
`status` command. Neither surface returns stored names, prompts, results,
private ciphertext, encrypted project envelopes, audit details, filesystem
paths, or the administration secret.

## Standalone Server and aggregate-canary evidence

```powershell
.\node_modules\.bin\bun.exe test `
  ./apps/cocodex-server/tests/process.test.ts `
  ./apps/cocodex-server/tests/cli-process.test.ts
```

Exit status `0`: `3 pass`, `0 fail`, `27 expect()` calls. The standalone
process test proves unauthenticated `401`, authenticated `200`, active epoch,
configured TLS/WSS endpoint, valid certificate, empty live connections,
healthy SQLite state, and absence of the admin token and state root. The
in-memory aggregate test plants `SECRET-` canaries in a device name, project
name, agent name, task prompt, private ciphertext, encrypted project event,
and audit details, then proves none enters the summary.

## Compiled three-process evidence

```powershell
.\node_modules\.bin\bun.exe test `
  ./tests/cocodex-private-alpha-process.test.ts
```

Exit status `0`: `1 pass`, `0 fail`, `290 expect()` calls. The harness builds
separate Server and Client executables, starts one Server plus isolated
Stephen and Kai Clients, and exercises the real TLS/WSS transport. Its live
administration assertion reports five authenticated sockets, two distinct
approved devices, three ready agent workers, one project, two memberships, and
three agents without returning the token or state path. The remainder of the
same harness completes bidirectional local agent execution, encrypted private
messaging, restart recovery, ordered queues, and offline local Codex.

## Static evidence

```powershell
.\node_modules\.bin\bun.exe run typecheck:cocodex
```

Exit status `0`.

## Complete CoCodex and inherited regression

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
.\node_modules\.bin\bun.exe run build:cocodex-server
.\node_modules\.bin\bun.exe run privacy:scan
.\node_modules\.bin\bun.exe run test:batched
```

Every command exited `0`:

- complete CoCodex: `157 pass`, `0 fail`, `1452 expect()` calls across 35
  files, including the 290-assertion compiled three-process phase;
- production Server executable: 368 modules bundled and compiled;
- privacy scan: passed;
- inherited OpenCodex: all 346 files completed across 14 fresh workers in
  isolated batches.

## GUI regression

```powershell
cd gui
..\node_modules\.bin\bun.exe test
..\node_modules\.bin\bun.exe run lint
..\node_modules\.bin\bun.exe run lint:i18n
..\node_modules\.bin\bun.exe run build
```

Every command exited `0`: `122 pass`, `0 fail`, `579 expect()` calls across 22
GUI test files; i18n lint and the TypeScript/Vite production build passed.
Standard lint reported zero errors and the existing unrelated
`use-app-route-state.ts` exhaustive-deps warning.

## Primary files

- `apps/cocodex-server/src/admin-status.ts`
- `apps/cocodex-server/src/server.ts`
- `apps/cocodex-server/src/cli.ts`
- `apps/cocodex-server/tests/process.test.ts`
- `apps/cocodex-server/tests/cli-process.test.ts`
- `tests/cocodex-private-alpha-process.test.ts`
- `docs/adr/0045-cocodex-server-administration-status.md`

## Honest limits

This checkpoint is the read-only status projection. Existing backup, restore,
authority transfer, device revocation, project lock, and lifecycle commands
remain separate. It does not claim that every long-term administration action
is available in a GUI, nor that logical SQLite bytes include WAL, backup, or
filesystem allocation.
