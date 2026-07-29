# Inherited OpenCodex suite and finite CLI lifecycle evidence

- Date: 2026-07-26
- Branch: `feat/cocodex-foundation`
- Implementation commit: `a93da8d4ae0321c11ca36b1e459c6328ee608c77`
- Scope: complete inherited root suite, finite CLI lifecycle, and unchanged
  private-alpha gates

## Completion claim

The complete inherited OpenCodex test inventory passes on Windows without
disabling or omitting a test file. The checked-in runner recursively enumerates
all 339 `tests/**/*.test.ts` files and executes each exactly once in a fresh
isolated Bun test process. It replaces long-lived Windows parent processes
after 25 files and fails closed on any file or worker timeout.

The underlying lifecycle repair is also a product fix:

- `status`, `provider`, and `models` terminate explicitly after finite work;
- model add/remove operations are awaited before exit; and
- live catalog sync after model mutation has a five-second upper bound;
- test homes remain disposable and separate from the user's real OpenCodex and
  Codex state;
- owned process trees are terminated before timed-out test state is removed;
  and
- ambient provider credentials and authenticated proxy settings are excluded
  from test-child environments.

Files:

- `src/cli/index.ts`
- `src/cli/models.ts`
- `scripts/test.ts`
- `scripts/test-batched.ts`
- `tests/cli-models.test.ts`
- `tests/test-runner.test.ts`
- `package.json`
- ADR 0032

## Complete inherited suite

Command:

```powershell
.\node_modules\.bin\bun.exe run test:batched
```

Exit status: `0`.

Aggregate evidence:

- 339 of 339 recursively discovered test files executed;
- 14 of 14 fresh workers passed;
- 4,161 tests passed;
- 0 tests failed;
- 20,703 `expect()` calls;
- 4 existing platform skips.

The skips are the existing symlink test plus SIGINT, SIGTERM, and SIGHUP
launcher tests, which exercise facilities unavailable on Windows. No CoCodex,
private-alpha, privacy, or security test is skipped.

The final output was:

```text
[test:batched] PASS: all 339 files completed across 14 fresh workers
```

## Finite CLI stress verification

Command, run once and then repeated twice:

```powershell
.\node_modules\.bin\bun.exe test --timeout 120000 `
  .\tests\cli-help.test.ts `
  .\tests\cli-models.test.ts `
  .\tests\cli-provider.test.ts
```

Each run exited `0` with `48 pass`, `0 fail`, and `217 expect()` calls. Across
the three consecutive runs, all 144 test executions passed. This covers
repeated status diagnostics, model listing, provider reads, provider mutations,
JSON output, argument rejection, and explicit sync behavior.

## CoCodex and GUI gates

Command:

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status: `0`; result: `119 pass`, `0 fail`, `1118 expect()` calls across
30 files. It includes the real Server plus resident Stephen and Kai Client
processes, reciprocal local execution, encrypted private delivery, offline
queues, restart recovery, server transfer, atomic member removal/key rotation,
and real TLS/WSS storage/routing tests.

Command:

```powershell
cd gui
..\node_modules\.bin\bun.exe test
```

Exit status: `0`; result: `112 pass`, `0 fail`, `550 expect()` calls across
19 files.

## Static, build, privacy, and lint gates

The following commands each exited `0`:

```powershell
.\node_modules\.bin\bun.exe run typecheck:cocodex
.\node_modules\.bin\bun.exe run build:cocodex-client
.\node_modules\.bin\bun.exe run build:cocodex-server
.\node_modules\.bin\bun.exe run privacy:scan
cd gui
..\node_modules\.bin\bun.exe run lint
..\node_modules\.bin\bun.exe run build
```

Evidence:

- protocol, Server, and root TypeScript checks completed without diagnostics;
- separate Client and Server executables compiled;
- the privacy scan printed `Privacy scan passed`;
- GUI lint reported zero errors and the existing
  `use-app-route-state.ts:84` hook warning;
- the production GUI built successfully with only its existing chunk-size
  advisory.

## Honest release status

This closes the previously open inherited-suite evidence gate. It does not
claim the entire long-term CoCodex product vision is complete. A live acceptance
run using two separately authenticated human Codex accounts remains required
before a private-alpha release, and later requirements such as production
ratcheted multi-device messaging, relay/libp2p traversal, and cross-platform
installers remain explicitly deferred.
