# CoCodex Server verified update-check evidence

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Decision: ADR 0053
- Mutation boundary: external checksum-covered `Install-CoCodex.ps1 -Action Update`

## Implemented flow

`cocodex-server update-check --bundle DIRECTORY`:

- accepts only Windows and the installed scoped-package layout;
- rejects source checkouts and standalone test artifacts as update targets;
- accepts only an ordinary, non-redirected bundle directory;
- bounds and verifies `SHA256SUMS.txt`, `RELEASE.json`, the package archive, and `Install-CoCodex.ps1`;
- rejects path traversal, duplicate checksum rows, missing coverage, tampering, wrong package identity, and inconsistent installer results;
- invokes PowerShell directly with argv and no shell;
- runs the installer's read-only `Check` action before any root-manifest or npm mutation;
- reports direct Server PID, optional service state, blockers, exact installed prefix, current/target versions, source commit, archive digest, and preserved state roots; and
- returns the exact external `Update` argv without executing it.

This flow performs no download, registry query, PATH update, process stop, Server-state write, or port-10100 operation.

## Focused verification

Commands:

```powershell
.\node_modules\.bin\bun.exe test .\apps\cocodex-server\tests\server-update.test.ts .\tests\cocodex-private-alpha-package.test.ts
.\node_modules\.bin\tsc.exe -p apps/cocodex-server/tsconfig.json --noEmit
.\node_modules\.bin\tsc.exe --noEmit
```

Current result:

```text
14 passed
0 failed
526 expect() calls
Server/root TypeScript: passed
```

Covered behavior includes all three release-input digest checks, four tamper classes, wrong identity, traversal and duplicate rows, exact prefix derivation, source-checkout rejection, direct PID and SCM blockers, unknown-state fail-closure, preserved-state disclosure, shell-free argv, inconsistent installer rejection, non-Windows rejection, and side-effect-free CLI help.

## Remaining clean-package acceptance

Before marking the update UX fully proven, build a newer clean-commit bundle, install the prior bundle into an isolated prefix, run `update-check`, apply the reported `Update` command with all test processes stopped, and verify:

- the target package version/source manifest and locked dependency tree;
- installed Client, Server, and compatibility commands;
- standalone Server init/start/restart/stop;
- optional service assets remain repairable without credential replacement;
- Client, Server, OpenCodex, and Codex state canaries survive; and
- the foreign home listener on port 10100 is unchanged.

## Runtime and Server-suite evidence

The complete standalone Server suite passed:

```text
88 pass
0 fail
936 expect() calls
19 files
```

A real Windows PowerShell `Check` smoke used the existing valid package archive, current installer, and freshly recomputed bundle checksums in a temporary directory. It returned:

```text
verified: true
packageName: @sdanderosa/cocodex
version: 0.1.0-alpha.1
Node: 24.18.0
npm: 11.16.0
blockingProcesses: []
readyForUpdate: true
```

The nonexistent validation prefix remained absent after `Check`, proving the action did not write install metadata or invoke npm. The temporary bundle was removed.
Maintained `test:cocodex` result:

```text
203 pass
0 fail
2181 expect() calls
39 files
```

## Complete regression and cleanup-leak repair

The final complete repository suite passed:

```text
4265 pass
4 skip
0 fail
21713 expect() calls
359 files
```

The first two full-suite attempts exposed separate Windows-only `EBUSY` cleanup failures after all product assertions had completed in `cocodex-device-revocation-session.test.ts` and `cocodex-project-encryption-session.test.ts`. Their prior cleanup retry windows were 20 seconds and 5 seconds respectively. Both now retain the original strict product event deadlines while allowing up to 30 seconds for Windows temp-directory locks, under a 45-second cleanup hook.

Each repaired process case passed in four parallel isolated processes. The subsequent complete 4,269-test run passed under full concurrency.
Final non-package gates:

```text
GUI: 142 pass, 0 fail, 661 assertions; production build passed
GUI lint: 0 errors, one pre-existing exhaustive-deps warning
Tauri Rust: 2 pass, 0 fail
Clippy -D warnings: passed
Privacy scan: passed
```
