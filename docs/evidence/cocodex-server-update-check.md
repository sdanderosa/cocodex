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

## Clean-package update acceptance

Clean commit `d77dec10c9b6b54f836b34efd470a113cf88ae6b` produced a new private-alpha bundle. The authoritative installer installed it into an isolated prefix, and the acceptance pass verified:

- the target package version/source manifest and locked dependency tree;
- installed Client, Server, and compatibility commands;
- standalone Server init/start/restart/stop;
- optional service assets remain repairable without credential replacement;
- Client, Server, OpenCodex, and Codex state canaries survive; and
- the foreign home listener on port 10100 is unchanged.

The installed `cocodex-server update-check` independently verified the bundle,
derived the exact isolated application prefix, reported no direct/SCM/process
blocker, and returned `readiness.ready: true`. Its exact reported System32
Windows PowerShell argv was executed externally with `-Action Update`. The update
completed successfully, all four canaries survived both update and uninstall,
and the installed package was removed without removing those state roots.

The immediate post-update verifier proved all 126 locked dependencies, the
installed launchers, local OpenCodex health and GUI, and Server
init/start/restart/stop. One initial post-install verifier attempt saw a
replacement Server exit during restart; three consecutive fresh verifier runs
and the immediate post-update verifier then passed. No owned process remained
after the failed attempt. This transient is recorded rather than omitted.

Fresh bundle files:

    archive  10,214,980 bytes  0150496bf85873b152a0bbb201f90226592d6968a1f2f00c7104076401d3e31f
    installer    23,386 bytes  aec4cd68de1f293fc887337be9f12e936a195788a5753d4d4a5e30ede4363c8b
    release         873 bytes  e9e1d3ac480f923c3d221d37d3643417f99200dc7c5ba3b03bdde2faa88b5882
    checksums       268 bytes  4fc11db9e64a4e837bc7d10e273ccff31fc1b1c70922bf4ee32ba5a39f08900f

Foreign PID 3704 remained the user-installed OpenCodex Bun executable and
continued owning 127.0.0.1:10100 throughout.

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
