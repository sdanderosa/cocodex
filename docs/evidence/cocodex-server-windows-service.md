# Optional CoCodex Server Windows service evidence

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Decision: ADR 0052
- Service id: `cocodex-server`
- OpenCodex service/proxy coupling: none

## Implemented boundary

The standalone Server CLI now owns:

```text
cocodex-server service install
cocodex-server service start
cocodex-server service stop
cocodex-server service status
cocodex-server service uninstall
```

The implementation uses a separately named, SHA-256-pinned WinSW 2.12.0
binary below the selected Server state root. XML contains no password, selects
the current Windows domain/user, requests automatic delayed startup, restarts
after bounded failure, and launches only the standalone Server entrypoint with
an absolute `--state-root`.

Installation proves configuration plus Server-authority and TLS private keys
are readable through the current user's DPAPI custody before registration. It
then verifies SCM binary path, account, and automatic startup, starts the
service, and requires the Server's TLS `/healthz` response plus PID ownership.
It does not invoke `ocx`, the OpenCodex service manager, or port 10100.

Unknown SCM state, another registered state root, built-in/different service
identity, direct Server PID ownership, missing assets on start, and failed
readiness all fail closed. Fresh-install failure attempts stop and unregister.
Existing-service repair snapshots the prior XML and restores its prior running
state when the replacement fails. Any rollback failure is included in the
reported error. Stop and uninstall target only the distinct SCM registration;
Server state and retained service assets are preserved.

## Focused verification

Command:

```powershell
.\node_modules\.bin\bun.exe test .\apps\cocodex-server\tests\windows-service.test.ts
```

Result:

```text
17 pass
0 fail
69 expect() calls
```

Covered regressions:

- distinct service id and no OpenCodex/10100 coupling;
- same-user WinSW XML with no password or LocalSystem;
- automatic delayed startup/restart configuration;
- XML/path escaping;
- pinned binary hash rejection;
- WinSW and SCM state parsing;
- error-1060-only absence proof;
- unknown SCM fail closure;
- mismatched state-root rejection;
- fresh install credential prompt/start/readiness flow;
- fresh readiness rollback;
- occupied-port owner remains alive;
- stopped-service recovery;
- direct PID refusal;
- state-preserving uninstall;
- prior XML/running-state restoration after repair failure; and
- explicit reporting when rollback itself fails.

Focused TypeScript command:

```powershell
.\node_modules\.bin\tsc.exe -p apps/cocodex-server/tsconfig.json --noEmit
```

Result: exit 0.

## Remaining release evidence

No live SCM registration was created on the user's PC in this implementation
pass because service installation prompts for Windows credentials/UAC and is an
explicit operator action. Before claiming packaged service acceptance, install
the freshly built package into an isolated validation root, initialize an
isolated Server on a non-10100 test port, perform the live service lifecycle,
record `sc.exe qc cocodex-server`, TLS health, PID/port ownership, restart
behavior, stopped recovery, and state-preserving uninstall, then remove only
that isolated registration. The separate verified Server update UX also
remains a product gap.


## Broader regression evidence

Final standalone Server aggregate:

```text
80 pass
0 fail
904 expect() calls
18 files
```

The maintained CoCodex gate passed before the final identity tightening:

```text
194 pass
0 fail
2139 expect() calls
38 files
```

The final complete repository pass, which includes the tightened service tests,
all CoCodex suites, inherited OpenCodex tests, and the compiled Tauri sidecar,
passed:

```text
4265 pass
4 skip
0 fail
21702 expect() calls
359 files
```

CoCodex-wide typechecking, root typechecking, standalone Server compilation,
and the privacy scan all exited 0. The compiled Server executable then ran
`service --help` and `service status` against a nonexistent isolated root.
It reported `state: "nonexistent"`, `installed: false`, and did not create
that root.

The first complete repository attempt exposed one unrelated but real
concurrency defect in `tests/tauri-sidecar-process.test.ts`: an unbounded
health/API fetch consumed the 30-second budget. The sidecar itself passed alone.
The test now bounds health requests to one second, API requests to five seconds,
and gives compilation/process setup bounded concurrency headroom. It passed
three consecutive fresh-build process runs and then passed in the final full
4,269-test run.

A read-only network check after implementation still showed the pre-existing
foreign OpenCodex listener on `127.0.0.1:10100` owned by PID 3704 at:

```text
C:\Users\Stephen\AppData\Roaming\npm\node_modules\@bitkyc08\opencodex\node_modules\bun\bin\bun.exe
```

It was neither stopped nor adopted.


## Final non-Bun release gates

The complete GUI gate initially exposed a Windows-only test defect:
`cocodex-scope-state.test.ts` searched LF source text while the current
`CoCodex.tsx` is CRLF. The project/chat reset invariant remained present.
The test now normalizes line endings before structural assertions.

Final GUI results:

```text
142 pass
0 fail
661 expect() calls
29 files
production build: passed
lint: 0 errors, 1 pre-existing exhaustive-deps warning
```

The remaining final gates passed:

```text
Tauri Rust: 2 passed, 0 failed
Clippy: passed with -D warnings
Privacy scan: passed
git diff --check: passed
```

The known lint warning remains
`gui/src/use-app-route-state.ts:84` for `applyHashAction`; it predates this
slice and is not represented as fixed.


## Clean-commit installed-package evidence

The feature commit used for package validation is:

```text
commit: a5e84476ad5e94cf00d1b838c45471c09ac62bea
tree:   d5de11bf2bc29779554a891084c17ebd0fbb339f
```

The strict clean-tree builder produced:

```text
archive: sdanderosa-cocodex-0.1.0-alpha.1.tgz
SHA-256: 09dd139701900f2616f4eb310653e6a5fcc0c22dd4f3ee3d4497903313aa3c9c
```

The archive contains `bin/ccx-server.mjs` and
`apps/cocodex-server/src/windows-service.ts`. A raw npm dependency install
was intentionally rejected by the installed-tree verifier when npm ignored
nested package overrides and selected an unlocked transitive dependency. The
temporary prefix was cleaned; no drift was accepted.

The authoritative `Install-CoCodex.ps1` path then wrote the root override
contract, installed and verified all 126 locked dependencies with Node
24.18.0/npm 11.16.0, and passed the installed lifecycle verifier:

```text
local runtime: port 53470, service opencodex, GUI HTTP 200
standalone Server: port 53496
initial Server PID: 32872
restarted Server PID: 34344
stopped status: true
state-preserving uninstall: passed
temporary prefix removed: true
```

That first installed-verifier attempt also exposed that verifier-owned
`ocx stop` consulted the user's real service metadata. The verifier now
retains the exact launcher subprocess and applies bounded SIGTERM/SIGKILL only
to that owned process. Its source-contract test forbids global
`run(ocx, ["stop"])`. The successful installed pass above ran with the
user's foreign home service still present and did not stop it.


The final post-verifier complete repository rerun passed 4,265 tests with 4 skips, 0 failures, and 21,704 expectations across 359 files.
