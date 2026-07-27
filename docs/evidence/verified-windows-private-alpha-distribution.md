# Verified Windows private-alpha distribution evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `1c323a20`
- Implementation commit: recorded by the commit containing this file
- Status: hardened source gates passed; the operator artifact is accepted only
  after the clean-commit build and exact installed lifecycle both pass

## Artifact under test

The local release builder produced:

```text
dist/private-alpha/0.1.0-alpha.1/
  Install-CoCodex.ps1
  RELEASE.json
  SHA256SUMS.txt
  sdanderosa-cocodex-0.1.0-alpha.1.tgz
```

The earlier development archive was intentionally invalidated by the
distribution security review. No pre-commit digest is an operator artifact.
The final clean-commit archive records its own SHA-256, source commit/tree, GUI
digest, and dependency-lock digest in the same manually approved GitHub
artifact. Operators must use those values from that downloaded bundle.

## Focused package tests

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-private-alpha-package.test.ts `
  .\tests\update-job.test.ts `
  .\apps\cocodex-server\tests\cli-process.test.ts
```

Exit status `0`: 29 focused tests, 0 failures in the independent distribution
review, followed by 6 package-security tests with 482 assertions after the
review repairs. The package tests prove the CoCodex package name, command
manifest, unchanged runtime dependencies, required release inputs,
checksum-before-install ordering, real PowerShell tamper rejection, and the
CoCodex-to-upstream update gate. The process tests prove a health-verified real
Server restart and cleanup after failed listener startup.

The complete hardened CoCodex suite subsequently passed with 172 tests, 0
failures, and 1,996 assertions. That run includes the real three-process
Stephen/Kai private-alpha recovery test.

## Exact installer with standard npm

An isolated npm 11.6.2 runtime and Node 24.14.0 installed the earlier exact
development archive into
a repository-local temporary prefix:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\dist\private-alpha\0.1.0-alpha.1\Install-CoCodex.ps1 `
  -Action Install `
  -PackagePath .\dist\private-alpha\0.1.0-alpha.1\sdanderosa-cocodex-0.1.0-alpha.1.tgz `
  -ChecksumPath .\dist\private-alpha\0.1.0-alpha.1\SHA256SUMS.txt `
  -NpmPrefix .\tmp\private-alpha-npm-install `
  -SkipPathUpdate
```

Exit status `0` for the pre-review archive. npm added 126 packages and all five
commands passed. The hardened follow-up additionally rejects a wrong
checksum-valid package before npm, pins the complete npm dependency graph, and
requires exact installed package/lock identity. The release workflow repeats
the exact installed lifecycle on both the minimum supported Node 22.12 runtime
with npm 10 and current Node 24. An artifact is not operator-ready unless that
workflow or the equivalent local clean-commit lifecycle succeeds.

## Installed Client and inherited runtime

The installed `cocodex --help`, `cocodex-server --help`, and `ocx --version`
commands exited `0`. `ocx update` exited `1` before any upstream update and
reported that `@sdanderosa/cocodex` is not connected to the
`@bitkyc08/opencodex` release feed.

With isolated `OPENCODEX_HOME` and `CODEX_HOME`, the installed `ocx start`
command served:

```text
GET http://127.0.0.1:54247/healthz
200 {"status":"ok","service":"opencodex","version":"0.1.0-alpha.1",...}

GET http://127.0.0.1:54247/
200 (961-byte GUI entry document)
```

The runtime was stopped through the installed command without touching the
user's real OpenCodex or Codex state.

## Installed Server lifecycle

The installed Server initialized an isolated state root and listened on one
reserved TLS port. Runtime evidence:

```text
initial PID: 41664
GET https://127.0.0.1:61107/healthz
200 {"ok":true,"service":"cocodex-server","protocol":1}

restart PID: 45772
PID changed: true
GET https://127.0.0.1:61107/healthz
200 {"ok":true,"service":"cocodex-server","protocol":1}

stop: {"stopped":true,"pid":45772}
status after stop: "running":false
```

The restart command did not report success until the replacement process owned
the PID file and the protocol-specific health response passed.

## Primary files

- `scripts/build-cocodex-private-alpha.ts`
- `scripts/Install-CoCodex.ps1`
- `tests/cocodex-private-alpha-package.test.ts`
- `apps/cocodex-server/src/cli.ts`
- `apps/cocodex-server/tests/cli-process.test.ts`
- `bin/ccx.mjs`
- `bin/ccx-server.mjs`
- `bin/ocx.mjs`
- `src/update/index.ts`
- `src/update/job.ts`
- `.github/workflows/cocodex-private-alpha.yml`
- `docs/adr/0048-cocodex-verified-windows-private-alpha-distribution.md`

## Honest limits

The archive is not Authenticode- or Sigstore-signed. Its checksum is meaningful
only inside a trusted complete manually approved GitHub artifact; pull-request
runs never upload an operator bundle. The package is not published
to npm and has no automatic CoCodex update feed. The current installer is
Windows-only, uses a user-level npm prefix, and does not install a Windows
Service. Standard npm performs the supported install from the committed
SHA-512-integrity shrinkwrap. That graph is required to match the name,
version, and integrity of the Bun-tested graph, and lifecycle scripts are
allowlisted only for the pinned Bun runtime. pnpm is not the private-alpha
operator path.

This distribution evidence does not upgrade the current single-device sealed
box private messaging into a ratcheting protocol. Forward secrecy,
post-compromise recovery, multi-device sessions, and encrypted attachments
remain later security work.
