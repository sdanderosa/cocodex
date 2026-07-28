# Tauri-managed Client runtime evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `c7f4f148`
- Implementation commit: recorded by the commit containing this file
- Status: local Windows lifecycle and packaging gates passed; the latest 2026-07-28 evidence below supersedes historical artifact identities

## Automated focused checks

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\tauri-dashboard-config.test.ts `
  .\tests\tauri-sidecar-process.test.ts `
  .\tests\cocodex-routes-security.test.ts `
  --timeout 60000
```

Exit status `0`: 4 tests, 0 failures, 44 assertions. The test compiles and
starts the actual target-triple sidecar with isolated Client, OpenCodex, and
Codex state. It verifies the health service, PID, dynamically reserved port,
embedded source version, exact Tauri origin, CORS response, per-launch
capability issuance, and a protected CoCodex status call.

```powershell
cd gui\src-tauri
cargo test
cargo clippy --all-targets -- -D warnings
```

Both commands exited `0`. Two Rust tests reject the wrong health service,
wrong port, non-JSON body, and multiline/oversized diagnostic content.

The root TypeScript typecheck and production GUI build also exited `0`.

## Windows bundles

```powershell
.\node_modules\.bin\bun.exe run build:tauri
```

Exit status `0`. Tauri compiled the Bun sidecar and Rust application, then
produced:

```text
gui/src-tauri/target/release/bundle/nsis/CoCodex_0.1.0_x64-setup.exe
gui/src-tauri/target/release/bundle/msi/CoCodex_0.1.0_x64_en-US.msi
```

The build output explicitly reports the sidecar compilation followed by
successful NSIS and WiX packaging. Final artifacts:

```text
NSIS  30,438,481 bytes
SHA-256 BB3F352381707B1E50DD91DFE07F4E8FC279911D1D54B4664B873CEE1CBD4562

MSI   43,749,376 bytes
SHA-256 91782C2EB7BABCC88420669F28BD9C3A0E70AE91202D9C84FBAD47C3D99BB82C
```

## Visible packaged-app lifecycle

The release executable was tested as the real Windows application, not as a
React preview.

1. With the source proxy already healthy on port 10100, packaged CoCodex
   opened one native window. Closing it removed PID 54828 while the unowned
   source proxy PID 11832 remained healthy.
2. With port 10100 empty, the application started its packaged
   `cocodex-runtime.exe`. A stale development proxy on fallback port 52746
   correctly triggered the inherited single-instance guard; the desktop
   showed a disconnected interface after its bounded timeout and recorded the
   reason without killing the unowned process.
3. After that verified stale development process was stopped, the already-open
   supervisor recovered without an application restart. Health returned the
   bundled child PID 58796 on port 10100.
4. The native dashboard rendered **Online**, one active provider, and seven
   models from the user's existing local configuration.
5. The packaged webview opened **CoCodex collaboration / PRIVATE ALPHA** and
   rendered the one-time-invite enrollment form. This proves the exact Tauri
   origin can cross CORS, obtain its per-launch capability, and call the
   protected bridge.
6. Closing the owning desktop PID 40032 terminated child PID 58796 and made
   port 10100 unavailable. No unowned process was targeted.
7. The final rebuilt desktop PID 59268 automatically started bundled child
   PID 21736. Health returned
   `{"status":"ok","service":"opencodex","version":"2.7.35","pid":21736,"port":10100}`;
   the visible dashboard rendered **Online / 2.7.35**. Closing the desktop
   removed both processes and freed port 10100.

Local lifecycle diagnostics are stored at:

```text
%LOCALAPPDATA%\CoCodex\logs\desktop-runtime.log
```

They record only native lifecycle events and sanitized stderr. Runtime stdout
does not enter the renderer.

## Files under test

- `scripts/build-tauri-sidecar.ts`
- `scripts/build-tauri-frontend.ts`
- `scripts/dev-tauri.ts`
- `gui/src-tauri/Cargo.toml`
- `gui/src-tauri/Cargo.lock`
- `gui/src-tauri/src/main.rs`
- `gui/src-tauri/tauri.conf.json`
- `gui/src-tauri/capabilities/default.json`
- `src/server/auth-cors.ts`
- `src/server/management/cocodex-routes.ts`
- `tests/tauri-dashboard-config.test.ts`
- `tests/tauri-sidecar-process.test.ts`
- `tests/cocodex-routes-security.test.ts`

## Honest limits

The installers are not Authenticode-signed. The desktop bundle installs the
Client and its local execution runtime, not the separately hosted CoCodex
Server. Automatic router mapping, CGNAT handling, relay infrastructure, and
cross-platform installers remain later requirements. A separately running
OpenCodex process on a nonstandard fallback port is not killed or silently
adopted; the local diagnostic identifies the conflict.

## Continuation verification — 2026-07-28

The durable handoff was read in full before work resumed. The worktree remains
intentionally uncommitted on `feat/cocodex-foundation` at base `c7f4f148`.

### Fail-safe transaction gates

With a repository-local temporary directory (the sandbox denies the system
temp directory), the focused regression command:

```powershell
.\node_modules\.bin\bun.exe test .\tests\codex-injection-guard.test.ts .\tests\codex-inject-integration.test.ts .\tests\codex-journal.test.ts .\tests\codex-shim.test.ts .\tests\service.test.ts .\tests\startup-prompt.test.ts --timeout 30000
```

exited `0`: 103 tests passed, 0 failed, 502 expectations. After the final
pre-readiness hardening, the guard/journal/shim regression subset exited `0`:
55 tests passed, 0 failed, 261 expectations. The new process-level stale
localhost recovery test and fresh shim rollback test both passed.

Root TypeScript typecheck and `typecheck:cocodex` exited `0`. Rust
`cargo test` exited `0` with 2 tests passed, and
`cargo clippy --all-targets -- -D warnings` exited `0`. The direct GUI
production build exited `0`; GUI ESLint exited `0` with one pre-existing hook
warning and no errors. The Tauri dashboard configuration tests exited `0`
with 2 tests and 25 expectations.

### Process and network evidence

Before and after testing, `127.0.0.1:10100` was listening under PID `23976`
at the foreign user-installed path
`C:\Users\Stephen\AppData\Roaming\npm\node_modules\@bitkyc08\opencodex\node_modules\bun\bin\bun.exe`.
That process was never stopped or adopted. No CoCodex test/build worker was
left running after the checks.

### Blocked gates and artifact policy

The full default Bun suite reached 3,302 passes and 4 skips, but had 136
failures and 70 module-load errors because Bun could not read the existing
`libsodium-wrappers-sumo` junction under the sandbox ACL. Representative CLI,
route-security, and private-alpha failures terminate with that same package
resolution error before exercising their assertions. The private-alpha suite
started with its compiled-DPAPI test passing, then stopped at the same
dependency error; its typecheck passed.

`bun run build:tauri` reached the sidecar compilation step but exited `1`
before packaging because the sandbox denied reads of
`libsodium-wrappers-sumo` and the native `@primno/dpapi` binary. Therefore the
existing NSIS/MSI/sidecar outputs retain their 2026-07-27 timestamps and are
stale; their historical hashes above were not reused as new distribution
evidence, and no commit or push was made.

## Final local rebuild and regression checkpoint — 2026-07-28

The dependency ACL obstacle above was resolved using repository-local physical
copies while preserving the original junctions for restoration. The complete
default-parallel suite then exited `0` with 4,237 passes, 4 skips, 0 failures,
21,607 assertions, and 352 files. A second isolated single-worker pass produced
the same counts. `test:cocodex`, root and CoCodex TypeScript checks, the GUI
production build, GUI lint, Rust tests, and Clippy with warnings denied all
exited successfully. GUI lint retained one existing hook warning and no errors.

The rebuilt desktop now refuses to adopt even a protocol-compatible listener.
Rust accepts readiness only when `/healthz` reports the PID of the actual
`CommandChild`; the renderer independently blocks every loopback API fetch
until Rust reports that child as owned. A packaged NSIS launch with the foreign
user-installed OpenCodex PID 23976 already listening on `127.0.0.1:10100`
recorded:

```text
foreign compatible runtime rejected pid=23976; showing disconnected interface
```

No bundled runtime was spawned. Closing only CoCodex left PID 23976 alive,
unchanged, and listening. The focused renderer ownership-gate test passed with
2 tests and 6 assertions; the Tauri dashboard/sidecar subset passed with 3
tests and 33 assertions.

Fresh final artifact identities are:

```text
NSIS installer
  30,438,408 bytes
  SHA-256 BB031651317913A1F792BAE629AE17CE465432AC3E5AFF2F3A92F28D52188217

MSI installer
  43,765,760 bytes
  SHA-256 4854A49E7C20419C1D9B6DAB073E987F6C1CC1AB80DEEE91DC8AFBC4ADC0EE9B

Bundled runtime
  104,804,352 bytes
  SHA-256 423B3EC62B337882A34C1BE29C520DA76EC87CC89B9F9552D6F886B9C315A6F9

Desktop executable
  11,466,752 bytes
  SHA-256 6419891FA096EB0475E7E835BCC3D7D6C3D3793717E445F2FA57BF1ADE988A33
```

The NSIS installer completed an isolated install and launch smoke. MSI
administrative extraction completed successfully with Windows Installer
status `0`; the extracted desktop and runtime hashes exactly match the release
executables above. WiX standard MSI linking remains unable to run ICE
validation because the environment cannot access the Windows Installer
service from the ICE sandbox. The fresh Tauri-generated `main.wixobj` was
therefore linked with WiX `light.exe -sval`; `dark.exe` successfully
decompiled the result and administrative extraction verified its payload.
This limitation is explicit: the MSI is structurally and extractably verified,
but has not passed standard ICE validation in this environment.

All four artifacts are intentionally unsigned private-alpha outputs. They are
not approved for publication until the wider CoCodex acceptance pass succeeds.
The complete transaction mapping is recorded in
[the fail-safe evidence matrix](fail-safe-proxy-injection-matrix.md).

## Post-session rebuild and packaged verification - 2026-07-28

The persistent-session, final-goal composer, usage-report, and chat-first route
changes made every earlier bundle hash stale. A fresh
`bun run build:tauri` exited 0 and rebuilt the sidecar, release desktop,
NSIS installer, and MSI installer.

Fresh artifact identities:

```text
NSIS installer
  30,459,781 bytes
  SHA-256 1B1DCE32C326BC919DD7E2A340313E9694D4FF3DF4624117D132537B741983E7

MSI installer
  43,769,856 bytes
  SHA-256 0A3144C5FF0A6143B8DA258B58C0B6777FFFC6D156AB3B044B3F98E999745C21

Bundled runtime
  104,813,056 bytes
  SHA-256 1B77E2AB17734AAF37A6046B706CA270A55A51A51CA33DD257664B8E4DDFDD8F

Release desktop executable
  11,465,728 bytes
  SHA-256 AE477BAF9BF4AC2864E4B82619F7CFD96DBF705A711FE32F6EB63E9546CB0550

MSI bundle-patched desktop payload
  11,465,728 bytes
  SHA-256 68B731020D04151692114F7B70582BF0858E03542D53AC96C89865FE52DA82B6
```

The NSIS installer completed an isolated silent install. The exact installed
Tauri desktop launched with isolated local app data while foreign PID 23976
owned `127.0.0.1:10100`. Its runtime log recorded
`foreign compatible runtime rejected pid=23976`; the only direct child was
`msedgewebview2.exe`, bundled-runtime count was zero, and closing CoCodex left
PID 23976 listening. The isolated NSIS uninstaller exited 0 and removed its
install root.

MSI administrative extraction exited 0. The extracted
`cocodex-runtime.exe` hash exactly matched the fresh bundled runtime. The
bundle-patched desktop payload launched successfully, recorded the same
foreign-owner rejection, created only a WebView2 child, and started no bundled
runtime. PID 23976 remained the listener after closure.

The final focused Tauri sidecar, route-capability, and renderer ownership gate
passed 6 tests with 0 failures and 51 expectations. The complete root
regression passed 4,240 tests with 4 skips and no failures; the explicit
CoCodex suite passed 177 tests; GUI passed 130 tests. TypeScript, GUI build and
lint, Rust tests, and Clippy all exited 0.

The foreign process was never stopped or adopted. Because it remains
authoritatively user-owned, this pass does not repeat the owned-runtime
port-10100 lifecycle by taking it offline. Owned sidecar startup remains
covered by the compiled dynamic-port process test and the earlier packaged
lifecycle checkpoint.
## Final post-leak rebuild and packaged verification - 2026-07-28

The final complete single-worker regression uncovered and then proved a
cross-file process leak in the CLI models fixture. The product liveness probe
used `AbortSignal.timeout()`, whose signal could leave a Bun fetch handle alive
after a fast failed probe. The CLI command had already persisted its model and
completed liveness discovery, but the process sometimes never exited. The
probe now owns an `AbortController`, uses an unref'd timer, and always clears
and aborts both in `finally`. The child-process fixture also has a 15-second
hard bound so a future regression fails diagnostically instead of hanging the
suite.

Verification after repair:

```text
liveness unit suite: 18 passed, 0 failed, 33 expectations
CLI models stress (10 complete repetitions): 100 passed, 0 failed, 340 expectations
complete repository, one worker: 4,243 passed, 4 skipped, 0 failed
complete repository assertions: 21,639 across 354 files
explicit CoCodex: 178 passed, 0 failed, 2,051 expectations
GUI: 133 passed, 0 failed, 626 expectations
privacy scan: passed
focused privacy/service/package/fail-safe: 123 passed, 0 failed, 1,122 expectations
TypeScript: exit 0
GUI lint/build: exit 0 (one pre-existing hook warning)
Rust: 2 passed, 0 failed
Clippy -D warnings: exit 0
```

A final `bun run build:tauri` after the runtime repair exited 0. Final artifact
identities are:

```text
NSIS installer
  30,476,863 bytes
  SHA-256 90B37E5664A048F82A31DFCB8952F5554C06A6118C190D376C68BE46FE70357F

MSI installer
  43,769,856 bytes
  SHA-256 E886347DBE571E5E1F58BC5B6D0B63927ABE0C5893F0387151FA5FD3062F979A

Bundled runtime
  104,818,176 bytes
  SHA-256 2C4DA2A55CA0A402CF84AAC08D1FF972A6B9B5B7FC7F3C916D2BDEC323336CF1

Release desktop executable
  11,466,752 bytes
  SHA-256 7591D5055AF816750DEFD891D3615647AD5F4BE83DC9AB7C3782BE7612C518A9

NSIS-installed desktop payload
  11,466,752 bytes
  SHA-256 D142F6877A262E179F1AF911F8529C017B61BCD08E5A3871A335B468AC40D0FC

MSI bundle-patched desktop payload
  11,466,752 bytes
  SHA-256 5CDE8E7322CE7A2A9947A34D44921AE422EEAA70C2AA3BCABA47A370F8F3A470
```

The final NSIS silent install and launch used isolated local app, Codex, and
OpenCodex state. The desktop logged
`foreign compatible runtime rejected pid=23976`; its only direct child was
`msedgewebview2.exe`, bundled-runtime count was zero, and exact-PID cleanup
left PID 23976 as the sole listener on 127.0.0.1:10100. Silent uninstall exited
0 and removed the isolated install root.

Final MSI administrative extraction exited 0. The extracted runtime hash
matched the final bundled runtime. Its desktop recorded the same foreign-owner
rejection, created only a WebView2 child, launched no bundled runtime, and left
no CoCodex process after exact-PID cleanup. PID 23976 remained alive and
listening throughout.
