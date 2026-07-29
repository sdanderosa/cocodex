# Native CoCodex Server onboarding evidence

Date: 2026-07-29
Branch under test: `codex/cocodex-onboarding`
Base: `b8fc439c233c8655bb584fe8d0c3e12b10caf648`

## Implemented boundary

The native Tauri build now contains two independently compiled executables:

- `cocodex-runtime`: Client-owned loopback proxy under
  `~/.cocodex/runtime/opencodex`.
- `cocodex-server`: independent collaboration Server under
  `~/.cocodex-server`.

The renderer has no shell permission. Structured Rust commands provide safe
Server status, first-host preparation, and bootstrap approval only. The Server
process is detached through its own lifecycle and is not retained in the
Client's owned-child slot.

## Fail-safe evidence

- Port 10100 and the managed runtime range 10101-10120 are rejected.
- Sunshine ports 47984-48010 are rejected.
- Wildcard and loopback availability are checked before initialization.
- Foreign occupied ports are never stopped or adopted.
- Local bootstrap uses a signed one-time `127.0.0.1` invitation while normal
  invitations retain the configured public host.
- Invalid invitation hosts and URL-shaped input are rejected.
- Server admin tokens are projected out before data reaches the WebView.
- Manual firewall, forwarding, and CGNAT diagnostics remain visible after
  successful local enrollment.
- The host OpenCodex listener and Sunshine state are rechecked separately
  before release integration.

## Verification completed in the isolated worktree

- Native Rust: 7 passed, 0 failed.
- Strict Clippy: passed with warnings denied.
- GUI: 158 passed, 0 failed, 714 assertions across 34 files.
- GUI production build: passed.
- GUI lint: 0 errors; one pre-existing hook dependency warning.
- Separate Server CLI process: 3 passed, 0 failed, 38 assertions.
- Tauri runtime/Server sidecars: 4 passed, 0 failed, 73 assertions.
- Maintained CoCodex suite: passed.
- Complete repository: 4,275 passed, 4 intentional skips, 0 failed,
  21,846 assertions across 362 files.
- Native accessibility inspection proved the default **Host on this PC** form
  and interactive **Join with invite** tab in a freshly built Tauri window.

## Final artifacts and package smoke

All five artifacts are unsigned private-alpha builds:

```text
NSIS    7F3E09723C58EC2BA1B007429894E3E884EF58CE0402C4269FA97131C87A9577
MSI     80B84D0B04338739A54CD634BD3F2A50687D403B4ED9BDF6FB4EB128C8DA7DC9
runtime CE0F8630797EC016637770E6C34C6695BD868FEE8BD583022D20E246E6ECAE80
server  CF3A64950EEFA02559F0D308C4BF058A5857AB33E36AC52302B96CC8EFFB359B
desktop FE1A652E6E1E957FB145F6A3D1F6D3BA91547B413CA3B930A4EE36D6644F5739
```

MSI administrative extraction returned 0 and contained the exact Server and
runtime hashes above. NSIS silent install returned 0 into a unique workspace
directory, contained the exact Server/runtime hashes, and produced desktop
hash `880AA6FC0D70FB921B65E2A8E4552765AF96E49B9872A51C103EBED6293A5FD4`.
Its generated uninstaller returned 0 and removed only that directory. The MSI
desktop payload hash is
`CE08BE17ACB84C3C4FBD5A00F3853E56CDC762377C42592B97847267CAD1A988`.

## Live protected-host evidence

The final raw desktop PID 66164 owned runtime PID 64484 on 10101. Native
accessibility inspection proved the default Host form. The QA desktop then
closed normally and both owned children exited.

Home OpenCodex PID 49016 remained healthy on 127.0.0.1:10100 with account mode
`direct`. SunshineService remained Running/Automatic. Sunshine PID 11100
retained TCP 47984/47989/47990/48010 and UDP 47998/47999/48000. The
pre-existing user-facing CoCodex desktop/runtime stayed alive on its own
managed port. No CoCodex Server was initialized on the home machine during
this verification.
