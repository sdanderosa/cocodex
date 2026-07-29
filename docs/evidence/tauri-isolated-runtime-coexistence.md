# Tauri isolated-runtime coexistence evidence

Date: 2026-07-29
Branch: `feat/cocodex-foundation`

## Outcome

The installed CoCodex Client now runs its own local execution runtime while an
independently installed OpenCodex service continues to own
`127.0.0.1:10100`. CoCodex neither adopts nor stops that service. The
desktop chooses a free port in 10101–10120, isolates OpenCodex runtime state
below `~/.cocodex/runtime/opencodex`, and gives the renderer only the
native-attested endpoint.

ADR 0050 remains unchanged. Port 10100 is still the intentional persistent
Codex-injection endpoint and still requires the complete readiness,
credential, autostart, atomic-write, and restoration transaction.

## Implemented boundary

- Rust excludes port 10100 and selects from 10101–10120.
- Health acceptance binds service identity, selected port, and the exact PID
  retained in native child ownership.
- A compatible or incompatible foreign listener is left running and skipped.
- Rust supplies `COCODEX_HOME=~/.cocodex`,
  `OPENCODEX_HOME=~/.cocodex/runtime/opencodex`, and
  `COCODEX_DESKTOP_MANAGED=1`.
- Desktop-managed CLI startup skips shim recovery, injection journals,
  system/shell integration, persistent Codex sync, resume-history migration,
  and interactive update/star prompts.
- `managed_runtime_status` returns the state, ownership, PID, port, and exact
  base URL.
- Renderer bootstrap and every managed request validate that attestation and
  fail closed otherwise.
- WebView CSP lists only the 10101–10120 HTTP/WebSocket endpoints; it excludes
  10100.
- Per-process CoCodex capabilities are reacquired once after 401/403 or a
  rejected acquisition. A recovered status poll clears only its transient
  runtime error, preserving unrelated action feedback.
- Tauri development no longer probes or starts a source process on 10100.

## Automated evidence

Final maintained CoCodex gate:

```text
222 pass, 0 fail, 2,456 assertions across 46 files
migration: 13 pass, 0 fail, 117 assertions
```

Final complete inherited root gate:

```text
4,274 pass, 4 intentional skips, 0 fail
21,838 assertions across 362 files
```

Additional gates:

```text
GUI: 153 pass, 0 fail, 699 assertions across 33 files
approval: 27 pass, 0 fail, 307 assertions
lock/emergency: 17 pass, 0 fail, 216 assertions
Rust: 4 pass, 0 fail
root TypeScript: pass
CoCodex protocol/Server/root TypeScript: pass
GUI production build: pass
GUI lint: 0 errors, one pre-existing route-state hook warning
privacy scan: pass
Rust format: pass
Clippy -D warnings: pass
git diff --check: pass
```

Focused coexistence coverage proves:

- port 10100 is outside the managed range;
- an occupied dedicated port is skipped without signaling its owner;
- forged status cannot redirect to 10100;
- requests follow a changed native-attested endpoint;
- compiled sidecar state is isolated;
- a native Codex sentinel remains byte-for-byte unchanged after startup;
- capability acquisition recovers after sidecar replacement;
- rejected capability acquisition is not cached permanently.

Three full-load scheduler failures were reproduced as fast isolated passes and
repaired without changing behavior assertions:

- migration rollback outer allowance: 5 seconds to 15 seconds;
- adversarial import-recovery outer allowance: 5 seconds to 15 seconds;
- project-session event wait: 15 seconds to 45 seconds;
- revocation reconnect probes: 20 to 40 under the unchanged 120-second hard
  test ceiling.

The final complete maintained and inherited commands then returned zero.

## Live source-build coexistence

Protected host state before and after:

```text
OpenCodex PID 49016 -> 127.0.0.1:10100, health ok, mode direct
Sunshine PID 11100 -> TCP 47984/47989/47990/48010
                      UDP 47998/47999/48000
SunshineService -> Running / Automatic
```

Fresh source desktop launch:

```text
desktop PID 67388
owned runtime PID 56508
owned endpoint 127.0.0.1:10101
Codex config SHA-256 unchanged: true
OpenCodex config SHA-256 unchanged: true
Sunshine TCP/UDP sets unchanged: true
```

Owned crash recovery replaced runtime PID 56508 with PID 56528 on 10101 while
PID 49016 kept 10100. A later visual pass replaced PID 43660 with PID 57744;
the enrollment page automatically reacquired its capability and removed the
transient error without reload.

A compatible temporary foreign runtime owned PID 58412 on 10101. CoCodex left
it alive, selected 10102 for owned PID 63032, stopped only PID 63032 on desktop
close, and still left PID 58412 alive until the harness cleaned up its own
process.

## Final artifacts

```text
NSIS
  bytes  30,559,039
  sha256 CA25064A6B99169DD813B6C63D13F9E74B579568B0F2B13B5085B980991C572C

MSI
  bytes  43,892,736
  sha256 6CAB77C1CB109D301C21A6E71357F7BE62C6ECFC49F4E046DF39C3A675CF7CF3

bundled runtime
  bytes  104,904,192
  sha256 04F4C21CEB26CF7079289DE855115DF52CC1D2A5868399B206E4C7E2D61F7DAD

release desktop
  bytes  11,866,112
  sha256 A91C3CA7EA7A787D048771078E29F48C4BC5EAAB976339C6960E78F71FF10F6
```

All four artifacts report `NotSigned`; these remain private-alpha outputs.

## Installer lifecycle smokes

NSIS silent install/uninstall:

```text
install exit 0
installed desktop hash 3361381285616309A7FCD4DEADC5AC7D14311F44D95E70BA9E033BD6DCDDB0B6
runtime hash 04F4C21CEB26CF7079289DE855115DF52CC1D2A5868399B206E4C7E2D61F7DAD
desktop PID 61172
runtime PID 62668 on 10101
direct children: WebView2 and the one owned runtime
Codex sentinel unchanged: true
home OpenCodex config unchanged: true
owned runtime stopped on close: true
uninstall exit 0
```

MSI administrative extraction:

```text
extract exit 0
extracted desktop hash E46F6140BA83B103DCA24FC5743167A98CC9B630CE502EB4F5DE1D85903404AA
runtime hash 04F4C21CEB26CF7079289DE855115DF52CC1D2A5868399B206E4C7E2D61F7DAD
desktop PID 65680
runtime PID 51680 on 10101
direct children: WebView2 and the one owned runtime
Codex sentinel unchanged: true
home OpenCodex config unchanged: true
owned runtime stopped on close: true
pre-existing msiexec PID 54480 preserved: true
```

Both smokes kept port 10100 owned by PID 49016 and Sunshine running. Only
validated smoke roots and harness-owned processes were removed.

## Remaining product scope

This checkpoint makes the desktop foundation usable alongside the protected
home installation. It does not complete the entire product brief. Signing,
automatic updates, live UAC/SCM/reboot acceptance, physical two-PC acceptance,
hosted Browser execution/control, the separate elevated full-computer helper,
mature ratcheted multi-device attachments, and final visual-reference parity
remain unproven or incomplete.
