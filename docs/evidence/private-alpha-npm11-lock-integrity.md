# Private-alpha npm 11 lock integrity

- Date: 2026-07-29
- Branch: `feat/cocodex-foundation`
- Host toolchain: Node `v24.18.0`, npm `11.16.0`, Bun `1.3.14`

## Confirmed failure

The clean `630a35a7` private-alpha archive passed checksum/provenance construction, but an isolated npm 11 installation without an explicit install strategy hoisted independently resolved transitive packages. The strict installed-release verifier rejected `@hono/node-server@1.19.17` because the published `npm-shrinkwrap.json` pins `1.19.14`. No installed OpenCodex or CoCodex Server process was launched after that rejection.

This was a real supported-toolchain defect: `Install-CoCodex.ps1` accepts npm 10 or newer, so npm 11 must preserve the audited dependency graph instead of resolving a second top-level graph.

## Repair

The installer now invokes npm with `--install-strategy=nested`. This keeps the distributed CoCodex package and its published shrinkwrap as the dependency authority instead of allowing prefix-level hoisting to replace locked transitive versions. The flag is explicit in the process argv; it does not depend on a mutable user or machine npm configuration.

The package regression suite asserts the exact installer invocation occurs only after archive checksum and release-manifest verification.

## Live verification

Using the supplied installer with nested strategy in a dedicated isolated prefix succeeded under npm `11.16.0`. The strict installed-release verifier reported:

```json
{
  "verified": true,
  "package": "@sdanderosa/cocodex@0.1.0-alpha.1",
  "installedDependencies": 126,
  "localRuntime": { "port": 58614, "service": "opencodex", "gui": 200 },
  "server": { "port": 58632, "initialPid": 47676, "restartedPid": 58648, "stopped": true }
}
```

Port 10100 remained owned by foreign PID 3704. Sunshine service/process and protected TCP/UDP listeners remained unchanged. The final clean rebuilt archive and installer hashes are recorded after the repaired release checkpoint passes the repeated package evidence gate.

## Source gates

- Focused private-alpha package suite: 6 pass, 0 fail, 500 assertions.
- Maintained CoCodex suite: 220 pass, 0 fail, 2,423 assertions across 46 files.
- Complete repository rerun: 4,270 pass, 4 intentional skips, 0 fail, 21,774 assertions across 361 files.
- Complete GUI suite: 149 pass, 0 fail, 691 assertions across 32 files.
- CoCodex TypeScript, privacy scan, GUI production build (154 modules), Rust tests (2 pass), and Clippy with warnings denied: pass.
- GUI lint: 0 errors and one pre-existing hook-dependency warning.

One first complete-suite run had a load-sensitive 5-second timeout in the unrelated provider-show masking test after 4,269 passes. The entire 26-test provider file then passed in isolation, with the affected test completing in 0.46 seconds, and the second complete repository run passed with zero failures. No production or unrelated test code was changed for that transient timeout.
