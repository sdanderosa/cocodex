# Windows safe repair shortcut evidence

Date: 2026-07-28

## Installed shortcut

- Desktop link: `C:\Users\Stephen\Desktop\Repair Codex.lnk`
- Link target: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Link arguments: `-NoProfile -ExecutionPolicy Bypass -File "C:\Users\Stephen\.opencodex\repair-codex.ps1"`
- Script source: `bin/repair-codex.ps1`
- Installed script copy: `C:\Users\Stephen\.opencodex\repair-codex.ps1`
- Shortcut SHA256: `079482A1EDE27CDEAA74AE67355A1C02DF95CC3254CE3B5F84181869296C97E7`
- Source and installed script SHA256: `C1EF412F66F3B9FB1B89B373304781A69B9A44CB9B13788BD877CA1F1C8C151B`

Double-clicking the link runs the repair with a completion pause. The script also supports `-DryRun -NoPause` for an explicit no-change diagnostic invocation.

## Fail-safe behavior

1. The script creates a collision-safe, no-overwrite copy of
   `C:\Users\Stephen\.opencodex\config.json` and verifies the source and backup
   SHA256 values before doing anything else.
2. It reads the configured proxy port, inspects the listener PID and executable,
   and never calls `Stop-Process`, `taskkill`, or service deletion. An unknown
   listener is left untouched.
3. It starts the installed service only when the configured port has no listener.
   Health polling is bounded. A running listener is not adopted merely because
   `/healthz` responds.
4. It requires `/readyz` to report `status: ok`, `code: ready`, and
   `checks.credentials: true` before it asks `ocx ensure` to persist routing.
5. If readiness, service start, or `ocx ensure` cannot be proven, it invokes
   `ocx restore` and leaves Codex on native routing. The dry-run mode reports the
   same decision without changing configuration or processes.

This covers the stopped-service, reboot/autostart, occupied-port, missing or
expired credential, and provider-readiness failure paths. It does not claim to
repair a missing `ocx.cmd`; that case fails closed and tells the user to run the
native restore/install diagnosis manually.

## Verification

- Focused contract test: passed after the final bounded-health assertion.
- Isolated no-listener smoke: exit 0 on configured port 19099; the exact config
  backup matched the config SHA256; the stub recorded `service start` followed
  by `restore`, and never recorded `ensure` after readiness failed. The temporary
  test root was removed after verification.
- Live dry run: exit 0; it detected foreign PID 3704 and printed that it would
  leave the listener untouched and restore native configuration. No live config
  or process was changed by the dry run.
- Live home state after verification: the scheduled task is Running,
  `http://127.0.0.1:10100/healthz` returns `status: ok`, the account mode is
  `direct`, and PID 3704 remains the listener. The protected config SHA256 is
  `3F75FE53583C8D77F5866B2B0D3996F301AA67620747CC2EEE0B890A5C541934E`.

The desktop link is a recovery control, not an installer or a forced process
replacement. It preserves native Codex availability when the local proxy cannot
prove safe readiness.
