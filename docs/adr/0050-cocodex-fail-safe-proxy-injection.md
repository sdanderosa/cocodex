# ADR 0050: Fail-safe proxy injection

Status: Accepted

## Decision

CoCodex must never leave the Codex desktop app configured to use `localhost:10100` unless the CoCodex proxy is healthy and a verified startup mechanism is installed.

Before modifying or preserving any Codex configuration, CoCodex must:

1. Read and save an exact backup of the current native Codex configuration.
2. Start the CoCodex proxy.
3. Confirm that port `10100` is owned by the expected CoCodex process. If another process owns the port, fail without changing Codex.
4. Verify that `/healthz` returns the expected successful response.
5. Verify that `/readyz` is returned by the same PID and proves valid persisted configuration, the selected provider, and a usable credential for the selected Direct/Pool mode.
6. Install the supported autostart service or shim.
7. Verify that the autostart entry points to an existing executable and can successfully start the proxy.
8. Only after every check passes, atomically update Codex to use `localhost:10100`.

If any startup, liveness, provider, credential, configuration, ownership, executable, autostart, or configuration-write check fails, CoCodex must atomically restore the exact pre-injection Codex configuration, stop any partially started CoCodex process, remove incomplete autostart changes created during that attempt, report setup as incomplete with the specific failed check, and never claim setup succeeded.

On startup, CoCodex detects stale localhost injection. If Codex points to `localhost:10100` but the proxy cannot be started and verified, it restores the saved native configuration automatically.

## Required verification

Targeted tests cover a stopped proxy service, reboot/autostart persistence, a foreign owner on port `10100`, a missing or moved executable, `/healthz` failure or timeout, unavailable or PID-mismatched `/readyz`, missing and expired credentials, Pool with no usable account, a proxy crash during setup, configuration-write failure, stale-injection recovery, exact restoration of existing settings, initialization/update mode preservation, and preservation of unrelated settings and repository changes.

CoCodex does not delete user data, reset unrelated Codex settings, or overwrite unrelated repository changes.

## Enforcement points

- `src/codex/injection-guard.ts` owns the fail-closed readiness decision.
- `src/codex/inject.ts` journals the exact pre-attempt state, uses atomic writes, re-verifies after the write, and restores on every failed check.
- `src/codex/journal.ts` provides exact crash/stale-injection recovery without overwriting user edits made after injection.
- Service and shim diagnostics must prove that recorded executable targets exist and the startup mechanism is operational.
- `src/server/readiness.ts` owns provider/credential readiness and the bounded `/readyz` client proof.
- `GET /readyz` exposes only non-secret proxy, configuration, provider, and credential check results and returns `503` while any check is not ready.
- `ocx init` and OpenAI upgrade migration preserve an explicit `codexAccountMode`.
- Every package-update lane writes a collision-safe exact `config.json` backup before stop/replacement.
