# Fail-safe provider readiness and home-install protection evidence ? 2026-07-28

## Home installation protection

No initialization, mode change, service stop, package update, or Codex routing
injection was performed against the home installation.

A timestamped no-overwrite backup was created before implementation work:

- source: `C:\Users\Stephen\.opencodex\config.json`
- backup: `C:\Users\Stephen\.opencodex\config.json.backup-20260728-100536`
- source and backup size: 526 bytes
- source and backup SHA-256:
  `3F75FE53583C8D77F586B2B0D3996F301AA67620747CC2EEE0B890A5C541934E`

The exact post-backup checks reported:

- `ocx.cmd service status`: scheduled task `opencodex-proxy` is `Running`;
- `GET http://127.0.0.1:10100/healthz`: HTTP success with
  `{"status":"ok","service":"opencodex","version":"2.7.42",...}`;
- `providers.openai.codexAccountMode`: `direct`; and
- `127.0.0.1:10100`: user-installed OpenCodex Bun process PID 3704.

PID 3704 was treated as foreign to this build/test attempt and was never
stopped, adopted, or replaced.

## Code contract

Persistent Codex routing now requires all of the following before
`openai_base_url` is written:

1. the configured port, not a fallback port;
2. identity-checked `/healthz` with a verified OpenCodex/CoCodex PID;
3. `/readyz` from the same PID;
4. valid persisted runtime configuration;
5. the canonical enabled OpenAI provider;
6. a usable credential for the selected Direct/Pool mode; and
7. an enabled, operational reboot-persistent service or healthy Codex shim.

`/readyz` is fail-closed and reports non-secret checks for proxy,
configuration, provider, and credentials. Direct requires a present,
non-expired native Codex credential. Pool checks the main account and refresh-
validates managed credentials instead of accepting a stored record alone. If
Pool has no usable account, setup returns either ?switch to Direct mode or
cancel proxy injection? (when Direct is usable) or a cancel-and-authenticate
instruction.

The existing exact journal/atomic-write transaction remains authoritative.
Any pre-write, post-write, or post-history readiness failure restores native
Codex configuration. Setup success text now includes provider authentication,
configuration, and autostart verification.

`ocx init` preserves the existing OpenAI `codexAccountMode`, including when
another default provider is selected. OpenAI tier migration already preserves
an explicit mode. All update lanes now make a collision-safe byte-for-byte
`config.json.pre-update.<timestamp>[-N].bak` before stopping the proxy or
replacing package files:

- Bun/source CLI update;
- GUI update worker; and
- Windows npm launcher update.

## Regression evidence

Focused readiness/injection/journal/init/update-backup group:

```text
52 passed, 0 failed, 176 expectations, 6 files
TypeScript: exit 0
git diff --check: exit 0
```

Real-process and lifecycle group:

```text
111 passed, 0 failed, 422 expectations, 11 files
```

That group covers:

- real `/readyz` process responses for missing and expired Direct credentials;
- Pool with no usable account and Direct-or-cancel guidance;
- stopped service and absent shim;
- healthy reboot-persistent service;
- stale/disabled/conflicting service diagnostics;
- occupied configured port/fallback-port rejection;
- missing executable and stale shim/service assets;
- `/healthz` timeout;
- unavailable `/readyz`;
- `/healthz`/`/readyz` PID disagreement;
- proxy crash during injection with exact native restoration;
- atomic configuration-write failure restoration;
- initialization mode preservation; and
- collision-safe pre-update backups.

Windows npm launcher validation:

```text
node --check bin/ocx.mjs: exit 0
update/backup static regressions: 13 passed, 0 failed, 60 expectations
```

A real isolated proxy on random port 54451 returned:

```json
{
  "readyStatus": 200,
  "ready": {
    "status": "ok",
    "service": "opencodex",
    "pid": 49664,
    "port": 54451,
    "provider": "openai",
    "accountMode": "direct",
    "code": "ready",
    "checks": {
      "proxy": true,
      "configuration": true,
      "provider": true,
      "credentials": true
    }
  }
}
```

Its isolated state was removed after the smoke. PID 3704 remained the sole
listener on port 10100.

## Quick diagnosis

- ?Could not connect? or ?stream disconnected?: service/port/liveness problem;
  check service status, port ownership, and `/healthz`.
- HTTP 401 ?account pool has no usable credential?: Pool/Direct selection or
  login/account problem; switch intentionally to Direct, authenticate/add a
  Pool account, or cancel injection.
- `/healthz` succeeds but requests fail: inspect `/readyz`; provider,
  credential, or persisted configuration is not ready.

The final complete repository rerun passed 4,260 tests, 4 skipped, 0 failed,
with 21,666 expectations across 357 files and 15 fresh workers. Fresh
notification/readiness-enabled NSIS and MSI installers were then rebuilt and
passed isolated foreign-listener lifecycle smokes. Authoritative hashes and
package evidence are in `tauri-managed-client-runtime.md`. The artifacts
remain unsigned private-alpha outputs and are not approved for publication
while broader product gaps remain.
