# Fail-safe proxy injection evidence matrix

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Normative decision: [ADR 0050](../adr/0050-cocodex-fail-safe-proxy-injection.md)
- Status: implemented and covered by the local regression evidence below; publication remains gated on the wider CoCodex product acceptance pass

## Transaction and recovery requirements

| Required failure mode or invariant | Enforcement | Evidence |
| --- | --- | --- |
| Save the exact native Codex configuration before injection | `src/codex/inject.ts` writes the journal before mutation; `src/codex/journal.ts` stores the exact pre-attempt bytes | `codex-journal.test.ts`: direct paths create a restorable journal; normal stop restores custom defaults; full write/crash/reconcile lifecycle |
| Do not inject while the proxy is stopped | `src/codex/injection-guard.ts` fails readiness unless a verified live proxy and supported startup path both exist | `codex-injection-guard.test.ts`: stopped service without an operational shim is rejected |
| Reject a foreign owner of the configured port | Guard identity verification requires the expected PID; the Tauri supervisor also requires health PID equality with its actual `CommandChild` | `codex-injection-guard.test.ts`: foreign owner and occupied configured port; `gui/tests/api-auth-fetch.test.ts`: renderer refuses loopback requests without Rust-owned status; packaged smoke rejected foreign PID 23976 without stopping it |
| Require valid `/healthz`, including timeout handling | Guard uses bounded health/identity verification | `codex-injection-guard.test.ts`: health timeout fails closed; focused Rust tests reject wrong service, wrong port, non-JSON, multiline, and oversized diagnostics |
| Require valid `/readyz` from the same PID | Guard requires provider/config/credential readiness after liveness and rejects endpoint absence or PID disagreement | `provider-readiness.test.ts`, `proxy-readiness-process.test.ts`, and `codex-injection-guard.test.ts`: Direct, Pool, unavailable endpoint, and PID race coverage |
| Reject missing, expired, or unusable selected-provider credentials | Direct validates the native Codex credential; Pool refresh-validates eligible credentials and returns Direct-or-cancel guidance | Real child-process missing/expired tests; Pool no-account and managed-refresh unit tests |
| Require reboot-persistent startup | Guard accepts only an operational supported service or shim and validates its recorded executable target | `codex-injection-guard.test.ts`: healthy reboot-persistent service accepted; stale service assets and missing shim executable rejected; healthy enabled shim accepted |
| Roll back a partially installed shim | Shim installation is one transaction across all launcher siblings | `codex-shim.test.ts`: fresh install rolls back every launcher after a later-step failure; mixed siblings and fingerprint races defer without piecemeal mutation |
| Roll back a partially installed service | Service installation journals first and cleans only state/processes created by that attempt | Focused service suite passed; service tests cover fail-closed backend state, stale baked paths, graceful owned-process cleanup, and cleanup continuation after kill errors |
| Detect a proxy crash during configuration update | Injection re-verifies readiness after the atomic write and restores on failure | `codex-injection-guard.test.ts`: proxy crash during injection restores native Codex and removes the attempt journal |
| Recover from configuration-write failure | Atomic write failure enters exact restoration and reports setup incomplete | `codex-injection-guard.test.ts`: write failure restores every existing setting atomically |
| Recover stale localhost injection at startup | Startup reconciliation removes only CoCodex-owned localhost routing from the journaled state | `codex-journal.test.ts`: dead-PID reconcile; full crash recovery; stale-injection recovery preserving later user edits |
| Preserve Direct/Pool mode during initialization and upgrades | Init carries forward the explicit OpenAI mode; tier migration already resolves and retains explicit mode | `init-backup-cleanup.test.ts` mode-preservation tests plus existing OpenAI migration suite |
| Back up home configuration before package replacement | CLI, GUI worker, and npm launcher create no-overwrite exact pre-update copies before stop/replacement | `config-update-backup.test.ts`; npm launcher syntax and ordering checks |
| Preserve unrelated Codex settings and user edits | Restoration compares the injected state and merges/restores only owned fields; external providers are not rewritten | `codex-inject-integration.test.ts`: external provider remains byte-for-byte unchanged; user base URL retained; CRLF/LF preserved; `codex-journal.test.ts`: post-injection edits are not clobbered |
| Never delete unrelated repository or user data | All implementation work is scoped to owned config, journal, shim/service, and runtime assets | Full default and isolated regression suites passed; worktree was kept intentionally dirty and no foreign process or unrelated change was removed |

## Tauri runtime ownership fail-safe

The desktop supervisor and renderer add a second fail-closed boundary around
port `10100`:

1. Rust records the actual spawned `CommandChild` PID.
2. A health response is accepted only when its PID equals that child PID.
3. A compatible or incompatible foreign listener is reported as disconnected.
4. Shutdown calls `kill` only on the stored owned child handle.
5. Before any renderer request to `127.0.0.1:10100`, `gui/src/api.ts` asks Rust
   for `managed_runtime_status`; an unowned result becomes a local synthetic
   `503` and no request crosses to the listener.

The packaged NSIS application was launched while user-installed OpenCodex PID
`23976` owned `127.0.0.1:10100`. The desktop diagnostic recorded:

```text
foreign compatible runtime rejected pid=23976; showing disconnected interface
```

No `cocodex-runtime` child was created. Closing only the desktop left PID
`23976` alive, at the same executable path, and still listening on port
`10100`.

## Test results

- Current readiness/service/update lifecycle group: 111 passed, 0 failed, 422 expectations across 11 files.
- Focused readiness/injection/journal/init/backup group: 52 passed, 0 failed, 176 expectations across 6 files.
- Final guard/journal/shim subset: 55 passed, 0 failed.
- Full default-parallel repository suite: 4,237 passed, 4 skipped, 0 failed,
  21,607 assertions across 352 files.
- Full isolated single-worker repository suite: 4,237 passed, 4 skipped, 0
  failed, 21,607 assertions across 352 files.
- `test:cocodex`, root typecheck, CoCodex typecheck, GUI production build, GUI
  lint, Rust tests, and Clippy with warnings denied all exited successfully.

The matrix records implementation evidence for ADR 0050. It does not claim
that unrelated remaining private-alpha product requirements are complete.

Current detailed evidence: [fail-safe provider readiness and home-install protection](fail-safe-readiness-and-home-protection.md).
