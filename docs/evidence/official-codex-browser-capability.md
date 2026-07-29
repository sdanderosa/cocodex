# Official Codex browser capability evidence

- Date: 2026-07-28
- Decision: [ADR 0057](../adr/0057-cocodex-official-browser-capability-boundary.md)
- Branch: `feat/cocodex-foundation`

## Authoritative contract

The current official Codex manual says Browser is not available in Codex CLI or the IDE extension and directs users to the official desktop app. The installed local runtime is `codex-cli 0.146.0-alpha.3.1`. Its read-only feature inventory reports `browser_use`, `browser_use_external`, and `browser_use_full_cdp_access` stable and enabled. Its plugin inventory reports `browser@openai-bundled` installed and enabled. The version-matched generated app-server schema contains no browser-specific task/event contract; the Browser plugin requires an app-provided browser runtime.

## Runtime evidence

The CoCodex detector returned:

```json
{"version":1,"executionSurface":"codex-exec","runtimeVersion":"0.146.0-alpha.3.1","agentBrowserAvailable":false,"officialAppAvailable":true,"browserPluginInstalled":true,"browserFeatureEnabled":true,"externalBrowserFeatureEnabled":true,"fullCdpFeatureEnabled":true,"status":"official-app-only"}
```

No local executable, plugin, marketplace, profile, workspace, browser, cookie, credential, or configuration path is present in this projection.

## Implemented behavior

- The detector probes only the selected runtime with shell-free, bounded, read-only argv.
- Missing runtime, feature, plugin, or app command fails closed.
- The resident capability command returns privacy-safe local facts and always reports Browser unavailable to `codex exec` agents.
- The renderer can request `codex.official-app.open` only with an agent ID. The resident Client resolves the stored canonical workspace and rejects renderer-provided paths or commands.
- The chat-first agent card shows checking, official-app-only, or unavailable state and offers an explicit Open in official Codex button only when all local prerequisites are proven.

## Current verification

- Focused capability/bridge/GUI/resident-session suite: 8 pass, 0 fail, 225 assertions.
- Maintained CoCodex suite: 220 pass, 0 fail, 2,423 assertions across 46 files.
- Complete GUI suite: 149 pass, 0 fail, 691 assertions across 32 files.
- Complete repository suite: 4,270 pass, 4 intentional skips, 0 fail, 21,774 assertions across 361 files.
- CoCodex TypeScript, privacy scan, GUI production build (154 modules), Rust tests (2 pass), and Clippy with warnings denied: pass.
- GUI lint: 0 errors and the same pre-existing hook-dependency warning.
- In-app Browser QA rendered the local CoCodex enrollment shell. The standalone Vite preview intentionally lacked the native status API, so it did not fabricate a connected agent card; card states are covered by the focused GUI tests.
- Temporary preview processes and listener `127.0.0.1:4179` were removed after QA. Foreign OpenCodex PID 3704 on port 10100 and Sunshine PID 11100/listeners were unchanged.

Clean source commit `0898f97aee560e86bf5a6c693f50b6eb72dddb18` (tree `21cbf56aca18b3cceffccdd445c8e752dd003f45`) produced the final private-alpha archive, Tauri runtime/desktop, NSIS, and MSI evidence under `dist/release-evidence/0898f97a/`. Archive, NSIS, MSI, and both packaged-desktop ownership smokes passed; exact hashes are recorded in `tauri-managed-client-runtime.md`.

This slice remains intentionally partial: hosted-agent Browser execution, watch/shared-control, sanitized browser events/results, and optional encrypted live viewing are not claimed.
