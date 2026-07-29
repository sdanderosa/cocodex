# Native private-message notification evidence ? 2026-07-28

## Implementation

The Tauri desktop now uses the official Tauri 2 notification plugin:

- JavaScript package: `@tauri-apps/plugin-notification` 2.3.3;
- Rust crate: `tauri-plugin-notification` 2.3.3;
- native plugin initialization in `gui/src-tauri/src/main.rs`; and
- exactly `notification:default` added to the main-window capability.

The webview retains no shell execution permission. The Tauri configuration
security regression requires exactly `core:default` and
`notification:default`, explicitly rejects shell permissions, and checks
native plugin initialization.

Permission is requested only after the user activates the notification
control. Denial, inaccessible preference storage, and native delivery errors
fail closed. Notification dispatch is limited to new inbound ordinary private
messages when the relevant conversation is not the focused active view.
Restored history, receipts, reactions, edits, deletes, and sent messages do not
notify.

The operating-system notification body is constructed without message
plaintext. It contains only bounded, control-character-sanitized labels.

## Verification

```text
focused notification tests: 4 passed, 0 failed, 18 expectations
complete GUI: 142 passed, 0 failed, 661 expectations across 29 files
Tauri configuration: 2 passed, 0 failed, 30 expectations
GUI TypeScript/build: exit 0; 150 modules transformed
GUI lint/localization: exit 0; one pre-existing hook warning
Rust: 2 passed, 0 failed
Clippy -D warnings: exit 0
privacy scan: passed
complete repository: 4,260 passed, 4 skipped, 0 failed,
  21,666 expectations across 357 files and 15 fresh workers
```

Fresh notification-enabled Tauri artifacts and packaged lifecycle evidence are
recorded in `tauri-managed-client-runtime.md`. NSIS and MSI packaged desktops
launched with isolated state while foreign user-installed OpenCodex PID 3704
owned port 10100. Both rejected that listener, launched only WebView2, and
started no bundled runtime.

## Honest acceptance boundary

The native permission prompt and visible operating-system toast were not
clicked automatically. Notification subscription is a user-controlled OS
permission and requires an explicit action-time confirmation. Implementation,
permission gating, native plugin compilation, installer packaging, and
plaintext-free dispatch logic are verified; one user-observed native toast
remains a manual acceptance step.
