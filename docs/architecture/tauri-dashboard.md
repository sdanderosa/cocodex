# CoCodex desktop dashboard

Persistent Codex routing is governed by
[ADR 0050](../adr/0050-cocodex-fail-safe-proxy-injection.md). Launching the
desktop dashboard is never evidence that port 10100 may be injected into Codex.

The dashboard is one React/Vite frontend delivered through the browser
dashboard and a Tauri 2 desktop shell. Project, chat, device, and agent
authority remain in the TypeScript Client/Server protocol; Rust owns only the
native desktop window and its bundled local-runtime lifecycle.

## Development

From the repository root:

```text
bun run dev:tauri
```

The development hook compiles the production Client runtime and separate
Server external binaries, then starts Vite on
`127.0.0.1:4179`. Rust starts and supervises the sidecar exactly as it does
in a packaged app. The hook does not probe, adopt, start, or stop the user's
port-10100 OpenCodex service.

Browser-only development remains:

```text
bun run dev:proxy
bun run dev:gui
```

## Packaging

```text
bun run build:tauri
```

The build compiles `src/cli/index.ts` as `cocodex-runtime` and the separate
`apps/cocodex-server/src/cli.ts` as `cocodex-server`, using validated
target-triple names, then builds `gui/dist` and packages both NSIS and MSI
installers. A destination computer does not need Git, Bun, Node.js, or Rust.

## Runtime bootstrap

Rust selects an available port from 10101–10120, launches the bundled runtime
with isolated state under `~/.cocodex/runtime/opencodex`, and accepts
readiness only when the health PID and port match the child Rust owns.
Port 10100 is reserved for the independent OpenCodex/ADR-0050 path.

The renderer first invokes `managed_runtime_status`. Its fetch boundary
accepts only an owned, ready status with a valid PID and exact
`http://127.0.0.1:<managed-port>` base URL, then rewrites requests to that
attested endpoint. The explicit CSP lists only ports 10101–10120. Runtime
restart may change the endpoint without reloading the UI because each managed
request rechecks native ownership.

Closing CoCodex kills only the child retained in Rust ownership state. Foreign
listeners are never adopted or stopped. If all dedicated ports are occupied,
the disconnected UI is shown and the supervisor retries.

## State and mutation boundary

The desktop child receives:

- `COCODEX_HOME=~/.cocodex`
- `OPENCODEX_HOME=~/.cocodex/runtime/opencodex`
- `COCODEX_DESKTOP_MANAGED=1`
- `OCX_SERVICE=1`

It may read the existing native Codex home for Direct credentials. Desktop
startup skips persistent Codex injection, journals, model sync, history
migration, shell hooks, system environment integration, and interactive
self-update prompts. ADR 0050 remains the only route to system-wide Codex
configuration.

## Security boundary

The WebView has `core:default` and notification permission only. It receives
no shell or filesystem permission. Rust invokes one configured sidecar.
Tauri's exact embedded origins may request the per-launch CoCodex capability;
arbitrary localhost origins cannot. Protected routes still require the random
capability.

The installer bundles the separately compiled CoCodex Server executable for
first-host setup, but it is never merged into the Client process. It retains
its own `~/.cocodex-server` state, database, TLS identity, PID, authority,
service/update flow, and detached lifecycle. Closing the Client does not stop
the Server.

The WebView cannot execute the Server binary directly. Rust exposes only
structured status, prepare/start/invite, and first-device bootstrap-approval
commands. The native layer constructs every argument, strips the admin token,
rejects OpenCodex/managed-runtime/Sunshine ports, and probes port availability
before initialization. A signed loopback invitation enrolls the host without
router hairpin support. Normal Server invitations retain the configured public
host, and manual firewall/forwarding/CGNAT guidance is preserved in the UI.

See ADR 0059 for the native Server bootstrap decision.

Native diagnostics are bounded, single-line, profile-redacted, and local at
`~/.cocodex/logs/desktop-runtime.log`.

See ADR 0049, ADR 0059, `docs/evidence/tauri-managed-client-runtime.md`, and
`docs/evidence/tauri-native-server-onboarding.md`.
