# CoCodex desktop dashboard

Persistent Codex routing is governed by [ADR 0050](../adr/0050-cocodex-fail-safe-proxy-injection.md). Launching the dashboard alone is never sufficient evidence that `localhost:10100` may be injected into Codex.

The CoCodex dashboard is now a shared React/Vite frontend with two delivery
surfaces:

- the existing browser dashboard (`ocx gui` or the Vite dev server), and
- a Tauri 2 desktop shell under `gui/src-tauri`.

The frontend is not duplicated. Both surfaces consume the same `gui/src`
bundle, route state, localization, and CoCodex client bridge. The Tauri shell
only owns the native window and packaging boundary; it does not move project,
chat, device, or agent authority into Rust.

## Development

From the repository root:

```text
bun run dev:tauri
```

This compiles the same OpenCodex/CoCodex local runtime used by production,
starts the source proxy when it is not already healthy, then starts Vite on
`http://127.0.0.1:4179` and opens it inside the Tauri window. An existing
compatible proxy is detected and is not stopped when the Tauri process exits.

For browser-only development, the existing two-process flow remains available:

```text
bun run dev:proxy
bun run dev:gui
```

## Packaging

The Tauri application uses the production assets from `gui/dist`:

```text
bun run build:tauri
```

On Windows this produces NSIS and MSI bundles when the Rust toolchain and
WebView2 prerequisites are installed. The build first compiles
`src/cli/index.ts` into the target-triple-named `cocodex-runtime` external
binary required by Tauri, then embeds that binary beside the native
application. A destination computer does not need Git, Bun, Node.js, or Rust
to run the desktop Client. `bun run build:gui` remains the browser/package
build and is intentionally unchanged.

The desktop shell points its API base at `http://127.0.0.1:10100` during Tauri
development and production builds unless `VITE_API_BASE` is provided. On
startup, Rust identity-checks an existing listener and reuses it only when its
health response identifies the expected OpenCodex service and port. Otherwise
it starts the pinned bundled runtime, waits for readiness before showing the
window, monitors health, and retries with bounded backoff. Closing the
application stops only the child that application started. A reused external
proxy is never stopped.

The OpenCodex proxy remains a separate local child process, preserving the
existing client/execution boundary. The internet-facing CoCodex Server is
never bundled into or started by the desktop Client and remains independently
hosted.

## Security boundary

The shell has only `core:default` webview capabilities and does not expose
shell, filesystem, or arbitrary command permissions to JavaScript. Rust alone
uses `tauri-plugin-shell` to resolve and launch the one configured external
binary. Its CSP permits the local OpenCodex API and the secure WebSocket
transports used by CoCodex.

Only Tauri's exact embedded origins (`http://tauri.localhost`,
`https://tauri.localhost`, and `tauri://localhost`) join the browser
dashboard's capability boundary. Arbitrary `*.localhost` origins cannot obtain
a CoCodex capability. The proxy's CORS preflight explicitly allows the random
per-launch `X-CoCodex-Capability` header; protected routes still reject a
missing or invalid capability.

Native lifecycle diagnostics are bounded, single-line, user-profile-redacted,
and local-only under
`%LOCALAPPDATA%\CoCodex\logs\desktop-runtime.log`. Runtime stdout is discarded
and is not copied into the renderer.

The desktop wrapper does not replace the CoCodex Server. Enrollment,
authoritative shared state, encrypted private messaging, and local agent
execution continue to run through the existing TypeScript client/server
protocol and server process.

See ADR 0049 and `docs/evidence/tauri-managed-client-runtime.md`.
