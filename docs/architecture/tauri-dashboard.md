# CoCodex desktop dashboard

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

This starts the existing OpenCodex proxy when it is not already healthy, then
starts Vite on `http://127.0.0.1:4179` and opens it inside the Tauri window.
An existing proxy is detected and is not stopped when the Tauri process exits.

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
WebView2 prerequisites are installed. `bun run build:gui` remains the
browser/package build and is intentionally unchanged.

The desktop shell points its API base at `http://127.0.0.1:10100` during Tauri
development and production builds unless `VITE_API_BASE` is provided. The
OpenCodex proxy remains a separate local process, preserving the existing
client/server boundary and allowing the CoCodex Server to remain independently
hosted.

## Security boundary

The shell has only `core:default` capabilities and does not expose shell,
filesystem, or arbitrary command permissions to the webview. Its CSP permits
the local OpenCodex API and the secure WebSocket transports used by CoCodex.
Tauri's `tauri.localhost` asset origin is treated as a loopback origin by the
proxy's existing CORS policy; it does not grant remote origins local API
access.

The desktop wrapper does not replace the CoCodex Server. Enrollment,
authoritative shared state, encrypted private messaging, and local agent
execution continue to run through the existing TypeScript client/server
protocol and server process.
