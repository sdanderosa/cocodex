# ADR 0049: Tauri-managed local Client runtime

- **Status:** Accepted (amended 2026-07-29)
- **Date:** 2026-07-27
- **Scope:** Installed CoCodex Client startup, local execution runtime,
  webview authority, state ownership, and Windows packaging

## Context

The shared React dashboard already ran inside Tauri, but the original desktop
runtime was hard-pinned to `127.0.0.1:10100` and shared `~/.opencodex`.
That made the installed CoCodex Client conflict with a user-managed OpenCodex
service and risked running persistent Codex integration from an app-owned
sidecar. Refusing a foreign listener protected ownership but left CoCodex
disconnected on a correctly configured home PC.

Port 10100 and the user's normal OpenCodex state remain governed by ADR 0050.
A desktop-local execution runtime is not authorization to change persistent
Codex routing, service configuration, shell hooks, or OpenCodex settings.

## Decision

Compile `src/cli/index.ts` with Bun into the target-triple-named
`cocodex-runtime` sidecar and bundle it through Tauri's
`bundle.externalBin`. Rust alone owns its lifecycle; the renderer receives no
shell or filesystem permission.

The desktop runtime is isolated as follows:

1. Reserve port 10100 for the independently managed OpenCodex/persistent
   injection path. Tauri neither probes, adopts, starts, nor stops that
   listener.
2. Select the first available IPv4 loopback port in the bounded range
   10101–10120. A listener that appears before or during startup is treated as
   foreign, left untouched, and skipped.
3. Accept readiness only when `/healthz` identifies OpenCodex, reports the
   selected port, and reports the exact PID held in Rust's child-ownership
   state.
4. Launch only the bundled sidecar with fixed `start --port <selected>`
   arguments and the environment marker `COCODEX_DESKTOP_MANAGED=1`.
5. Set `COCODEX_HOME=~/.cocodex` and
   `OPENCODEX_HOME=~/.cocodex/runtime/opencodex`. Existing `CODEX_HOME`
   remains available read-only for native Direct credentials.
6. In desktop-managed mode, skip Codex-shim recovery, injection journals,
   shell/system environment injection, shell hooks, persistent model sync,
   resume-history migration, and interactive update/star prompts.
7. Publish `state`, `owned`, `pid`, `port`, and `baseUrl` through the
   fixed Tauri command `managed_runtime_status`.
8. Bootstrap the renderer from that command and rewrite every managed
   loopback request to the current attested endpoint. Requests fail closed
   unless state is ready, the runtime is owned, and PID/port/base URL validate.
9. Constrain the WebView CSP to the explicit 10101–10120 HTTP/WebSocket
   endpoints. Port 10100 is not a permitted desktop connection target.
10. Keep the window hidden through initial readiness, supervise and restart
    only owned children, and terminate only the child retained in native
    ownership state when the application exits.

The separate internet-facing CoCodex Server, authority keys, firewall rules,
and port-forwarding lifecycle remain outside the desktop application.

## Relationship to ADR 0050

ADR 0050 is unchanged. Intentional system-wide Codex routing still uses port
10100 and must pass backup, process ownership, `/healthz`, `/readyz`,
provider/credential, autostart, atomic-write, and restoration gates.

The Tauri runtime does not perform that transaction and must never claim that
launching the desktop app completed persistent Codex setup.

## Alternatives rejected

- **Reuse a compatible process on port 10100:** crosses lifecycle and state
  ownership and makes closing/updating the desktop ambiguous.
- **Stop the port-10100 owner:** could terminate the user's service or another
  application.
- **Use one shared `~/.opencodex`:** couples PID files, runtime ports, config,
  logs, updates, and recovery journals across independent lifecycles.
- **Grant JavaScript shell permission:** turns renderer compromise into an
  arbitrary local-process boundary violation.
- **Use an unrestricted ephemeral port with a wildcard CSP:** broadens renderer
  network authority unnecessarily; the bounded range supports failover while
  remaining auditable.
- **Embed the CoCodex Server:** breaks the required Client/Server architecture.

## Consequences

The desktop Client can coexist with a healthy user-installed OpenCodex service
on port 10100. It owns a separate process, endpoint, configuration tree, PID
state, and logs below `~/.cocodex`. Provider credentials can still be read
from the native Codex home, but desktop startup cannot rewrite that home.

If every dedicated port is occupied or the bundled runtime cannot become
ready, the app shows a disconnected state and retries without killing any
listener. Native diagnostics remain bounded, single-line, profile-redacted,
and local under `~/.cocodex/logs/desktop-runtime.log`.

## Required evidence

- Rust tests for health PID/port identity, exclusion of port 10100, bounded
  diagnostics, and occupied-port selection;
- renderer tests for fail-closed ownership and attested endpoint rewriting;
- configuration tests for the bounded CSP, external binary, state environment,
  and absence of WebView shell permission;
- a compiled-process test proving isolated state and byte-for-byte preservation
  of a sentinel native Codex configuration;
- live coexistence evidence with an independently owned port-10100 service and
  Sunshine ports unchanged;
- fresh NSIS/MSI lifecycle, recovery, ownership, and shutdown smokes.
