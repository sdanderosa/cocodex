# ADR 0049: Tauri-managed local Client runtime

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** Installed CoCodex Client startup, local execution runtime,
  webview authority, and Windows packaging

## Context

The shared React dashboard already ran inside Tauri, but a production desktop
launch still required a separately installed and manually started OpenCodex
proxy. The development hook hid that dependency by starting a source process.
An installed application could therefore open directly into “Proxy not
connected” even though its UI files were present.

CoCodex also requires two separate applications. Making the desktop Client
self-contained must not collapse the authoritative internet-facing CoCodex
Server into the Client or expose a generic native shell to web content.

## Decision

Compile the existing `src/cli/index.ts` Client foundation with Bun into one
standalone `cocodex-runtime` executable for the active Rust target triple.
Declare that executable through Tauri's `bundle.externalBin` mechanism and
resolve it by its fixed sidecar name from Rust through the maintained
`tauri-plugin-shell` 2.3.5 library.

The Rust application owns this lifecycle:

1. keep the main window hidden during the initial readiness check;
2. probe only `127.0.0.1:10100` and parse the health response as JSON;
3. reuse a listener only when status, service identity, and port all match;
4. otherwise launch only the bundled `cocodex-runtime` with fixed
   `start --port 10100` arguments;
5. drain child pipes without placing runtime output in the renderer;
6. show the window after success or after a bounded timeout;
7. continue health supervision and retry failed owned starts with bounded
   backoff;
8. on application exit, terminate only the child held in native ownership
   state.

The webview retains only `core:default`. It receives no shell permission.
`tauri-plugin-shell` exists solely behind Rust's fixed sidecar call. The
separate CoCodex Server binary, authority keys, listener, firewall rules, and
port-forwarding lifecycle remain outside the desktop application.

The embedded UI may obtain its per-launch CoCodex API capability from the
exact Tauri origins `http://tauri.localhost`, `https://tauri.localhost`, or
`tauri://localhost`. These fixed values do not make arbitrary localhost
websites trusted. Cross-origin preflight allows the capability header, while
all subsequent CoCodex routes still validate the random capability.

The compiled sidecar carries the source package version as a compile-time
fallback because a standalone executable has no adjacent `package.json`.
Bounded native diagnostics are written locally with newlines removed and the
Windows profile prefix redacted.

## Alternatives rejected

- **Keep a manual proxy prerequisite:** repeats the exact failure an installed
  desktop application is meant to remove.
- **Grant JavaScript shell permission:** turns renderer compromise into an
  arbitrary local-process boundary violation.
- **Embed CoCodex Server:** breaks the requested separate Client/Server
  architecture and confuses local execution with authoritative shared state.
- **Bundle an unrelated runtime or reimplement OpenCodex in Rust:** duplicates
  tested provider, account, Codex, usage, and CoCodex bridge behavior.
- **Stop every existing listener on port 10100:** could terminate an
  independently managed user process. Only a natively owned child may be
  stopped.

## Consequences

The NSIS and MSI Client packages are self-contained with respect to their
local proxy runtime. They still require the normal Windows WebView2
prerequisite and a separately hosted CoCodex Server for collaboration.

A stale OpenCodex process running on a different fallback port can trigger the
inherited single-instance guard. The desktop app fails visibly, records a
local diagnostic, and retries; it does not kill that unowned process. A future
multi-port discovery design may negotiate a runtime URL through a native
bootstrap channel, but it must not weaken process ownership or CSP.

## Required evidence

- Rust unit tests for strict health identity and bounded diagnostics;
- configuration tests proving the external binary and lack of webview shell
  permission;
- a compiled-process test that starts the actual sidecar with isolated state
  and exercises health plus the capability-protected API;
- successful NSIS and MSI builds containing the sidecar;
- visible packaged-app checks for external-proxy reuse, automatic owned
  startup, recovery, private-alpha page access, and owned-only shutdown.
