# ADR 0059: Native desktop bootstrap for the separate CoCodex Server

Status: Accepted

## Context

The desktop Client previously exposed only device enrollment. A first trusted
user therefore could not create the team from the native application even
though the separate CoCodex Server CLI already implemented initialization,
background lifecycle, invitations, device approval, network diagnostics,
backup, transfer, and service support.

CoCodex Server must remain a separate application and process. Giving the
WebView generic shell access or hiding the Server inside the Client process
would violate that boundary.

## Decision

The Tauri distribution includes a separately compiled `cocodex-server`
external binary in addition to the Client's loopback `cocodex-runtime`.
Bundling the executable for bootstrap does not merge their lifecycles:

- Server state remains exclusively under `~/.cocodex-server`.
- The Server owns its database, TLS identity, logs, PID, authority epoch, and
  update/service lifecycle.
- The Server starts as a detached process through its own CLI lifecycle.
- Closing the CoCodex Client stops only the Client-owned local runtime; it does
  not stop a running CoCodex Server.
- The Client renderer never reads or mutates the Server database.

The WebView still receives no shell or filesystem permission. Rust exposes only
three structured commands: safe status, prepare/start/invite, and first-device
bootstrap approval. All server arguments are constructed natively. No generic
command, path, environment, or argument vector crosses the renderer boundary.

Desktop setup validates the public host and dedicated port, rejects ports
10100-10120 and the complete Sunshine range 47984-48010, and probes both
wildcard and loopback availability before initialization. An occupied port
fails before Server state, firewall, or router configuration changes.

Initialization uses the Server's existing automatic UPnP/NAT-PMP/PCP,
Windows Firewall, and direct-hosting diagnostics. The renderer preserves a
manual-forwarding or CGNAT warning after enrollment. The host device receives a
signed one-time loopback invitation so local enrollment does not depend on NAT
hairpin support; invitations created normally continue to use the configured
public address.

The native bridge returns a redacted status projection and never returns the
Server admin token to JavaScript.

## Consequences

A first trusted user can choose **Host on this PC** or **Join with invite** from
the native onboarding screen. Host setup creates a real separate Server,
enrolls the local Client, bootstrap-approves the first device, and starts the
normal Client session.

A dedicated standalone Server installer/admin application remains a broader
distribution requirement. This ADR establishes the safe native bootstrap
boundary without claiming that later distribution work complete.
