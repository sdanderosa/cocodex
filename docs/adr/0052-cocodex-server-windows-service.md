# ADR 0052: Optional same-user CoCodex Server Windows service

- **Status:** Accepted
- **Date:** 2026-07-28
- **Scope:** Standalone CoCodex Server background startup on Windows

## Context

The standalone Server supports an ordinary user-level background process, but
the product brief also requires an optional Windows service. Server authority
and TLS private keys are protected with DPAPI `CurrentUser`; LocalSystem or a
different service account cannot safely reuse state initialized by the signed-in
operator. The inherited OpenCodex proxy has a separate lifecycle and service
identity and must not become coupled to Server administration.

## Decision

Add an explicit `cocodex-server service install|start|stop|status|uninstall`
surface on Windows. It owns the distinct SCM id `cocodex-server` and stores its
pinned WinSW executable, XML, and rolling logs below the selected Server state
root. It never invokes the OpenCodex service manager or uses proxy port 10100.

The service runs as the current interactive Windows account. Fresh installation
uses WinSW's interactive credential prompt, never stores a password in XML, and
verifies the resulting `SERVICE_START_NAME` before startup. Installation first
loads the Server configuration and both DPAPI-protected private identities under
that account. Service XML uses absolute executable, CLI, and state-root paths,
automatic delayed startup, bounded restart-on-failure, and a graceful stop
timeout.

Installation and repair fail closed when SCM state is unknown, the selected
state root differs from an existing registration, account or startup
verification fails, a direct Server process is already running, the configured
port is occupied, or TLS health does not become ready. A failed fresh install is
stopped and unregistered while Server configuration, database, identities, and
recovery material remain untouched. An existing registration is not silently
rebound to another state root.

`service stop` stops only the registered Server service. It never terminates an
unrelated process or an unknown port owner. `service uninstall` preserves all
Server state and retained verified WinSW assets for recoverable reinstall.

## Security and operational consequences

Service mode is opt-in and may require UAC plus the current user's Windows
credentials. Ordinary user-level `start`, `stop`, and `restart` remain the
default and require no administrative installation. DPAPI state is not portable
between service accounts; migration continues through protected Server recovery
or authority transfer.

The service registration is application infrastructure, not Server authority.
It cannot execute Client commands, access local workspaces, load provider
credentials, or control the inherited proxy.

## Evidence requirement

Unit tests must prove XML escaping, same-user/no-password configuration,
automatic delayed startup, independent service identity, pinned-binary
verification, unknown-SCM fail closure, state-root mismatch rejection, fresh
install rollback, stopped-service repair, and state-preserving uninstall.
Process tests must prove successful readiness and cleanup, stopped-service
recovery, occupied-port failure without terminating the owner, and restart-style
automatic configuration suitable for reboot. Windows release evidence must
record SCM account/start-mode queries and exact process/port ownership without
using port 10100.
