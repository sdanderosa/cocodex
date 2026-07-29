# ADR 0054: Sunshine host-service protection

Status: Accepted

## Context

CoCodex can bind a Server port, request automatic router mapping, create a Windows Firewall rule, and stop or restart a directly launched CoCodex Server. On a host that also runs Sunshine, those powers must never alter Sunshine's network identity, occupy or remap its listener ports, or signal a Sunshine process because a stale CoCodex PID file happened to contain the same PID.

## Decision

### Sunshine non-interference clause

CoCodex must leave Sunshine's host IP configuration and every Sunshine TCP/UDP listener port untouched. CoCodex may read process, service, interface, and listener state for diagnostics and ownership checks only. It must never bind, reserve, forward, remap, firewall, stop, restart, reconfigure, or otherwise mutate Sunshine's IP address, network interfaces, service, processes, or ports. A CoCodex operation that cannot prove it is outside that boundary fails closed without changing host networking.

CoCodex treats TCP/UDP ports 47984 through 48010 inclusive as a protected Sunshine range. Configuration load and creation, Server binding setup, automatic port mapping, and Windows Firewall setup fail closed when a protected port is requested.

CoCodex does not change a host IP address or network-interface IP configuration as part of Server setup. The only permitted Windows network mutation is a port-specific inbound firewall rule for a non-protected CoCodex Server port; automatic router mapping is likewise limited to that non-protected port.

Before direct-process stop or restart can send `SIGTERM`, CoCodex must query the configured local TLS `/healthz` endpoint and prove all of the following in one response:

- the response is healthy;
- `service` is `cocodex-server`;
- `protocol` is `1`;
- `processId` exactly equals the PID about to be signaled.

Missing, stale, foreign, or unhealthy endpoints deny signal authority. A process merely occupying a port or matching a stale PID file is never stopped. This includes Sunshine and the foreign user-installed OpenCodex listener on port 10100.

## Consequences

Users cannot configure CoCodex Server inside Sunshine's reserved range, even if an individual port appears idle. This deliberately trades a small range of available ports for a stable, auditable safety boundary. Existing configurations in that range fail closed on load and require choosing a different CoCodex port; CoCodex does not repair them by changing Sunshine.

Regression coverage checks every protected port, bind/mapping rejection, exact process ownership, signal ordering, and the absence of Windows IP-configuration commands.
