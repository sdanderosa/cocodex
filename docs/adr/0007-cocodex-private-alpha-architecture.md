# ADR 0007: CoCodex private-alpha architecture

- Status: Accepted for private-alpha implementation
- Date: 2026-07-25
- Upstream base: `357acee6`

## Context

CoCodex must extend OpenCodex without turning the local provider proxy into an
internet-facing collaboration server. The first mandatory delivery is a tested
private-alpha path with Stephen and Kai using separate clients and one
self-hosted server.

OpenCodex currently owns a Bun-native local proxy, local provider credentials,
Codex state injection, local account selection, usage reporting, management
APIs, and a React dashboard. Its listener and lifecycle are intentionally
coupled to local proxy behavior and native-Codex restoration.

## Decision

### Process boundary

Build two separately runnable applications:

- **CoCodex Client** extends OpenCodex and owns local Codex/provider/runtime
  behavior.
- **CoCodex Server** is a separate headless Bun process with its own
  configuration, SQLite database, TLS identity, logs, PID, and lifecycle.

The collaboration server is not a route inside `src/server/index.ts` and does
not reuse `/api/stop` or the OpenCodex service manager.

### Network boundary

The server exposes one configurable TCP port using TLS and WSS. Manual
Minecraft-style port forwarding is the guaranteed private-alpha path. The
invite carries the externally reachable address, port, pinned server
fingerprint, and one-time enrollment token.

Automatic router mapping, NAT traversal, relays, and libp2p remain later
requirements and cannot block the private alpha.

### Authority boundary

The server is authoritative for:

- users, devices, enrollment, approval, suspension, and revocation
- project membership and agent host assignment
- chronological chat and monotonic event sequence
- queued ciphertext and reconnect cursors
- task/artifact metadata and signed routing decisions

Each client remains authoritative for:

- provider and Codex credentials
- local usage and account selection
- device and private-message private keys
- local project paths and files
- local process, command, browser, and agent execution
- emergency stop and local permission policy

The server validates and routes a signed execution request. The destination
client independently validates the user, device, project, agent, host,
capability, expiry, nonce, and server authorization before invoking the local
runtime. The server has no raw-shell endpoint.

### State boundary

- Preserve OpenCodex state in `~/.opencodex` and Codex state in
  `$CODEX_HOME`.
- Store CoCodex Client state in a separate hardened `~/.cocodex` root.
- Store CoCodex Server state in a separate `~/.cocodex-server` root.
- Use SQLite transactions for authoritative server state and monotonic event
  ordering.

The client never reads the server database. The server never reads OpenCodex,
Codex, browser, provider, or local project credentials.

### Identity and enrollment

Each client installation creates an Ed25519 signing identity and a separate
encryption identity. The public-key fingerprint is the durable device
identifier; display name, host name, and IP address are metadata only.

Invitation tokens are random, scoped, short-lived, hashed at rest, single-use,
and consumed atomically when a valid proof-of-possession claim is accepted. The
TLS server fingerprint is verified before a client submits the invitation. New
devices remain pending until an existing trusted device approves the displayed
verification phrase.

Authentication uses signed challenges and short-lived device-bound sessions.
Sensitive events use signed envelopes, unique event IDs, nonces, expiry, and
per-device sequence numbers.

### Collaboration and messaging

- Use Yjs for collaborative prompt text and awareness state.
- Use Hocuspocus as the TypeScript WebSocket integration layer if its auth,
  queue, and persistence hooks satisfy the protocol boundary.
- Authorize the project/document before applying any Yjs update.
- Persist exact binary CRDT state or updates; do not reconstruct saved Yjs
  history through JSON.
- Evaluate the official Apache-2.0 Matrix crypto implementation for
  per-device private messages before selecting bindings.
- Store only private-message ciphertext and routing metadata on the server.
- Never expose private-message plaintext to an agent without an explicit,
  signed share action.

### Reconnection

Clients persist outbound event IDs and queue state locally. After reconnect,
the server deduplicates accepted event IDs, assigns authoritative sequence
numbers in arrival order, and returns missed events after the client cursor.
FIFO is required within each device queue; cross-device arrival order is
server authoritative.

Local OpenCodex and Codex behavior must not depend on collaboration
availability.

## Security invariants

1. The internet-facing port terminates only the CoCodex protocol.
2. The local OpenCodex proxy remains loopback by default.
3. Provider credentials and local proxy tokens never enter collaboration
   payloads.
4. Server authorization and client-local execution authorization are both
   mandatory.
5. Unknown, revoked, stale, replayed, expired, or wrongly scoped events fail
   closed.
6. The TLS fingerprint in the invite is pinned before enrollment.
7. Private-message plaintext and keys never reach server storage or logs.
8. CRDT convergence is not treated as authentication or authorization.

## Test strategy

The private-alpha gate launches three real child processes with separate state
roots, ports, identities, databases, account fixtures, and project paths:

1. CoCodex Server
2. Stephen Client
3. Kai Client

Tests exercise the actual TLS/WSS transport, invitation consumption, approval,
reconnection, authoritative ordering, bidirectional remote-agent routing,
client-local execution, streamed results, encrypted private messages, server
restart, durable offline queues, and local OpenCodex operation while offline.

Every security-sensitive negative path must prove that the local execution
adapter was not invoked and authoritative state did not advance.

## Consequences

- The first implementation contains fewer product features but each required
  private-alpha feature is connected and testable end to end.
- Advanced NAT traversal, relay, remote desktop, server migration, failover,
  and decorative UI remain deferred rather than removed.
- Some maintained dependencies will be added after exact API and transitive
  license review.
- Authentication, encryption, dependency, CI, and release changes require
  explicit security review under `MAINTAINERS.md`.
