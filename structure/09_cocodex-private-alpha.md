# CoCodex private-alpha structure

This file defines the maintained subsystem boundaries for CoCodex. It extends,
but does not weaken, the OpenCodex invariants in the preceding structure files.

## Applications

| Application | Responsibility | State |
| --- | --- | --- |
| CoCodex Client | Existing OpenCodex proxy/runtime plus local collaboration bridge and UI | `~/.cocodex` plus unchanged explicit OpenCodex import/compatibility state |
| CoCodex Server | Internet-facing TLS/WSS collaboration authority | `~/.cocodex-server` |

They are separate processes and separately runnable packages. The client must
not read the server database. The server must not read client provider
credentials, Codex authentication, local files, or command output except content
explicitly published as a collaboration event.

## Private-alpha delivery order

1. Separate server package, configuration, SQLite migrations, health, and
   lifecycle.
2. TLS identity, invitation generation, device enrollment, approval, and
   proof-of-possession authentication.
3. Authoritative projects, chronological shared chat, sequence numbers, and
   reconnect cursors.
4. Client connection and signed remote-agent routing with local revalidation.
5. Per-device end-to-end encrypted private messaging.
6. Persistent offline queues and restart recovery.
7. Client collaboration UI and complete three-process test harness.

Do not start secondary networking, migration, remote-desktop, analytics, or
decorative UI work until that path passes.

## Internet-facing listener

The server exposes one configurable TLS port. WSS carries a strict versioned
protocol. HTTP on the same listener is limited to bounded health and
authenticated administration routes.

The alpha connection contract is a manually forwarded port. Automatic router
mapping and advanced traversal are later additions. They must not change the
protocol authority model or expose the local OpenCodex proxy.

## Authority invariants

- Server: identity status, membership, permissions, event order, task routing,
  ciphertext delivery, and reconnect history.
- Client: provider credentials, account/usage selection, Codex runtime, files,
  processes, applications, browser access, and emergency stop.
- Every remote execution needs both server authorization and local-client
  authorization.
- A compromised server does not automatically obtain a shell.
- A compromised client cannot rewrite authoritative shared history.
- Local OpenCodex/Codex behavior does not depend on collaboration availability.

## Local private-message history

Private contacts come from the Server's bounded approved-device directory.
The Server distributes public certificate metadata only; the resident Client
verifies the certificate and joins it to the explicit local fingerprint trust
store only after an independently confirmed fingerprint matches the current
directory entry. The GUI receives a safe contact projection and never a
certificate or public-key payload. A protected, bounded public-certificate
cache is re-verified on restart and bound to the Server authority so known
recipients remain usable for offline ciphertext queueing without crossing an
authority transfer. A terminal revoked-recipient rejection marks only that
encrypted-history entry as not sent and cannot head-of-line block later
durable events. Discovery is not authorization. See ADR 0036.

The Client owns a bounded `private-history.json` protected with the same
device-state ACL and atomic-write boundary as other sensitive local state. It
contains ciphertext only. Received messages retain their recipient ciphertext;
sent messages store a separate self-sealed local copy that is never sent to the
Server. The resident Client re-verifies and decrypts each entry before exposing
it to the GUI, which enables sender echo, offline-readable history, restart
recovery, and local search without putting plaintext on disk.

Outgoing entries use staged, queued, and accepted states and reconcile with the
durable outbox on startup. Accepted entries follow authoritative Server
sequence; persisted delivery/read receipts replay offline. Capacity pressure
never evicts an unaccepted sender copy.

This cache remains single-device and does not claim a ratchet, forward secrecy,
multi-device synchronization, or private-message backup. See ADR 0035.

## Atomic Co-Project bootstrap

The normal Client creation path is `project.create`, not Server CLI
pre-seeding. The resident owner generates one random project key and signs the
normalized project name plus its owner-only epoch-1 envelope.

The Server creates the project, owner row, epoch row, replay record, and opaque
owner key envelope in one immediate SQLite transaction. A committed
Client-created project is never observable without encryption state. Exact
reconnect replay remains idempotent after later membership changes;
incomplete, substituted, altered, or conflicting requests roll back
completely. See ADR 0037.

Adding Kai is a separate explicit consent boundary. Stephen's resident Client
must already trust Kai's certified fingerprint, seals the active project key
to Kai, and signs an expiring `project.invite.create`. The Server stores the
opaque pending invitation but does not add Kai. Kai's resident Client verifies
Stephen's certificate, its own local fingerprint trust, both owner signatures,
and the addressed envelope before enabling **Accept**. Kai's signed acceptance
atomically installs membership and the envelope; decline or cancel never does.
Expiry, revocation, and key rotation invalidate pending invitations. The
renderer sees only safe invitation metadata, while certificates, wrap keys,
sealed envelopes, signatures, and decrypted keys remain resident-only. See
ADR 0038.

## Test isolation

The mandatory harness launches one server and two clients as real processes.
Every process receives a unique:

- state root;
- database;
- port;
- device identity;
- account fixture;
- project directory;
- log destination.

Tests exercise the real TLS/WSS transport where practical. Direct function
calls may cover pure validation units but cannot substitute for the
three-process integration path.
