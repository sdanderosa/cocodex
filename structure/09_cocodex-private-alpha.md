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
