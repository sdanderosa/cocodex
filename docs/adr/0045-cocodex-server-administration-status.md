# ADR 0045: Authenticated aggregate Server administration status

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** CoCodex Server health, authority, endpoint, TLS, connection, and
  SQLite status

## Context

The public health route intentionally exposed only process liveness. The
authenticated administration route exposed an epoch, socket count, and TLS
fingerprint, which was insufficient to diagnose a private Server without
opening its database or logs. Operators need one bounded view of the running
authority, connected Clients and agent workers, trusted-device state, active
projects, storage health, and certificate expiry. That view must not weaken
the Server's ciphertext-only and local-execution boundaries.

## Decision

Keep `GET /healthz` public and minimal. Require the initialization admin token
for `GET /v1/admin/status`, compare only its stored hash, and return:

- process start time and monotonic non-negative uptime;
- active/retired authority state, epoch, and public identity fingerprint;
- configured bind/public endpoint and the single TLS/WSS port;
- TLS certificate fingerprint, validity interval, current validity, and days
  remaining;
- authenticated socket, distinct device, ready agent-worker, unauthenticated
  socket, and active-presence-project counts;
- bounded SQLite integrity, foreign-key, migration, page-size, logical-byte,
  device-state, project, membership, agent, task-state, private-ciphertext,
  encrypted-project-record, and audit-event aggregates.

The response never contains the admin token, token hash, state path, device or
project name, public key, prompt, result, message ciphertext, encrypted project
envelope, audit details, provider credential, or local workspace information.
The offline `cocodex-server status` command reuses the database aggregate but
does not claim live socket state.

## Open-source reference and licensing decision

MeshCentral's authoritative-server/installed-endpoint separation remains the
architectural reference: central administration observes and routes trusted
device state, while endpoint software owns local execution. CoCodex adapts
that boundary independently and copies no MeshCentral source. No dependency is
added; MeshCentral's Apache-2.0 license therefore creates no new distribution
obligation for this decision.

## Security and operational consequences

The admin bearer remains a high-value local secret and is never logged or
returned after initialization. The route is deliberately read-only. SQLite
`quick_check(1)` and `foreign_key_check` run only on an explicit authenticated
request, and their output is bounded before serialization. Logical storage is
the database page count multiplied by page size; it is not a physical
database/WAL/backup byte total.

Backup, restore, transfer, device revocation, project lock, authority
retirement, and shutdown keep their existing explicit command or signed WSS
boundaries. This status projection does not silently authorize those actions.

## Evidence requirement

A real standalone Server must reject unauthenticated status, accept the admin
token, report healthy empty state, and omit the token and state path. A
populated database test must prove aggregate counts while planting secret
canaries in names, prompts, ciphertext, and audit details. The compiled
three-process harness must additionally report two distinct approved Clients
and three ready agent workers over the real TLS/WSS transport.
