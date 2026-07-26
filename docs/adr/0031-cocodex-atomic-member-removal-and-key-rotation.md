# ADR 0031: Atomic project-member removal and key rotation

- **Status:** Accepted for the private-alpha security boundary
- **Date:** 2026-07-26
- **Scope:** Owner revocation UX, project-key epochs, agent cancellation, and reconnect

## Context

ADR 0019 made member removal fail closed by setting a server-side
`rotation_required` gate. That two-step safety boundary prevented old-epoch
writes, but it left an operational gap: an owner still had to discover the
remaining devices' wrap keys, construct a complete rotation, and submit it
after removal. A crash between those steps could leave the project safely
blocked but unusable.

The private-alpha owner needs one connected action that removes a device,
stops work involving that device, and immediately creates the next usable key
epoch without exposing project keys to the server or renderer.

## Decision

The server exposes an authoritative, bounded `project.member.list` roster.
It contains approved project devices, roles, signing fingerprints, and the
device-signed key certificate each client publishes after authentication.
The certificate binds the enrolled Ed25519 identity to its messaging and
project-wrap X25519 keys. The resident Client accepts a remote wrap key only
when the certificate signature and roster fingerprint match and that exact
fingerprint is in its explicit trusted-device store. The GUI receives only
device IDs, display names, roles, fingerprints, and a local verified/unverified
status.

An owner uses `project.member.remove-and-rotate`. The GUI supplies only the
project and target device IDs. The resident Client:

1. requires a current local project key and cached authoritative roster;
2. verifies its own roster wrap key matches its local cryptographic identity;
3. generates a new random project key;
4. signs one sealed epoch envelope for every remaining approved member; and
5. persists the exact command in the protected durable outbox before delivery.

The server verifies owner authority, target membership, expected epoch,
signatures, unique recipients, and equality with the complete remaining
approved recipient set. One SQLite immediate transaction then removes
membership, disables agents hosted by the removed device, terminalizes queued
or running tasks where the device is either requester or target, deletes its
key envelopes, installs all next-epoch envelopes, advances the epoch, clears
the rotation gate, and records both removal and rotation audit events.

The request ID is the rotation ID. Migration 25 persists an immutable operation
record containing the exact project, owner, removed member, committed epoch,
envelope set, cancelled tasks, and timestamp. Exact replay returns that
committed result even after later key rotations; changed replay content fails.
Only the first execution sends cancellation, presence, membership, and key
fanout side effects. A semantic membership, epoch, or recipient-set conflict
is terminal for that exact outbox event so it cannot block newer work. The
owner must refresh the roster before retrying.

Removal is pushed to online clients. On reconnect, the authoritative project
list also reconciles the local key store: a locally known project absent from
the server list is marked revoked, its subscriptions are cleared, and its
local agents are emergency-stopped. This covers a device that was offline
during removal.

Migration 24 removes the historical agent row's foreign-key dependency on an
active project-membership row. Agent definitions and task history remain
available for audit, while removed hosts are disabled. The migration rebuild
temporarily disables SQLite foreign-key enforcement outside the transaction,
then re-enables it and rejects the database unless `foreign_key_check` is
empty.

Migration 25 adds the signed device-certificate directory and immutable atomic
removal operation records. A client that receives authoritative
not-a-project-member rejection purges every queued write for that project.
Project-list reconciliation performs the same purge, marks local keys revoked,
clears subscriptions, and emergency-stops hosted agents. A strictly newer
valid envelope can restore access only if the server later re-adds the device.

The older remove-then-rotate protocol remains compatible and fail closed via
ADR 0019. The owner GUI uses only the atomic path.

## Reuse and licensing

This independently combines Syncthing-style device-bound identity,
MeshCentral-style authoritative routing/local execution, and the existing
libsodium sealed-key-envelope design. It introduces no new cryptographic
algorithm or dependency and copies no RustDesk, MeshCentral, Syncthing,
Matrix, Signal, GPL, or AGPL source.

## Security consequences

- The removed device is excluded from the new epoch and cannot use old-epoch
  frames because the server authorizes membership and current epoch on every
  encrypted route.
- A removed requester cannot leave work running on another member's host; a
  removed host cannot keep queued work.
- The server sees membership and envelope routing metadata but never receives
  plaintext project keys.
- The renderer cannot choose recipient wrap keys or inspect sealed envelopes.
- The server remains authoritative for membership and certificate delivery,
  but cannot silently substitute a survivor wrap key without failing the
  device signature, enrollment-key match, or recipient's explicit fingerprint
  trust check. A future transparency or cross-signed device-directory design
  could further reduce equivocation risk, but is not implied by this alpha.
- Revocation does not erase historical ciphertext already possessed by a
  removed device. It protects future epochs and future authorized access.

## Evidence

- `apps/cocodex-server/tests/project-encryption-storage.test.ts` proves atomic
  rollback, exact recipients, replay, agent disabling, bidirectional task
  cancellation, audit state, and foreign-key integrity.
- `apps/cocodex-server/tests/database-migration.test.ts` preserves existing
  agent/task rows while removing the obsolete membership parent constraint.
- `tests/cocodex-project-encryption-session.test.ts` exercises roster,
  removal, rotation, online revocation, a third surviving device, continued
  encrypted chat, resident-session replacement, server restart, and durable
  offline replay through real authenticated TLS/WSS sessions.
- `tests/cocodex-outbox.test.ts` proves durable recovery and strict
  acknowledgement.
- `packages/cocodex-protocol/tests/protocol.test.ts` and
  `tests/cocodex-gui-bridge.test.ts` prove strict frames and the renderer
  boundary.
