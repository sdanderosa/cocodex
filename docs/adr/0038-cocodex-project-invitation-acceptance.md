# ADR 0038: Explicit encrypted Co-Project invitation acceptance

- Status: Accepted
- Date: 2026-07-26
- Scope: Adding a trusted device to an existing encrypted Co-Project

## Context

ADR 0037 made project creation, initial membership, and epoch-one key storage
atomic, but the creator could include any approved device without that
recipient's consent. Rate and ownership limits bounded the abuse; they did not
make unsolicited membership acceptable for broader use. The product requires
an explicit **Invite member** path and device trust must remain mutual.

## Open-source reference and licensing decision

Matrix room membership is the closest authority model. Its authenticated room
invite operation creates an invited state, and the invitee does not participate
until it joins. Only an existing room member with sufficient permission may
invite. CoCodex adapts that state transition and does not copy Matrix source.
The Matrix specification and SDK repositories are Apache-2.0 compatible.

Syncthing requires both devices to know and configure the other's
cryptographic device identity before they communicate. CoCodex adapts the
mutual-trust principle: Server approval makes a device discoverable, while the
owner and recipient must each independently trust the other's certified
fingerprint. Syncthing is MPL-2.0 and remains concept-only.

The existing ISC-licensed libsodium dependency continues to provide X25519
sealed boxes. No new dependency and no AGPL, GPL, or MPL source is copied.

## Decision

New encrypted projects contain only their creator. Adding another device uses
three authoritative states:

1. The owner selects a Server-approved, project-capable device whose exact
   fingerprint is trusted locally. The resident Client seals the current
   project key to that device and signs an expiring invitation transcript that
   binds the invitation, project, owner, recipient, key epoch, expiry, and
   exact envelope.
2. The Server verifies owner membership, the recipient's approved state, the
   current epoch, both owner signatures, non-membership, limits, and expiry.
   It stores one pending ciphertext-only invitation and notifies only its two
   parties.
3. The recipient resident verifies the owner's device certificate and local
   fingerprint trust, verifies and decrypts the addressed envelope in memory,
   and signs an accept or reject transcript. On acceptance, one SQLite
   transaction inserts membership and the already-verified current-epoch
   envelope, marks the invitation accepted, and writes an audit event.

The renderer receives only safe invitation metadata. Certificates, public-key
payloads, sealed keys, invitation signatures, and decrypted project keys remain
inside the resident process. The recipient persists the decrypted key only
after a matching accepted acknowledgement.

Invitations are single-recipient, single-use, bounded, and expire. Exact
create/response replay is idempotent. A changed invitation ID, project,
recipient, epoch, expiry, envelope, or decision fails closed. Rotation makes a
pending invitation stale; time expiry, device revocation, rotation-required
state, and epoch advancement mark affected pending rows expired and emit audit
events. The owner must issue a new envelope for the new epoch. Rejection does
not create membership or persist a project key.

## Security invariants

- Project creation cannot grant another device membership.
- Server approval or display-name equality never implies project consent.
- Only the current project owner can create an invitation.
- Only the addressed approved device can accept or reject it.
- Acceptance requires the recipient's device-key signature and mutual
  fingerprint trust in the stock Client.
- Membership and the current-epoch key envelope appear atomically.
- The Server stores the project key and invitation content only as opaque
  sealed-envelope JSON.
- Pending, rejected, expired, revoked, stale-epoch, and conflicting invitations
  cannot authorize project reads, writes, presence, or agent execution.
- Invitation envelopes and key material never cross the resident/renderer
  boundary.

## Consequences and limits

The two-person private-alpha bootstrap becomes owner creation followed by a
visible invitation and recipient acceptance. This adds one deliberate action
for a security boundary, not per-command approval. Device-level multi-user
grouping, invitations to an entire user account, invitation delegation,
project links, role selection, and ownership transfer remain later work.

## Required evidence

- strict invitation/transcript schemas and tamper tests;
- database migration, expiry, replay, authorization, rollback, and audit tests;
- real WSS owner/recipient/outsider routing tests;
- resident mutual-trust, envelope-redaction, reject, and restart/list recovery;
- GUI invite, accept, and reject controls using safe DTOs only;
- the three-process private-alpha harness creating owner-only, inviting Kai,
  and requiring Kai's acceptance before shared state or agent routing; and
- complete CoCodex, GUI, privacy, build, and existing OpenCodex regressions.
