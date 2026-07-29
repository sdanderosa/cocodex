# ADR 0042: Signed trusted-device enrollment approval

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** First-device bootstrap, subsequent enrollment approval, resident
  Client and renderer trust boundaries, expiry, replay, and reconnect

## Context

Enrollment already proved possession of a new Ed25519 identity and consumed a
one-time invitation. The remaining approval was an unrestricted local Server
CLI mutation. That did not prove that an already trusted person reviewed the
new identity, did not bind the decision to the exact enrolled key bundle, and
could not support the required Stephen-approves-Kai product flow.

## Decision

Exactly one first device may be approved through a local-only
`bootstrap-approve` command. The database records a permanent
`device_bootstrap_consumed` marker. Bootstrap requires active server authority,
no approved devices, and exactly one unexpired pending enrollment. Revocation,
restore, or transfer never resets the marker. `approve` remains only a
deprecated alias for this one-shot bootstrap and cannot approve a second
device.

Every later decision is made by an authenticated approved resident Client over
TLS/WSS. Enrollment stores an immutable digest covering:

- the pinned TLS endpoint and stable Server identity;
- invitation ID, token-hash commitment, scope, and expiry;
- target device ID, display name, canonical signing fingerprint, and complete
  Ed25519/X25519 public-key bundle; and
- enrollment time, approval expiry, and expected revision.

The reviewing Client receives that raw attestation inside its resident process,
recomputes the fingerprint and digest, and rejects a wrong authority, duplicate
identity, expired record, or changed key. It exposes only display name,
fingerprint, a deterministic 64-bit comparison phrase, and timestamps to the
GUI. The person must type the matching phrase before Approve or Reject is
enabled.

The resident Client signs a separate length-prefixed decision transcript. It
binds the operation ID, target ID/fingerprint/enrollment digest, expected
revision, decision, stable Server identity and epoch, validity window, and
32-byte nonce. The GUI never supplies keys, digests, signatures, or nonces.

The Server verifies the authenticated approved actor and signature, then
rechecks active authority, actor status, target state, expiry, immutable
attestation, and revision inside one immediate SQLite transaction. The
operation row, target transition, approver, audit event, and revision commit
together. Exact replay returns the stored result without a second mutation;
altered replay, self-approval, concurrent decisions, stale authority, and
pending-device requests fail closed. Rejection and approval expiry retain the
identity as revoked so an invitation cannot be recovered or reused.

## Open-source reference and licensing decision

Syncthing's MPL-2.0 device-fingerprint and explicit-trust model informs the
permanent cryptographic identity and human comparison step. MeshCentral's
Apache-2.0 server/installed-agent boundary informs the authenticated Server
route and resident endpoint decision. Only concepts were adapted. No source
was copied and no new production dependency was added.

## Consequences

- Computer names, IP addresses, display names, and invitation possession are
  never approval authority.
- A compromised approved device can approve another identity; device
  revocation and project-key rotation remain the response.
- The comparison phrase assists out-of-band review; the full 256-bit
  fingerprint remains the cryptographic identity.
- Pending approval lasts 15 minutes. Expired legacy pending rows without an
  immutable attestation are revoked during migration.
- The three-process private-alpha path must bootstrap Stephen only, have
  Stephen's running Client sign Kai's approval over real WSS, and then prove
  Kai reconnects without reenrollment.

## Evidence requirement

Completion requires strict protocol/transcript tests, bootstrap permanence,
atomic exact replay, tamper rejection, migration tests, renderer redaction,
real TLS/WSS three-process enrollment, all CoCodex regressions, builds,
privacy scanning, and inherited OpenCodex tests.
