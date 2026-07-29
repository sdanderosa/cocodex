# ADR 0040: Device-revocation incident response

- **Status:** Accepted for the private-alpha security boundary
- **Date:** 2026-07-27
- **Scope:** Administrative device revocation, encrypted projects, local
  execution, reconnect, and owner recovery

## Context

ADRs 0019 and 0031 make an explicit project-member removal safe by coupling
membership removal to a complete project-key rotation. Administrative device
revocation is broader: one device may belong to several encrypted projects,
host agents, request work from other computers, hold current project-key
envelopes, and be offline when the administrator acts.

Marking only the device row as revoked blocks its next authentication, but does
not protect future project content already encrypted with a key the device
possesses. It also leaves remote work requested by that device running and
does not give surviving members a durable recovery signal after a server or
client restart.

## Decision

Revoking an approved device runs one SQLite immediate transaction. For every
encrypted project containing that device, the Server:

1. sets the device status to revoked;
2. disables agents hosted by the device;
3. terminalizes queued or running tasks where the device is requester or
   target;
4. deletes project-key envelopes sent by or addressed to the device;
5. sets the authoritative project-key epoch's `rotation_required` gate;
6. expires pending project invitations;
7. records a durable unresolved revocation incident and audit event; and
8. when the revoked device was the owner, deterministically promotes the
   earliest approved surviving member so recovery remains possible.

The revoked member remains in the authoritative roster with a revoked status
until the recovery owner performs the existing
`project.member.remove-and-rotate` operation. The resident Client—not the GUI
or Server—generates a new random project key and complete owner-signed
recipient envelope set. The same atomic operation removes the revoked
membership, advances the epoch, clears the write gate, and resolves the
incident. Exact replay remains idempotent.

The authorization sweep closes every live socket belonging to the revoked
device, clears its presence, and delivers a strict
`project.device-revoked` incident notice to approved surviving members. The
notice is replayed once per connection until the incident is resolved, so
server and client restarts cannot lose the recovery requirement. Task-summary
data is bounded on the incident frame, while cancellation commands are
delivered independently for every affected task hosted by a surviving device.

On receipt, a Client immediately marks the project rotation-required in its
protected key store, stops using the old epoch for writes, refreshes the
authoritative roster, and exposes only a renderer-safe incident summary. A
promoted owner can then use the explicit recovery action already backed by the
atomic remove-and-rotate path. No silent client-generated rotation is
performed.

An owner-only project has no eligible recovery owner. It remains durably
quarantined and unavailable for encrypted writes until a separately designed
lost-device recovery flow establishes a new trusted authority. The Server
does not weaken identity or key checks to make that case appear recovered.

## Open-source reference and licensing decision

This independently adapts Syncthing's permanent cryptographic device identity,
explicit trusted-device list, and unknown/revoked-device rejection model.
Matrix device-revocation and key-withholding behavior informs the requirement
that a revoked device receive no future project epoch. MeshCentral informs the
authoritative-server/local-execution boundary: the Server cancels and routes
authorizations, but never directly operates a remote shell.

The implementation reuses the existing MIT/ISC-compatible CoCodex and
libsodium components. It copies no Syncthing MPL, Matrix, MeshCentral,
RustDesk, Signal, GPL, or AGPL source and introduces no new dependency or
cryptographic primitive.

## Security consequences

- Revocation closes both authentication and future project-key access instead
  of relying on a disconnected socket or display-name change.
- A revoked requester cannot leave authorized work running on a survivor's
  computer; a revoked host cannot accept more work.
- Old ciphertext and old project keys already possessed by the revoked device
  cannot be erased. The epoch gate protects future accepted writes and the
  next rotation protects future ciphertext.
- Promotion is deterministic and limited to an already approved project
  member. It does not enroll a new device or create cryptographic trust.
- The Server retains only incident, membership, task, and envelope-routing
  metadata. It never receives the plaintext project key.
- Incident replay is durable, bounded, and authorized per project member.
  Resolution requires the same complete-recipient signed rotation as ordinary
  member removal.

## Evidence

The implementation is not considered complete until focused storage,
protocol, real TLS/WSS, resident-client, GUI-boundary, reconnect, build,
privacy, and inherited-regression tests pass and are recorded in a dedicated
evidence report.
