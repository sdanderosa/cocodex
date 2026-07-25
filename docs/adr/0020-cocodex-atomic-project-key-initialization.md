# ADR 0020: Atomic project-key initialization

- Status: Accepted
- Date: 2026-07-25
- Scope: first project-key enrollment and client/server acknowledgement

## Context

The first project-encryption slice created a key locally and sent one
`project.key.share` request per approved member. A dropped connection or a
rejected recipient could therefore leave the client using an encryption key
for which the server had persisted only a partial recipient set.

## Decision

Project initialization uses one strict, versioned `project.key.initialize`
frame. The owner submits one signed epoch-1 envelope for every currently
approved project member. The server verifies the owner, membership, unique
recipients, signatures, and complete recipient set before inserting all
envelopes and the epoch row in one SQLite immediate transaction.

The server replies with `project.key.initialized` carrying the authoritative
envelope set and an idempotent `created` flag. The initialization request ID is
recorded as an initialization transaction marker, so the same request can be
replayed after a reconnect without creating a second epoch. The older
single-envelope share route remains available for compatibility and explicit
key delivery, but it cannot make a partial batch look like an initialization.

The client stages the generated project key before sending the batch, keeps the
exact frame in memory until acknowledgement, replays it after a transport
reconnect, and removes the staged key if the server rejects the transaction or
returns a mismatched acknowledgement. The key is never sent to the server.

## Reuse and licensing

This is an independent protocol and transaction adaptation inside the MIT
CoCodex/OpenCodex fork. It reuses the existing maintained `libsodium` envelope
implementation, SQLite transaction boundary, Ed25519 device signatures, and
Syncthing-style device-bound identity concepts. No RustDesk, MeshCentral, Yjs,
Syncthing, Matrix, Signal, GPL, or AGPL source code is copied, and no new
cryptographic primitive is introduced.

## Security considerations

- A non-owner cannot initialize a project key.
- A batch cannot omit an approved member, duplicate a recipient, target an
  unapproved device, use another epoch, or use an invalid owner signature.
- SQLite rollback on any validation/insert failure prevents partial envelopes
  and prevents the server from entering encrypted mode accidentally.
- Replay uses the original request ID and exact envelope set; changed content
  is rejected as a replay conflict.
- The server still sees routing metadata and pre-key legacy rows. Historical
  plaintext migration, encrypted file references, and ratcheted private
  messaging remain separate release-gate work and are not implied by this ADR.

## Evidence

- `packages/cocodex-protocol/tests/protocol.test.ts` validates strict batch and
  acknowledgement frames.
- `apps/cocodex-server/tests/project-encryption-storage.test.ts` proves
  complete-member validation, atomic rollback, and idempotent replay.
- `tests/cocodex-project-encryption-session.test.ts` exercises initialization
  through real TLS/WSS sessions and local decryption.
- `tests/cocodex-private-alpha-process.test.ts` exercises the batch path in the
  three-process alpha harness.
