# ADR 0014: CoCodex private-messaging crypto boundary

- Status: Accepted for the private alpha; forward-secret migration deferred
- Date: 2026-07-25
- Scope: one-recipient/device private messages, device certificates, and the
  ciphertext-only server mailbox

## Context

The private-alpha path needs encrypted offline delivery without putting
provider credentials, message plaintext, or attachment keys in CoCodex Server.
It also needs a device identity that a user can verify independently of a
display name or IP address. A home-grown ratchet would create a high-risk,
unreviewed protocol and would contradict the open-source reference rules.

## Decision

The private alpha uses maintained `libsodium-wrappers-sumo` sealed boxes for a
single recipient device. The sender wraps a bounded, domain-separated payload
with the recipient's X25519 messaging public key. The payload contains the
message ID, sender and recipient device IDs, creation time, text, and an
Ed25519 signature. The recipient verifies the signed payload against the
trusted device-key certificate before exposing plaintext to the UI.

The server treats the result as an opaque mailbox record. It validates approved
sender/recipient devices, message IDs, timestamps, replay hashes, and size
bounds, assigns a delivery sequence, and stores ciphertext plus routing
metadata only. Private plaintext is never included in project chat or agent
context automatically. The client keeps a durable outbox for offline delivery.

The implementation uses the ISC-licensed libsodium dependency already selected
in the lockfile. No RustDesk, MeshCentral, Syncthing, Matrix, Signal, or
libsignal source is copied.

## Rejected alternatives

- Do not invent a CoCodex-specific stream cipher, ratchet, or key-exchange
  protocol.
- Do not claim Signal compatibility, forward secrecy, break-in recovery, or
  multi-device sessions for sealed boxes.
- Do not use AGPL `libsignal` in the MIT distribution without an explicit
  licensing decision.
- The official Matrix bindings were reviewed in the TypeScript/Bun desktop
  path and did not meet the durable-store/packaged-runtime gate. Do not add
  them until the replacement runtime conditions in ADR 0022 are demonstrated;
  do not silently substitute a weaker or unreviewed implementation.

## Security invariants

- Device signing, messaging, project-wrap, and TLS keys remain separate.
- Device-key certificates bind the X25519 messaging key to the Ed25519 device
  fingerprint.
- Ciphertexts must be canonical base64url, contain the sealed-box overhead,
  and stay within the protocol's bounded payload size.
- The server rejects unknown, pending, or revoked devices and duplicate
  ciphertext delivery under a different message ID.
- Decryption failures are fail-closed and do not reveal whether a key or
  payload field was wrong.

## Consequences and migration

This is sufficient for the required private-alpha message flow and its
ciphertext-only persistence test. The implementation now also bounds and
canonicalizes ciphertext, commits the replay index transactionally, persists a
bounded mailbox cursor/receipt set, serializes delivery, and closes active
sockets after revocation. Sealed boxes do not provide forward secrecy after a
recipient-key compromise, message-key rotation, or multi-device session
management. A later migration must satisfy ADR 0022, select a maintained
Apache-2.0 Matrix crypto state-machine binding (or another compatible reviewed
protocol), define durable per-device session state and verification/revocation
UX, and run interop and failure-case tests before changing the wire format.
Until then, the client and documentation must continue to label the current
path as single-device private-alpha messaging.

## Evidence

- `tests/cocodex-private-messaging.test.ts` covers certificate binding, sealed
  box recipient isolation, signed outer-envelope binding, canonical ciphertext
  bounds, and fail-closed decryption.
- `apps/cocodex-server/tests/collaboration-server.test.ts` covers real WSS
  delivery, replay rejection, ciphertext-only SQLite persistence, and recovery
  by cursor.
