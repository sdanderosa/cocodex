# ADR 0019: Revocation-safe project-key rotation

- **Status:** Accepted for the private-alpha security boundary
- **Date:** 2026-07-25
- **Scope:** Project member removal, encrypted writes, and reconnect behavior

## Context

Project content is encrypted by enrolled clients, while the server owns
membership and ordered storage. Removing a member must therefore do more than
delete a membership row: a removed device may still possess the old project
key and could otherwise submit or read old-epoch ciphertext through a queued
socket or a legacy plaintext route.

## Decision

The server keeps a `rotation_required` bit beside the authoritative project
key epoch. Member removal runs in the existing immediate membership
transaction and atomically:

1. removes the membership and key envelopes for the removed device;
2. terminalizes queued/running agent tasks targeted at that device;
3. sets `rotation_required = 1`; and
4. notifies remaining connected members with a strict
   `project.key.rotation-required` frame.

Every encrypted write path (chat, shared prompt, context, artifact, task, and
agent result) checks the gate and current epoch. Legacy plaintext project
routes are rejected once encrypted mode has been initialized. The owner may
load the current local key for rotation, but only a complete owner-signed
rotation containing every remaining approved member advances the epoch and
clears the gate. Reconnect key responses include the authoritative epoch and
gate state so a disconnected client cannot miss the notice.

The client persists the gate in its protected project-key store. A same-epoch
envelope never clears it; a strictly newer accepted envelope does. Legacy
context known by a client at first key enrollment is durably re-encrypted before
the client switches to encrypted context reads. Competing migration retries
are treated as terminal outbox conflicts. Historical pre-key chat, prompt,
artifact, and task rows remain a separately tracked migration requirement.

## Alternatives rejected

- **Delete only the membership row:** rejected because old-key writes remain
  possible during the epoch lifetime.
- **Rotate only in clients:** rejected because a malicious or stale client can
  still submit old-epoch frames to the server.
- **Accept legacy plaintext while rotation is pending:** rejected because it
  bypasses the project-wide encryption boundary.
- **Invent a new cryptographic primitive:** rejected. The implementation keeps
  the existing signed envelope and X25519 wrapping design; no new encryption
  algorithm or dependency is introduced.

## Security and licensing

This decision reuses the existing CoCodex/Syncthing-style device-key and
envelope concepts and independently implements the transaction and protocol
gate. No RustDesk, MeshCentral, GPL, or AGPL source is copied and no dependency
license changes. The server stores only opaque encrypted payloads for keyed
routes; membership, epoch, task status, and delivery metadata remain
authoritative server state.

## Evidence

- `apps/cocodex-server/tests/project-encryption-server.test.ts` proves removal
  fanout, old-epoch write rejection, and successful post-removal rotation.
- `apps/cocodex-server/tests/project-encryption-storage.test.ts` proves atomic
  invalidation, epoch monotonicity, and context epoch checks.
- `tests/cocodex-project-encryption.test.ts` proves same-epoch local envelopes
  do not clear the pending gate.
- `packages/cocodex-protocol/tests/protocol.test.ts` strictly validates the
  rotation-required notice and key-result metadata.
