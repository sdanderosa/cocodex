# ADR 0017: CoCodex Server authority handoff

- Status: Accepted for private-alpha server migration
- Date: 2026-07-25
- Scope: moving authoritative SQLite state from one CoCodex Server process to a prepared destination

## Context

The private alpha needs a recoverable server process without creating a
split-brain authority. A same-identity encrypted backup is not sufficient for a
machine move: clients need a verifiable endpoint and TLS change, and the old
process must be unable to continue accepting writes after the handoff.

## Decision

Use a two-phase, destination-bound handoff over the existing operator-managed
transfer file:

1. `transfer-prepare` creates a new destination Ed25519 identity, TLS
   certificate, configuration, and a `prepared` SQLite authority.
2. The source validates the target request, checkpoints its database, signs a
   certificate binding source and destination identities, the destination host
   and port, the destination TLS fingerprint, and `sourceEpoch + 1`, then
   encrypts the database with AES-256-GCM and signs the complete transfer.
3. After the encrypted file is durably written, the source marks its local
   authority `retired`. `start` refuses `prepared` and `retired` authorities.
4. The destination verifies the source signature, target identity/certificate,
   checksum, and epoch before replacing its prepared database and activating
   the destination identity.
5. Clients accept the source-signed `ccx-transfer1.` certificate only when its
   source identity matches the currently trusted server, its target TLS pin
   covers the target host, and its epoch is newer. The endpoint update is a
   single protected-file replacement.

The existing one-port TLS/WSS transport and manual forwarding remain the
baseline. Router mapping, relay, libp2p, and remote desktop are not required
for this handoff.

## Rejected alternatives

- Do not copy or retain the source identity on the destination; a distinct
  identity plus a signed handoff makes the ownership change explicit.
- Do not let a destination import an arbitrary snapshot into an active state;
  require a prepared target and exact identity/TLS matches.
- Do not let clients trust a new host or certificate based on DNS, display
  names, or IP addresses alone.
- Do not use a live dual-writer or best-effort last-writer-wins migration; the
  retired source and monotonically increasing epoch fence split-brain writes.

## Security and operational consequences

The transfer file is passphrase-encrypted and source-signed, but the operator
must still deliver the passphrase and authority code over a trusted channel.
The server database contains the same project/device records after import;
provider credentials remain client-local. Clients that have not accepted the
certificate continue to reject the new server identity until the owner gives
them the code. A failed or expired target request leaves the source active; a
failed import leaves the prepared destination unavailable.

## Evidence

`tests/cocodex-server-transfer-process.test.ts` launches real source and
destination CLI processes, enrolls and approves separate Stephen and Kai
devices over HTTPS/WSS, makes Stephen the project owner and Kai a member,
publishes pre-transfer chat and an encrypted private message, then exports and
imports the encrypted handoff. It proves source retirement and start refusal,
updates both clients to the destination TLS pin and identity at epoch 2,
rejects reuse of the old authority certificate, and reconnects both clients to
read the preserved project, chat, and ciphertext. Kai decrypts the recovered
message locally; the destination database is checked to contain ciphertext and
not its plaintext.
