# ADR 0046: Complete protected Server recovery archives

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** stopped-Server backup, disaster recovery, identity continuity,
  TLS continuity, and atomic state replacement

## Context

The original `backup` command wrote the SQLite database as plaintext base64 in
a signed JSON file. It omitted configuration, the Server Ed25519 identity, and
the TLS certificate/private key. `restore` therefore required the original
identity files to survive and could not recover a lost Server host. Its Windows
fallback also overwrote the live database directly when rename failed.

A recovery archive contains the keys that define the trusted Server authority.
It must remain confidential on an untrusted backup target, restore only as one
internally consistent authority, and never partially replace a stopped Server.
It is different from a planned authority handoff: cloning the same identity
onto two running hosts would create split brain.

## Decision

Replace the alpha backup command with a version-2 structured recovery archive.
The encrypted payload contains exactly:

- normalized endpoint configuration and the administration-token hash;
- checkpointed authoritative SQLite database;
- Server Ed25519 public/private identity;
- TLS certificate and matching private key.

Derive a 256-bit key from a passphrase with fixed scrypt parameters
(`N=65536`, `r=8`, `p=1`) and a random 128-bit salt. Encrypt and authenticate
the complete payload with AES-256-GCM and a random 96-bit nonce. Bind the
version, kind, creation time, public fingerprints, authority epoch, endpoint,
KDF parameters, cipher parameters, and payload hash as AEAD associated data.
Sign that metadata, authentication tag, and ciphertext with the archived
Server identity. The clear outer document contains operational metadata and
ciphertext only—never private keys, configuration secrets, database records,
or filesystem paths.

Require `--passphrase-file` or `COCODEX_BACKUP_PASSPHRASE` for both backup and
restore. Do not accept a passphrase argument that would enter shell history.
The removed version-1 database-only format was never released as a stable
format and is intentionally not accepted by the new command.

Before creating an archive, require a stopped active authority, checkpoint
WAL, verify SQLite integrity and foreign keys, and prove that the database,
loaded signing identity, identity files, configuration, TLS key, TLS
certificate, public host, and fingerprints agree.

Before restoring, decrypt and authenticate in memory, verify the Server
signature and every per-entry checksum, prove both private/public key pairs,
verify certificate hostname coverage, and validate the database identity,
epoch, active state, integrity, and foreign keys. Write only the six fixed
entries to a newly ACL-hardened sibling staging directory; there is no generic
archive extraction or caller-controlled entry name.

Replace the stopped state with same-filesystem directory renames. If prior
state exists, rename it to a timestamped `pre-restore` rollback directory,
activate the staged state, and validate it again at its final paths. Any failed
activation restores the prior directory. A successful replacement preserves
the rollback directory and reports its path for deliberate later cleanup.

## Open-source reference and licensing decision

Restic's design is the closest reference: encrypt all backup content, derive
keys from a password with scrypt, authenticate before accepting decrypted
content, and treat restoration as a verified snapshot operation. Restic is
BSD-2-Clause. CoCodex copies no restic code or format and adds no dependency;
it independently uses Node's maintained `crypto` implementation already
shipped with the Server runtime.

SQLite's documented WAL checkpoint model informs the stopped-database
checkpoint. CoCodex does not copy SQLite source; Bun's existing SQLite runtime
performs the operation.

## Security and operational consequences

The passphrase is not recoverable. A weak passphrase weakens an offline backup,
so operators should use a high-entropy secret stored separately. The archive
is capped at 1.5 GB and the database payload at 1 GB in this alpha to bound
untrusted in-memory parsing. Larger deployments need a future streaming,
chunk-authenticated format.

Restoring preserves the same Server identity, epoch, endpoint, and TLS pin.
Use it only after the original authority is stopped or irrecoverably lost. For
a planned move to a new host/identity or changed endpoint, use the
destination-bound authority-transfer flow from ADR 0017 so clients receive a
source-signed new identity and the source retires itself.

This decision protects private keys inside backup files. ADR 0047 subsequently
adds Windows DPAPI `CurrentUser` custody for the live Server authority and TLS
private-key files and makes restore rewrap them for the restoring Windows user.

## Evidence requirement

Tests must prove no private-key, database-canary, admin-token, or source-path
text appears in the archive; wrong passphrases and modified ciphertext fail
before creating a destination; an empty root recovers identical identity, TLS,
configuration, epoch, and database state; an initialized replacement retains
its previous state in a readable rollback directory; and the restored
standalone Server serves TLS successfully.
