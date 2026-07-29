# ADR 0047: Windows user-bound private-key custody

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** Client device keys, Server authority key, Server TLS key, legacy
  key migration, and disaster recovery

## Context

CoCodex separated signing, private-messaging, project-wrap, Server-authority,
and TLS keys and restricted their files with per-user NTFS ACLs. The files
still contained exportable PKCS#8 PEM. A process or backup tool able to read
the file could therefore copy the long-lived identity directly. This did not
meet the Windows-first requirement that private keys be bound to the signed-in
Windows user and not be stored as raw PEM or ordinary JSON.

The private-alpha crypto and TLS libraries currently require exportable key
bytes in process memory. Moving every key into non-exportable TPM/CNG hardware
would require different signing, X25519, libsodium, certificate, recovery, and
runtime adapters. That remains the preferred long-term direction where each
algorithm and recovery policy can be supported honestly, but it is not a safe
drop-in storage change.

## Decision

On Windows, protect each private key independently with Windows DPAPI
`CurrentUser` scope. Use a fixed, purpose-specific SHA-256 entropy value so a
protected device-signing key cannot be substituted for a messaging,
project-wrap, Server-authority, or TLS key.

Store only a strict versioned envelope containing:

- protection mechanism;
- non-secret purpose identifier;
- DPAPI ciphertext;
- a purpose-bound plaintext digest used only after successful DPAPI
  authentication to detect implementation or storage corruption.

The file remains protected with the existing current-user NTFS ACL. Invoke
`CryptProtectData` and `CryptUnprotectData` through the exact
`@primno/dpapi` 2.0.1 N-API binding. The prebuilt binding is embedded in the
compiled Windows Client and Server, so key material does not cross a shell,
command-line, environment-variable, or helper-process boundary. Fail closed
when the native binding is unavailable, native protection fails, the purpose
is wrong, the platform is wrong, ciphertext is modified, or the digest does
not match.

Normal Client startup unwraps the Ed25519 device-signing key and the separate
X25519 messaging and project-wrap keys into resident process memory. Normal
Server startup unwraps its Ed25519 authority key and TLS private key into the
headless process. Public keys and certificates remain ordinary public PEM.

When an existing private-key file begins with a legacy PEM header, first create
and ACL-harden a complete protected temporary envelope, then atomically replace
the legacy file. Preserve the public key and verify the same keypair through
the existing identity/TLS consumers. A malformed protected envelope never
falls back to PEM parsing.

Complete Server recovery continues to decrypt its passphrase-protected archive
in memory, but writes the restored private keys through this storage boundary.
This rebinds restored keys to the Windows user performing the restore; neither
the active root nor a newly restored root contains raw private-key PEM.

Cache a successfully unwrapped secret only inside the current process and only
while the exact protected file bytes and purpose still match. Every read still
rehardens, bounds, and reads the file before consulting that cache. This avoids
repeated native unprotection during one Client/Server lifetime without
accepting changed or oversized storage.

The current non-Windows compatibility path retains the existing user-only
filesystem boundary and labels its envelope `filesystem-user-only`. It is not
claimed as OS-backed encryption. The private alpha is Windows-first; a
production cross-platform release must select and test an OS keyring or
hardware-backed adapter before claiming equivalent custody.

## Reference and licensing decision

Microsoft's documented `CryptProtectData` model is the platform
security primitive: `CurrentUser` normally decrypts only for the same Windows
logon on the same machine, while any process already running as that user may
request decryption. CoCodex reuses `@primno/dpapi` 2.0.1 and its
`node-gyp-build` 4.8.4 loader. Both are MIT-licensed, their notices are
preserved in `THIRD_PARTY_NOTICES.md`, and the exact versions are locked in
the root lockfile and private-alpha shrinkwrap. No Microsoft source or binary
is copied.

Syncthing remains the open-source architectural reference for permanent
cryptographic device identity, explicit fingerprints, and rejecting unknown
devices. It is MPL-2.0 and remains concept-only; no Syncthing key-storage code
is copied. CoCodex differs by maintaining separate keys per protocol role and
wrapping their exportable alpha representation with DPAPI.

No new cryptographic algorithm or CoCodex-designed encryption scheme is
introduced. The native dependency replaces the previous PowerShell/.NET
adapter after real Windows CI showed that repeated Windows PowerShell children
could hang under constrained runners even though DPAPI itself remained
available.

## Security consequences

DPAPI protects keys at rest from another local account or an offline copy of
the files. It does not protect against malware already executing as the same
Windows user, process-memory inspection after unlock, or a fully compromised
host. The existing explicit device trust, revocation, project-key rotation,
and encrypted Server recovery remain necessary.

Current-user DPAPI is normally machine/user bound. Copying a live state
directory to another PC or account is not a migration mechanism. Use fresh
Client enrollment for a replacement device and the passphrase-protected
Server recovery command for disaster recovery. An administrator-forced
password reset can make DPAPI material unrecoverable depending on domain
recovery configuration.

A Server initialized or restored by an interactive account cannot later be
started as LocalSystem or another Windows service account. The future service
installer must choose its final service identity first and initialize or
restore under that identity; account rebinding is unsupported in this alpha.

## Evidence requirement

Tests must prove real Windows DPAPI round-trip, absence of plaintext canaries
and PEM headers on disk, wrong-purpose rejection, ciphertext-tamper rejection,
oversized-file/ciphertext rejection before unprotection, legacy PEM migration
without identity change, stable Client/Server reload,
protected recovery restore, compiled Client/Server startup, and the complete
two-client Server-restart path. The restart test must also retain the mailbox
race regression: an outbound acknowledgement may not advance the inbound
cursor past an earlier ciphertext from another device.
