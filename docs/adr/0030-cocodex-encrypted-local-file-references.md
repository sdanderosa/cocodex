# ADR 0030: Encrypted local file references

## Status

Accepted for the private-alpha keyed-project path.

## Context

CoCodex needs to let a project artifact identify a file that remains on the
artifact-producing client without revealing the local path, workspace
coordinates, file hash, size, or media type to the authoritative server. The
server is an honest-but-curious ciphertext router and may also receive malformed
or replayed frames from an approved but malicious member.

Matrix encrypted attachments keep file keys and integrity metadata inside the
encrypted room event while the content repository receives ciphertext. CoCodex
adapts the metadata-separation lesson but does not implement file-content
transfer in this slice. Existing project records already use the maintained
`libsodium-wrappers-sumo` XChaCha20-Poly1305 implementation, signed by the
device Ed25519 identity and bound to project, epoch, record type, record ID, and
sender through authenticated additional data.

## Decision

A file reference is immutable encrypted metadata attached to one existing
encrypted artifact:

- The publishing client resolves a path beneath an explicit workspace root,
  rejects traversal, absolute paths, symbolic links/junctions, and non-regular
  files, then computes the file size and SHA-256 digest.
- The plaintext contains a canonical POSIX-relative path, workspace mode and
  reference, optional branch/commit/media type, size, digest, project,
  artifact, reference, and host-device bindings.
- The client seals that object as project record type `file-reference`.
- The server derives host and author identities from the authenticated socket.
  It stores only project/artifact/device routing IDs, timestamps, and the opaque
  signed envelope in `project_file_references`.
- Only the artifact-producing device may attach its local reference in v1.
- Publish requires current project membership, an artifact in the same project,
  the current writable key epoch, the enrolled sender key, and a valid
  signature. Exact replay is idempotent; reuse of an ID with different routing
  data or ciphertext is rejected.
- A project has a hard 500-reference private-alpha cap, preventing accepted
  records from falling outside the bounded recovery list. Lists may return historical epochs. Clients with retained authorized key
  history decrypt each row independently, validate every wrapper/plaintext
  binding, and isolate a corrupt row rather than suppressing valid rows.
- Publish frames use the protected durable outbox. List subscriptions are
  reissued after reconnect and rebuild client state after server restart.

The server-readable/ciphertext boundary is:

| Server-readable | Encrypted |
| --- | --- |
| reference, project, artifact, host, and author UUIDs | relative path and filename |
| authoritative created/updated timestamps | workspace mode/reference, branch, commit |
| envelope version, epoch, nonce, sender key, signature | SHA-256, size, and media type |

The file bytes never enter this protocol. A remote member can inspect the
decrypted metadata but cannot resolve the local file. References are never
automatically added to agent context. Actual use must occur on the host client
and must re-check containment, file type, size, and digest immediately before
opening the file.

## Rejected alternatives

- Absolute paths or server-readable paths leak host identity and workspace
  layout.
- Bearer URLs, UNC paths, and network shares expand the trust boundary and are
  not device-bound capabilities.
- Server-side decryption would make the server a project-content authority.
- Automatic file-content injection into agent prompts violates the explicit
  artifact/context boundary.
- Large-file upload, relay, and streaming encryption are separate features.
  A future transfer ADR may evaluate libsodium secretstream; this ADR does not
  claim encrypted file transfer.

## Security and recovery consequences

Membership removal and rotation-required state block new references through the
existing key-epoch write gate. Historical ciphertext remains readable only to
clients that legitimately retain the historical key. Focused database,
resident-session, and outbox assertions use path and file-byte canaries.
The server remains unable to verify decrypted path or digest semantics, so
clients must fail closed on envelope, key, sender, schema, and binding errors.

## Evidence

- `packages/cocodex-protocol/tests/protocol.test.ts`
- `apps/cocodex-server/tests/project-encryption-storage.test.ts`
- `apps/cocodex-server/tests/project-encryption-server.test.ts`
- `tests/cocodex-project-encryption.test.ts`
- `tests/cocodex-project-encryption-session.test.ts`
- `tests/cocodex-outbox.test.ts`
