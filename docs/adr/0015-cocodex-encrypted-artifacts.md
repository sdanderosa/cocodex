# ADR 0015: CoCodex encrypted project artifacts

- Status: Accepted for the project-encryption migration
- Date: 2026-07-25
- Scope: artifact titles, summaries, type/status, and bodies when a project key exists

## Context

The legacy `artifacts` table and `artifact.*` frames made project handoffs
server-readable. That is useful for the earliest fixtures, but it violates the
project-content boundary once a project has an enrolled project key. Artifacts
also need to remain routable and idempotent without giving the server access to
their content.

## Decision

Use the existing signed XChaCha20-Poly1305 project-content envelope with
`recordType: "artifact"` and `recordId: artifactId`.

The client encrypts and authenticates the complete artifact record: artifact
type, title, summary, body, status, project ID, and optional task ID. The server
accepts only approved project members, checks the current key epoch and sender
signature, and stores the opaque envelope in `project_artifacts`. The only
server-readable columns are the routing fields needed for authorization and
ordering: project ID, optional task ID, author device ID, and server timestamps.

`artifact.publish` and `artifact.list` automatically select the encrypted
`project.artifact.*` transport when a local project key is available. Encrypted
publishes are durable in the existing protected outbox. The client verifies the
envelope sender and project key locally, validates the decrypted record, and
emits the existing artifact frame shape to the UI. Projects without a key keep
the legacy plaintext route for compatibility.

## Rejected alternatives

- Do not encrypt only the body while leaving titles or summaries in SQLite;
  those fields are project content too.
- Do not let the server decrypt artifacts to validate type, status, or task
  metadata; that would turn the server into a content authority.
- Do not copy implementation code from MeshCentral, Matrix, Signal, or other
  reference projects. Reuse the maintained libsodium dependency already chosen
  for CoCodex project envelopes.

## Consequences and remaining work

The server is blind to keyed artifact content and can still authorize,
deduplicate, list, and broadcast records. The legacy table remains for older
fixtures and must not be used to claim whole-project E2EE. Keyed agent task
prompts and results now use the same envelope boundary through ADR 0016;
encrypted local file-reference metadata is now defined by ADR 0030. Encrypted
file-content transfer, automatic key rotation after membership removal, and a
complete artifact UI are still later work.

## Evidence

- `apps/cocodex-server/tests/project-encryption-storage.test.ts` covers opaque
  persistence, member listing, idempotent retries, and signature rejection.
- `packages/cocodex-protocol/tests/protocol.test.ts` covers strict publish and
  list frame schemas.
- `tests/cocodex-project-encryption-session.test.ts` runs two real client
  sessions over TLS/WSS, publishes an encrypted artifact, checks that SQLite
  contains no title/body plaintext, decrypts it on the other client, and
  recovers it from a list after server restart.
