# ADR 0013: CoCodex project key envelopes and encrypted project content

- Status: Accepted for the first project-encryption slice
- Date: 2026-07-25
- Scope: project-wrap identity, opaque key delivery, and encrypted
  Final Goal/context/chat/prompt slices

## Context

The private alpha originally stored the shared Final Goal and structured
context as ordinary SQLite JSON. That is server-authoritative, but it does not
meet the product requirement that Co-Project content be encrypted. The server
must be able to order and authorize an encrypted update without receiving the
plaintext or a reusable project secret.

## Decision

Each client installation now has a dedicated X25519 project-wrap keypair in
addition to its Ed25519 signing keypair and separate private-message keypair.
The project-wrap private key stays in the protected client state directory and
is never sent to the server.

The client-side project encryption module uses maintained `libsodium` through
`libsodium-wrappers-sumo`:

- a random 32-byte project key is sealed separately to each enrolled device;
- the owner signs each key envelope with its Ed25519 identity;
- project context is encrypted with XChaCha20-Poly1305-IETF;
- the authenticated data binds project ID, key epoch, record type and ID,
  nonce, sender device, and canonical sender key;
- the encrypted content envelope is signed as well as AEAD-authenticated.

The server stores only canonical opaque envelope JSON in
`project_key_envelopes` and `encrypted_project_context`. It validates the
envelope schema, sender signature, approved-device membership, owner-only key
sharing, revision conflicts, and idempotent retries. It routes encrypted
envelopes to project members but never opens them. The client verifies the
sender fingerprint, unwraps the project key locally, and decrypts Final
Goal/context before exposing a normal local context frame to the UI.

Project key epochs are server-authoritative. An owner rotation is a
compare-and-swap operation that must include exactly one signed envelope for
every approved project member. Removing a member deletes its membership and
key envelopes; the removed client receives a revocation notice and marks its
local key ring unusable for new writes. Replayed rotations are idempotent and
stale expected epochs are rejected.

The same envelope format now backs the `project.chat.*` and
`project.prompt.*` paths. The server assigns an authoritative sequence and
persists only the opaque envelope in `project_chat_events` and
`project_prompt_updates`; the client decrypts `{content}` or `{update}` locally
and emits the existing chat-event or Yjs prompt-update shape to the UI. The
server deliberately does not apply encrypted Yjs updates because doing so would
require access to the prompt plaintext.

Legacy `context.get`/`context.update` remain available for the existing
private-alpha fixtures. They are explicitly server-readable and must not be
described as end-to-end encrypted. The encrypted path uses distinct
`project.key.*` and `project.context.*` frames and a protected local key store.

## Rejected alternatives

- Do not reuse private-message keys or a private-message session for project
  content.
- Do not invent an encryption algorithm or let the server generate project
  secrets.
- Do not copy RustDesk, MeshCentral, Syncthing, Matrix, or Signal source code.
- Do not silently reinterpret existing plaintext rows as ciphertext; a future
  migration must explicitly re-encrypt them on a trusted client.

## Consequences and remaining work

This slice proves complete encrypted-context, encrypted-chat, and encrypted
shared-prompt flows and keeps the server blind to those payloads. It does not
yet encrypt tasks, agent prompts/results, artifacts, or file references. The
legacy plaintext chat/context/prompt compatibility routes remain for old
fixtures and must be removed only after every record type has an end-to-end
migration.

## Evidence

- `tests/cocodex-project-encryption.test.ts` covers sealed-key/content round
  trips, wrong recipients, tampering, AAD transplant, and bounds.
- `apps/cocodex-server/tests/project-encryption-storage.test.ts` covers owner
  authorization, membership, signature checks, opaque persistence, replay, and
  revision conflicts.
- `apps/cocodex-server/tests/project-encryption-server.test.ts` exercises real
  WSS key/context/chat/prompt routing and restart-safe SQLite storage.
- `tests/cocodex-project-encryption-session.test.ts` runs two enrolled client
  sessions against a real server, initializes a project key, encrypts a chat
  message, Yjs prompt update, and Final Goal/context update, proves the stored
  rows omit the plaintext, and verifies that the other client decrypts all three
  locally.
