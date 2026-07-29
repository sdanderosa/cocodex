# ADR 0039: Authoritative chat-scoped Co-Project collaboration

- Status: Accepted
- Date: 2026-07-27
- Scope: Multiple shared chats and chat-bound encrypted project records

## Context

A Co-Project must contain multiple chronological chats without letting content,
tasks, artifacts, prompt drafts, context, or presence from one chat silently
appear in another. The previous private-alpha implementation treated the
project ID as its only chat ID. That supplied one working General conversation,
but project-only routing metadata could not prove isolation once another chat
was created.

The Server remains authoritative for shared state and order. The Client remains
the only component that decrypts project content or executes local agents.

## Open-source reference and licensing decision

Hocuspocus and Yjs use a distinct authenticated document identity for each
collaborative document. CoCodex adapts that separation by assigning each prompt
document a `(projectId, chatId)` scope. Yjs remains the only CRDT dependency and
is MIT licensed. Hocuspocus remains an MIT-licensed architectural reference;
no source or dependency is copied into this slice because the existing
authenticated WSS transport already supplies ordering, reconnect, and
persistence.

Matrix room state demonstrates that a server-assigned conversation identifier
and authoritative membership checks must precede event acceptance. CoCodex
adapts the authority rule but does not federate, use Matrix identifiers, or
copy Matrix source. The relevant specifications and SDKs are Apache-2.0
compatible.

The existing ISC-licensed libsodium dependency supplies
XChaCha20-Poly1305. No new dependency and no AGPL, GPL, or MPL source is added.

## Decision

Every encrypted Co-Project has a deterministic General chat whose ID equals the
project ID. Additional chats use random UUIDs and are created through a strict,
expiring, device-signed `project.chat.create` request. The Server verifies
membership, the approved creator key, signature, nonce, lifetime, replay
identity, and a 64-chat project limit before committing the chat. It broadcasts
only authoritative chat metadata to project members.

New project-content envelopes use version 2. Their AEAD associated data and
Ed25519 signature transcript include both `projectId` and `chatId`. New Server
writes reject legacy version-1 content envelopes. Existing version-1 records
remain readable only from the deterministic General chat; they cannot be
opened or copied into a newly created chat.

These records are chat scoped:

- chronological encrypted messages and agent result events;
- collaborative Yjs prompt updates and snapshots;
- project context and Final Goal projection;
- tasks, dependencies, execution reports, and artifact inputs;
- artifacts and encrypted local file-reference metadata; and
- cursor, caret, and typing presentation.

Named agent definitions remain project scoped because the same configured
local agent may be addressed from multiple chats. A task is immutable to its
originating chat. Its dependency graph, selected artifacts, host execution
report, streamed results, and task-list projection must all carry that exact
chat ID.

SQLite migration 28 creates authoritative `shared_chats`, materializes General
for every existing project, and backfills all existing collaboration rows to
General. Composite primary keys separate prompt/context state by chat. The
Client keeps reconnect cursors and subscriptions under a composite
`projectId:chatId` key and the GUI clears/reloads scoped state when the selected
chat changes.

## Security invariants

- A chat ID alone never grants project membership.
- The Server assigns shared-event order and rejects writes to missing or
  archived chats.
- A signed or encrypted record cannot be transplanted between chats, even when
  both chats share the same project key.
- Dependencies and artifact inputs cannot cross a chat boundary.
- The host Client verifies the requester proof, Server dispatch proof,
  envelope binding, and local policy before execution.
- The host's signed execution report is bound to the persisted task chat.
- Private messages remain outside project chats and agent context unless
  explicitly shared.
- The Server stores ciphertext only for encrypted collaboration content and
  never gains local execution authority.

## Compatibility and limits

Legacy plaintext fixtures and version-1 encrypted records map only to General.
This compatibility path is explicit and may be removed only after historical
data migration is complete. Chat rename, archive/delete controls, per-chat
membership, moving records between chats, and cross-chat artifact sharing are
later product work. They are not simulated by project-wide fallback.

## Required evidence

- strict shared-chat and v2 envelope schemas;
- migration and foreign-key validation from every supported schema;
- signature, replay, expiry, membership, and chat-limit tests;
- AEAD/signature tests that reject a re-signed cross-chat transplant;
- real authenticated TLS/WSS creation, notification, write, list, and isolated
  recovery for General and an additional chat;
- cross-chat rejection for agent dispatch, dependencies, artifacts, execution
  reports, prompts, context, and file references;
- a real three-process private-alpha recovery run; and
- complete CoCodex, GUI, build, privacy, and inherited OpenCodex gates.
