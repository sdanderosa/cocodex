# ADR 0058: Owner-attested historical plaintext migration

Status: Accepted and implemented

## Context

Projects created before project-key initialization may retain Server-readable Final Goal/context, shared chat and agent-result rows, Yjs prompt state, artifacts, and agent task prompts. ADRs 0013, 0015, 0016, 0019, and 0020 require a trusted client to re-encrypt those records. The Server cannot generate a project key, encrypt on the owner's behalf, silently reinterpret plaintext as ciphertext, discard attribution/order, or claim whole-project encryption while any legacy project-content row remains.

The authenticated WebSocket payload limit is bounded, and one legal legacy record may be larger than the old 64 KiB connection limit. Migration must therefore be paged, restart-safe, idempotent, and atomic at the plaintext-removal boundary.

## Decision

The approved project owner performs one Server-coordinated migration transaction per project and key epoch.

1. `project.migration.prepare` freezes a canonical inventory of every legacy project-content row, computes a SHA-256 snapshot digest, records a durable migration ID, and gates all legacy and encrypted project-content writes.
2. The owner pages through that frozen inventory over authenticated WSS. Inventory pages carry only content the Server already stores and are delivered only to the approved owner.
3. The resident Client loads the current protected project key and encrypts each item locally with the existing signed XChaCha20-Poly1305 project-content envelope. No project key or reusable secret reaches the Server.
4. Encrypted items are uploaded in bounded pages and stored in a migration staging table. `(migration ID, source kind, source ID)` is idempotent. A retry with different ciphertext for an already staged item is rejected; inventory pages identify staged items so a restarted Client skips them.
5. Every staged item binds its exact legacy source digest and encrypted-envelope digest. The owner signs a canonical final manifest containing the Server fingerprint, project ID, migration ID, key epoch, snapshot digest, and all sorted source/envelope mappings.
6. `project.migration.commit` verifies current ownership, membership, key epoch, owner signature, unchanged snapshot digest, exact one-to-one inventory coverage, expected record type/ID/chat scope, and every envelope signature. One immediate SQLite transaction then replaces every legacy class and marks the migration complete. Any failure preserves all legacy rows and staged ciphertext.
7. The Server broadcasts `project.migration.completed`. Clients clear affected encrypted cursors and request fresh snapshots because chat/prompt sequence space may have been rebuilt to place historical records before newer ciphertext.

The inventory covers:

- each chat-scoped Final Goal/context row;
- each legacy chat event, including `agent_task_events` result metadata;
- one canonical current Yjs document state per chat, after verifying it represents the stored update log;
- every legacy artifact, including title, summary, type, status, and body;
- every legacy agent task prompt and its signed routing metadata.

Owner-encrypted historical records retain original author/requester attribution as Server-authoritative migration metadata distinct from the envelope signer. Recipients verify the owner envelope and the completed migration ID before displaying original attribution. New records continue to require envelope sender and routable author equality.

## Write and recovery policy

- A project with a pending/required migration rejects chat, prompt, context, artifact, file-reference, task, result, lifecycle deletion, and ordinary key rotation writes except migration control itself. Emergency member removal and leave completion remain available: they atomically invalidate and erase uncommitted staging before revocation and successor-key rotation proceed.
- Project initialization detects legacy content and enters `required` atomically with epoch creation. A schema migration marks already-keyed projects with legacy rows as required.
- Prepare is idempotent while the snapshot is unchanged. Staging survives Server and Client restart. A changed source snapshot invalidates uncommitted staging and requires a new transaction; it is never merged heuristically.
- No user-facing cancellation can declare a keyed legacy project complete or re-enable encrypted writes. A changed snapshot, key/owner mismatch, or emergency revocation invalidates staging; the owner must prepare a fresh migration.
- No non-owner can inspect inventory or stage/commit records.
- The Server never logs inventory plaintext, encrypted payloads, project keys, or manifest contents.

## Ordering

Chat and prompt rows are rebuilt in deterministic order using original accepted timestamps, original legacy sequence, existing encrypted sequence, and stable record ID tie-breakers. Rebuilt global sequence values are newly allocated above the current table maximum. Existing encrypted envelopes remain byte-identical. Cursor reset is mandatory; silently appending old records after new records is rejected.

Artifacts preserve IDs and timestamps. Context preserves the authoritative revision. Completed/failed historical tasks retain metadata and receive an opaque task envelope; queued/running legacy tasks block prepare so a prompt can never change representation during execution.

## Payload bounds

WSS has a separate bounded maximum large enough for one maximum project envelope plus protocol overhead. Inventory and staging are paged below that bound. HTTP management limits remain unchanged. Every array, string, byte payload, page count, item count, and total staged byte count is schema- and Server-bounded.

## Rejected alternatives

- Server-side encryption or key escrow.
- Deleting or merely hiding plaintext rows.
- Migrating only context while leaving chat/prompt/artifact/task content readable.
- Appending old chat rows after new encrypted history.
- Accepting owner assertions without a digest-bound signed manifest.
- Best-effort per-row deletion before all record classes are verified.
- Requiring every historical author device to be online; revoked or lost devices would make migration impossible.

## Required verification

Protocol tests must reject extra fields, duplicate mappings, wrong record types/scopes, oversized pages, malformed digests, and noncanonical signatures. Storage tests must cover every record class, mixed legacy/encrypted ordering, idempotent restart, changed snapshots, missing/extra staging, wrong owner/epoch, invalid envelope/manifest signatures, queued/running task refusal, rollback on injected late failure, and plaintext canary absence after commit. An authenticated two-client TLS/WSS test must partially stage, restart the Server, recover staged envelope digests, finish commit, and broadcast the cursor reset. A reconstructed resident coordinator must skip those staged envelopes and sign the same complete manifest. A real two-resident TLS/WSS session must migrate all classes, reset subscriptions/cursors, decrypt history on another member, and prove no project-content plaintext remains in SQLite. Privacy and packaged-runtime gates separately prove that migration content is not logged.

The complete inherited, privacy, Sunshine, fail-safe injection, Tauri, and package gates remain required after implementation.
