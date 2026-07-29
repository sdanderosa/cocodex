# ADR 0055: Authoritative project lifecycle

Status: Accepted

## Context

The private-alpha brief requires project rename, archive, restore, and permanent deletion. These operations change shared authority and retained data, so a renderer-only state change or an unsigned WebSocket message would let clients diverge, bypass ownership, or delete the wrong revision.

## Decision

Project lifecycle changes are Server-authoritative, owner-only, signed operations. A request binds its operation and project IDs, action, expected lifecycle revision, optional new or confirmation name, Server fingerprint and epoch, bounded validity window, and a 32-byte nonce into an Ed25519 transcript. The Server accepts only an approved current project owner targeting the current Server authority.

The transition rules are fail closed:

- rename requires an active, unlocked project and a distinct 1-120 character name;
- archive requires an active project whose project lock is already locked;
- restore requires an archived project and deliberately preserves the existing lock;
- delete requires an archived project and exact case-sensitive confirmation of its current name.

Every accepted change increments an optimistic lifecycle revision in one immediate SQLite transaction. The transaction records a canonical transition and audit event. An operation ID is idempotent only for an identical signed request; conflicting reuse is rejected.

Archived projects remain readable but every authoritative project write fails with `PROJECT_ARCHIVED`. Archive and deletion clear live presence. Members receive personalized project snapshots after rename, archive, and restore. Deletion first captures the deterministic member delivery set, then cascades project-scoped data and emits a signed-shape deletion tombstone. The lifecycle operation record survives deletion so retries remain idempotent and auditable. On receipt, a Client revokes local project access before publishing the deletion event to the renderer.

## Consequences

Deletion is intentionally irreversible and cannot be used as an implicit member-leave operation. A restored project remains locked until an owner performs the separate signed unlock workflow. Historical plaintext migration and member leave/revocation semantics remain separate requirements.

Protocol, transaction, real TLS/WSS, bridge, Client, migration, and GUI tests cover malformed payloads, authority mismatch, invalid and expired signatures, stale revisions, replay conflicts, lock/state preconditions, write denial, exact deletion confirmation, cascading deletion, surviving tombstones, deterministic member delivery, local revocation, and selection recovery.
