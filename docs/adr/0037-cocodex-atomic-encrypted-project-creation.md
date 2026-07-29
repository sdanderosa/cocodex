# ADR 0037: Atomic encrypted Co-Project creation

- Status: Accepted; initial-recipient membership superseded by ADR 0038
- Date: 2026-07-26
- Scope: Client-created Co-Projects, owner membership, and epoch-1 keys

## Context

The Server CLI could create a project and add members, after which the owner
initialized project encryption through a separate Client command. The
three-process harness used that administrative shortcut. A normal user could
therefore not complete the primary product workflow, and a crash between the
two operations could leave a project observable without an encryption epoch.

## Open-source reference and licensing decision

Matrix room creation informs one authenticated operation that establishes the
creator, initial state, and name. Its Client-Server specification
requires creation events to be applied in a defined order and permits
encryption state in `initial_state`. Matrix SDKs are Apache-2.0, but this slice
adapts only the architectural concept and copies no source.

MeshCentral informs the authoritative server/group-membership boundary:
untrusted display names never decide identity or permissions, and the server
admits only enrolled devices. MeshCentral is Apache-2.0; no code or dependency
is reused.

Syncthing continues to inform explicit cryptographic device trust. It is
MPL-2.0 and remains concept-only. Libsodium remains the already selected
ISC-licensed implementation for X25519 sealed project-key envelopes.

## Decision

Add a strict signed `project.create` WSS request. The owner Client:

1. generates a fresh project UUID and random 32-byte key;
2. creates one owner-signed epoch-1 sealed key envelope for itself;
3. excludes every other device from creation membership;
4. signs a canonical transcript binding the project ID, normalized name,
   creator device, and exact owner envelope; and
5. durably stages the key and exact request before transmission.

The Server verifies the authenticated creator, creation signature, enrolled
signing key, exact owner recipient, envelope signature, approved status, and
epoch 1. One immediate SQLite transaction then inserts the project, owner
membership, key-epoch row, owner key envelope, and immutable creation replay
record. Any validation or write failure rolls the entire operation back.

The client-generated project UUID and request UUID provide exact replay
semantics. Replaying the same signed operation returns the original project;
changing its name, creator, request identity, or envelope fails closed. The
dedicated replay record means a later accepted invitation does not make the
original creation retry conflict with the now-larger roster. Exact replays
acknowledge only the requester and do not rebroadcast membership or keys.
Creation is limited per authenticated device and each device may own at most
128 projects. A transient creation-limit error preserves the resident's
durable signed intent and local key for timed or reconnect replay. After
commit, only the creator receives project metadata and its envelope.

The resident process clears staged creation state only after a matching
acknowledgement. The GUI supplies a name; it never
receives certificates, wrap keys, sealed keys, signatures, or the creation
acknowledgement's envelope batch.

## Security invariants

- A committed Client-created Co-Project always has exactly one current
  encryption epoch and exactly one initial envelope for its owner.
- The authenticated creator is the sole owner and sole creation recipient.
- No Server-approved contact becomes a member through project creation.
- Device IDs and certified keys establish identity; names are metadata only.
- Project keys and recipient wrap keys never enter Server plaintext storage,
  renderer events, logs, or evidence.
- Partial inserts, extra recipients, altered
  signatures, and conflicting replays leave no project behind.
- Offline/restart recovery replays the exact signed creation; it never
  regenerates a different key or silently falls back to plaintext.
- Rate and ownership limits bound authenticated creation/replay spam.

## Consequences and limits

The normal Client creates a private owner-only project. Adding a verified
contact is the separate signed invitation and recipient-acceptance lifecycle
defined by ADR 0038. Rename, archive, delete, local-project conversion,
ownership transfer, and multi-device user grouping remain separate lifecycle
operations.

## Required evidence

- strict protocol/transcript tests;
- SQLite atomicity, signature, owner-only, and exact-replay tests;
- resident crash-staging and renderer-redaction tests;
- real WSS owner-only creation and exact replay after invitation acceptance;
- the three-process private-alpha harness creating its project through the
  Stephen Client rather than Server CLI pre-seeding; and
- restart recovery plus server-database plaintext/key canary scans.
