# ADR 0037: Atomic encrypted Co-Project creation

- Status: Accepted for the private alpha
- Date: 2026-07-27
- Scope: Client-created Co-Projects, initial membership, and epoch-1 keys

## Context

The Server CLI could create a project and add members, after which the owner
initialized project encryption through a separate Client command. The
three-process harness used that administrative shortcut. A normal user could
therefore not complete the primary product workflow, and a crash between the
two operations could leave a project observable without an encryption epoch.

## Open-source reference and licensing decision

Matrix room creation informs one authenticated operation that establishes the
creator, initial state, name, and invitations. Its Client-Server specification
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
2. resolves only approved contacts whose exact fingerprints were independently
   trusted locally;
3. creates one owner-signed epoch-1 sealed key envelope for itself and every
   selected device;
4. signs a canonical transcript binding the project ID, normalized name,
   creator device, complete recipient set, and exact envelope set; and
5. durably stages the key and exact request before transmission.

The Server verifies the authenticated creator, creation signature, enrolled
signing key, every envelope signature, exact unique recipient set, approved
device status, owner inclusion, and epoch 1. One immediate SQLite transaction
then inserts the project, complete membership, key-epoch row, and every key
envelope. Any validation or write failure rolls the entire operation back.

The client-generated project UUID and request UUID provide exact replay
semantics. Replaying the same signed operation returns the original project;
changing its name, creator, roster, request identity, or envelopes fails
closed. Exact replays acknowledge only the requester and do not rebroadcast
membership or keys. Creation is limited per authenticated device and each
device may own at most 128 projects. A transient creation-limit error preserves
the resident's durable signed intent and local key for timed or reconnect
replay. After commit, each included connected device receives safe project
metadata and only its addressed key envelope. Reconnect recovers the project
through `project.list` and its addressed envelope through `project.key.get`.

The resident process clears staged creation state only after a matching
acknowledgement. The GUI supplies a name and selected safe device IDs; it never
receives certificates, wrap keys, sealed keys, signatures, or the creation
acknowledgement's envelope batch.

## Security invariants

- A committed Client-created Co-Project always has exactly one current
  encryption epoch and one epoch-1 envelope per initial member.
- The authenticated creator is the sole owner and must be one recipient.
- Every other initial member is approved and independently fingerprint-trusted
  by the owner Client.
- Device IDs and certified keys establish identity; names are metadata only.
- Project keys and recipient wrap keys never enter Server plaintext storage,
  renderer events, logs, or evidence.
- Partial inserts, incomplete recipient sets, duplicate recipients, altered
  signatures, and conflicting replays leave no project behind.
- Offline/restart recovery replays the exact signed creation; it never
  regenerates a different key or silently falls back to plaintext.
- Rate and ownership limits bound authenticated creation/replay spam, and
  exact retries never notify recipients again.

## Consequences and limits

The normal Client can now create a private project alone or include verified
contacts, and every included device immediately receives authoritative
membership and encryption state. Rename, archive, delete, local-project
conversion, later member addition, ownership transfer, and multi-device user
grouping remain separate lifecycle operations.

For this two-person alpha, approval to the Server makes a device eligible for
project membership; there is not yet a separate per-project recipient
acceptance event. A modified authenticated Client could therefore add another
approved device to a bounded unsolicited project. The recipient still refuses
to open the owner's key envelope until that owner fingerprint is trusted
locally, and no command executes from membership alone. A later project-invite
and explicit acceptance state is required before broad or multi-tenant use.

## Required evidence

- strict protocol/transcript tests;
- SQLite atomicity, signature, completeness, and exact-replay tests;
- resident crash-staging and renderer-redaction tests;
- real WSS two-Client creation and addressed-key recovery;
- the three-process private-alpha harness creating its project through the
  Stephen Client rather than Server CLI pre-seeding; and
- restart recovery plus server-database plaintext/key canary scans.
