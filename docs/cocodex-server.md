# CoCodex Server

CoCodex Server is a separate headless process and executable. It owns
authoritative projects, memberships, ordered chat, task state, artifacts,
encrypted private-message envelopes, server epochs, and audit records. It does
not load OpenCodex provider credentials or access a client workspace.

## Build and state

```powershell
bun install
bun run build:cocodex-server
dist\cocodex-server.exe --help
```

For an npm installation of this repository, the public server commands are:

```powershell
cocodex-server --help
ccx-server --help
```

Both commands launch only the separate headless Server entrypoint. They use the
`bun` runtime installed as a pinned package dependency, never the CoCodex Client
or inherited OpenCodex proxy. The launcher performs no first-run download and
fails closed if package-install policy omitted Bun's lifecycle build or
optional platform dependency.

The default state directory is `%USERPROFILE%\.cocodex-server` (or
`COCODEX_SERVER_HOME`). It contains the SQLite database, TLS certificate,
server Ed25519 identity, configuration, and PID file. Keep it separate from
client state and back it up while the server is stopped.

## Initialize and host

```powershell
cocodex-server init --public-host YOUR_PUBLIC_HOST --port 19463
cocodex-server start
cocodex-server status
```

Initialization creates the server identity and TLS certificate, attempts a
Windows Firewall rule, and tries UPnP followed by NAT-PMP and PCP. The JSON output
includes a one-time admin token, the certificate fingerprint, mapping result,
and manual-forwarding instructions. If automatic mapping is unavailable, run:

```powershell
cocodex-server network-diagnose --port 19463
```

Forward exactly one TCP port from the router to the server PC, allow that port
through the firewall, and use the public host and port in the generated invite.
The diagnostic distinguishes ready, manual-forwarding-required, likely-CGNAT,
and blocked states. CoCodex does not require Tailscale, a VPN, paid hosting, or
a second installed application.

The server can run in the background as a user-level process. `stop` and
`restart` use the PID file and refuse to start a second authority on the same
state directory:

```powershell
cocodex-server stop
cocodex-server restart
cocodex-server status
```

## Enrollment and projects

```powershell
cocodex-server invite --ttl 900
cocodex-server devices
cocodex-server approve --fingerprint FINGERPRINT
cocodex-server revoke --fingerprint FINGERPRINT
cocodex-server project-create --name "Nocturne Launcher" --owner-device DEVICE_ID
cocodex-server project-add-member --project PROJECT_ID --owner-device OWNER_ID --member-device MEMBER_ID
```

Invites are single-use and short-lived. Approval is explicit; revocation is
checked on every authenticated connection and project operation.
The two project CLI commands are administrative/recovery compatibility
surfaces. The normal product flow uses the authenticated Client
`project.create` operation, which creates only the owner membership and
encryption epoch atomically. Another device joins only through
`project.invite.create` followed by its own signed
`project.invite.respond` acceptance.

Approved Clients publish a self-signed public device-key certificate after
proof-of-possession authentication. The `private.contact.list` WSS request
returns only other approved certificate-bearing devices. Pending, revoked,
certificate-less, and requesting devices are excluded. The Server broadcasts
an updated bounded snapshot when the directory changes, while the Client
independently verifies certificate signature, device ID, enrolled fingerprint,
and local explicit trust before encrypting. Device private keys never enter
the directory or Server.
Identical certificate re-publication is idempotent, publication and explicit
directory requests are independently rate-limited, and only a stored
certificate transition triggers a directory broadcast.

## Backup, transfer, and health

```powershell
cocodex-server backup --output backup.json
cocodex-server restore --input backup.json
cocodex-server migrate
```

The legacy `transfer-export`/`transfer-import` pair is an encrypted,
identity-bound snapshot for restoring the same server state. For a real
authority handoff to a new machine, prepare the destination first:

```powershell
cocodex-server transfer-prepare --public-host NEW_PUBLIC_HOST --port 19463 `
  --output target-request.json --state-root C:\CoCodex\new-server

cocodex-server stop
cocodex-server transfer-export --target-request target-request.json `
  --output authority-transfer.json --passphrase-file transfer-passphrase.txt

cocodex-server transfer-import --input authority-transfer.json `
  --passphrase-file transfer-passphrase.txt --state-root C:\CoCodex\new-server
cocodex-server start --state-root C:\CoCodex\new-server
```

`transfer-prepare` creates a distinct destination identity, TLS certificate,
and a prepared database. The source signs the destination identity, endpoint,
TLS pin, and next server epoch inside an encrypted AES-GCM snapshot, then
retires its own authority. The destination accepts the snapshot only when its
identity and certificate match the signed target request. The export/import
output contains a one-time `ccx-transfer1.` authority certificate for clients.
Never start the source after it is retired; this is the split-brain fence.

The real-process transfer harness enrolls both Stephen and Kai, preserves their
project membership, chronological chat, and private ciphertext, updates both
client endpoint/TLS pins, and reconnects both clients at the next authority
epoch before checking the retired-source fence.

Never place a passphrase directly in shell history for a real deployment—prefer
`--passphrase-file` with a protected file. The health endpoint is
`GET /healthz`; authenticated admin status is `GET /v1/admin/status` with the
initialization token.

## Security boundary

The single TLS/WSS port carries authenticated, versioned protocol frames. The
server validates device proof, membership, signatures, task dependencies, and
replay rules, then routes a request to the host client. The host client
revalidates and executes locally. Private-message rows contain ciphertext and
routing metadata only; private delivery/read receipts contain message IDs and
authenticated device/status metadata but never plaintext or ciphertext. The
server validates that only the original recipient can submit a receipt and
stores receipt history with an independent sequence; clients persist the
receipt recovery cursor. Plaintext is not logged or passed into agent context.

The server cannot enable a host's full-computer profile. That profile and its
durable emergency-stop state live only in the destination Client; even a
trusted-device task must pass the local policy immediately before the official
Codex runtime starts. The server therefore has no raw shell, desktop, browser,
or elevation capability to expose. See ADR 0021.

The `agent.list` route is the authoritative named-agent roster. It is scoped to
the requesting project member and derives each agent's host display name,
approved-device state, socket readiness, active/queued task counts, and latest
terminal status from server state. A disconnected or revoked host is reported
as `offline`; the server never trusts a client-provided status or exposes task
prompts/results in the roster. The route is advisory discovery only, so every
`agent.request` still passes the normal signed authorization and local-policy
checks. See ADR 0018.

`agent.create` is the authenticated self-hosting path. The Server derives the
host device from the WSS session, verifies the device-signed definition and
project membership, applies the eight-agents-per-host/project and
128-agents-per-project limits, and audits the exact idempotent creation. It accepts
no workspace, sandbox, access-profile, or full-computer fields. The host Client
commits those local-only controls only after `agent.created`, then opens an
agent-scoped worker WSS and announces `agent.ready`. Results are accepted only
from the matching authenticated ready lease. See ADRs 0025 and 0026.

`agent.task.list` is the companion activity projection. It returns only
bounded task identity, dependency, status, timestamp, event-count, and
encryption metadata for the requesting project member and selected chat. It
joins both legacy
and encrypted result-event tables without opening ciphertext or prompts, so a
GUI activity card cannot become a server-side agent context leak.

The owner-facing removal path is one atomic security boundary. The server
verifies a complete next-epoch envelope set for every remaining approved
member, then one SQLite transaction removes membership, disables the removed
host's agents, terminalizes queued/running work where that device is requester
or target, deletes its key envelopes, installs the new epoch, and records the
immutable replay result. Exact replay remains safe after later rotations and
does not repeat cancellation or membership fanout. The older two-step removal
route remains fail closed behind `rotation_required` for compatibility.
Historical pre-key plaintext rows are retained for audit but are not served
through keyed routes; a full historical migration is still a release-gate item.

The administrative `revoke --fingerprint` path applies the same boundary
across every encrypted project that contains the device. Device status,
invitation expiry, hosted-agent disablement, requester/target task
terminalization, sender/recipient envelope invalidation, epoch quarantine,
owner recovery assignment, audit state, and a durable incident row commit or
roll back together. Live revoked sockets are closed and their presence is
cleared. Approved survivors receive a bounded
`project.device-revoked` notice on each connection until an explicit atomic
member removal and complete-recipient rotation resolves the incident. Every
affected task hosted by a survivor also receives its own cancellation command;
the Server still does not execute a local command. A revoked owner is replaced
only by an already approved deterministic survivor. Owner-only projects remain
quarantined with no fabricated recovery authority. See ADR 0040.

Presence is a separate ephemeral membership-scoped channel. Both legacy and
encrypted chat subscriptions register the socket for presence snapshots and
updates, so project-key selection does not disable awareness. The server bounds
cursor/caret/display-name payloads, rate-limits updates, keeps cursor/caret/
typing state independent, removes state on member revocation, and clears a
device only after its last authenticated socket closes. Presence is never
persisted in SQLite or included in agent context.

Signed usage reports are a separate sanitized server record. The server checks
the reporting device's Ed25519 signature and revision, stores the latest report
only, and returns it only to approved members of a shared project. It never
receives provider credentials or raw quota/account records.

Project-content encryption is enabled for the explicit `project.key.*`,
`project.context.*`, `project.chat.*`, `project.prompt.*`,
`project.artifact.*`, and keyed `project.agent.*` slices. The server
verifies owner-signed key envelopes, approved membership, signatures,
replay/idempotency, context revisions, and monotonic key epochs, then stores
only opaque envelope JSON in `project_key_envelopes`,
`encrypted_project_context`, `project_chat_events`, `project_prompt_updates`,
`project_artifacts`, and `project_file_references`. Keyed agent tasks store an
`[encrypted]` prompt placeholder and an opaque prompt envelope; streamed
results use the same opaque envelope table with task/final/status routing
metadata. Encrypted file-reference rows expose only project/artifact/device
routing IDs and timestamps; paths, workspace metadata, hashes, sizes, and media
types remain inside ciphertext. It never receives the project key or opens the
Final Goal/context/chat/prompt/artifact/file-reference/task/result ciphertext. For
encrypted prompts it orders and deduplicates Yjs updates without applying them;
the clients perform the Yjs state transition after local decryption. Encrypted
artifact rows expose only project/task/author routing metadata and timestamps.

Each project has an authoritative General chat whose ID equals the project ID.
Additional chats are created through an expiring device-signed request and are
bounded to 64 per project. Migration 28 materializes General for existing
projects and backfills existing collaboration rows into it. New project
content uses a v2 envelope whose signature and XChaCha20-Poly1305 associated
data bind `chatId`; legacy v1 envelopes are accepted only from General.
Message order, Yjs documents, context revisions, tasks, dependencies,
execution reports, artifacts, and encrypted file-reference metadata are
queried by the composite project/chat scope. See ADR 0039.

`project.create` accepts a client-generated project UUID, bounded name, one
owner-signed epoch-1 envelope, and a creator signature over all of that
meaning. The Server verifies the creator's enrolled Ed25519 key, owner-only
recipient, envelope signature, and exact epoch. One immediate SQLite
transaction inserts `projects`, the owner `project_members` row,
`project_key_epochs`, `project_key_envelopes`, and a durable exact-replay
record; any failure leaves none of them behind. Later membership changes do
not break replay of the original creation. A changed name, request, creator,
or envelope is rejected. Each authenticated device is limited to 12 creation
attempts per minute and 128 owned projects. See ADR 0037.

`project.invite.create` is owner-only and binds the Server fingerprint,
project, recipient device, active key epoch, exact sealed-key envelope, expiry,
nonce, and owner signature. Server approval makes a device eligible to be
invited, not a project member. The Server stores the pending opaque envelope
and routes it only to owner and recipient. The addressed approved device signs
accept or decline; acceptance inserts the member row, key envelope,
invitation status, and audit record in one immediate transaction. Decline and
owner cancellation add no membership. Exact create/decision replay is
idempotent. Time expiry, device revocation, rotation-required state, and key
epoch advancement expire pending invitations with audit records. See ADR
0038.

The first `project.key.initialize` operation is stricter than the compatibility
`project.key.share` route. It accepts one owner-signed epoch-1 envelope for
every approved project member and inserts the complete set plus the epoch row in
one immediate SQLite transaction. The `project.key.initialized` response is
idempotent by a project-scoped request ID, so a reconnect can safely replay the
batch. The server re-sends the addressed envelope set both on an idempotent
retry and after every authenticated reconnect, covering recipients that were
offline during the original broadcast. A failed batch leaves no partial key
envelopes and does not enable encrypted mode.

This is not yet a whole-project E2EE claim. Legacy `context.*`, `agent.*`, and
file-reference paths remain server-readable for projects without a key.
Keyed projects now use encrypted metadata-only local file references; actual
file-content transfer is not implemented. Legacy `prompt.*` and
`artifact.*` remain for projects without a project key. The owner GUI and
resident Client now perform verified-device atomic removal and immediate key
rotation; the removed client revokes local access live or during authoritative
reconnect reconciliation. See ADRs 0016 and 0031 for the keyed agent and
revocation boundaries.

The private alpha supports the connected single-device delivered/read receipt
path, but deliberately defers conversations, attachments, replies, reactions,
edit/delete events, multi-device fan-out, relay/libp2p traversal, automatic
failover, full multi-device ratchets, and cross-platform service installers.
Those are later requirements and must not be presented as available by the
current setup instructions.
