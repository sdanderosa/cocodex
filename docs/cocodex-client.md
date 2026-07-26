# CoCodex Client

CoCodex Client is the OpenCodex-based desktop/CLI application. It keeps
provider credentials, Codex accounts, local usage, device private keys, agent
workspaces, and execution policy on the local computer. CoCodex Server never
receives those secrets and never executes a local shell command.

## Build and run locally

From the repository root:

```powershell
bun install
bun run build:cocodex-client
dist\cocodex-client.exe --help
```

For an npm installation of this repository, the public client commands are:

```powershell
cocodex --help
ccx --help
```

Both commands launch the same CoCodex Client through the `bun` runtime installed
as a pinned package dependency. A normal npm installation must allow Bun's
package lifecycle script and optional platform dependency; the launcher never
downloads or repairs a runtime on first launch and fails closed if installation
policy omitted it. The existing `opencodex` and `ocx` commands remain
compatibility surfaces for the inherited local proxy.

The GUI remains the normal OpenCodex GUI. Open the **CoCodex** page to enroll
the device, start the resident collaboration session, select a shared project,
edit the Yjs prompt, and set the server-authoritative **Final Goal**.

Client state defaults to `%USERPROFILE%\.cocodex` (or `COCODEX_HOME`). It is
separate from `.opencodex` and `.codex`; no import or migration overwrites
those directories.

## Importing an existing OpenCodex installation

The Client has an explicit, local-only import flow for an existing
`OPENCODEX_HOME`. Preview before applying it:

```powershell
cocodex import-opencodex --preview --source "$env:USERPROFILE\.opencodex" --target "$env:USERPROFILE\.cocodex\opencodex" --include-secrets
cocodex import-opencodex --apply --source "$env:USERPROFILE\.opencodex" --target "$env:USERPROFILE\.cocodex\opencodex" --include-secrets
```

The preview reports source/destination paths, sizes, sensitivities, collisions,
and excluded files without printing file contents. Source files are read through
a bounded, identity-checked descriptor. Apply stages every selected file, writes
a prepared journal, then atomically renames each file into the separate local
target. Existing target files are moved into a timestamped backup directory first
and protected with the same fail-closed ACL policy. The target directory is
hardened before any sensitive rename, and required ACL calls can be forced even
when an earlier write used the same pathname. `--list` and `--status` show local
backup manifests; `--rollback BACKUP_DIRECTORY` validates the journal phase/schema,
rechecks imported and collision-backup hashes immediately before mutation, restores
previous target files, and removes only files created by that import. Edited
destinations, edited backups, symlink ancestors, forged plans, stale source
metadata, and target roots that overlap generated backup metadata are rejected. If
a crash leaves a prepared journal with
ambiguous destination ownership, recovery refuses to delete it and leaves staging
for explicit manual cleanup.

The allowlist covers provider configuration (`config.json`), Codex configuration
(`config.toml` and `opencodex.config.toml`), recognized catalog/cache files, and
non-sensitive usage data. JSON/TOML configuration is scrubbed for private-key,
token, certificate, authorization, password/passphrase, access-key, vendor-header, and nested secret fields. JSON arrays are
walked as well, so PEM and Bearer values cannot hide inside primitive array
members. Bare TOML dotted keys are scrubbed by their final segment; quoted-key,
inline-table, and multiline-array forms that the redactor cannot prove safe are
rejected instead of copied. Explicit provider `apiKey`/`apiKeyPool` values are
preserved only with `--include-secrets`.
API-key fields outside provider objects or tables are scrubbed even with --include-secrets.
Diagnostic/request logs are always excluded because they can contain credentials or
prompts. Authentication stores and account refresh grants are always excluded.
Runtime locks, PID files, sockets, symlinks, and unknown files are also excluded.
The source `.opencodex` and `.codex` directories are never modified. Imported
configuration remains inside the protected Client-local target; this command never
opens a server connection and the Server protocol has no route for imported files
or provider secrets.

## Enroll and connect

1. The server owner creates a one-time invite with `cocodex-server invite`.
2. Paste the complete invite into the GUI, or run:

   ```powershell
   cocodex enroll --invite CODE --name Kai
   ```

3. The owner approves the displayed device fingerprint.
4. Start the client session from the GUI, or run:

   ```powershell
   cocodex connect --json-lines
   ```

The invite pins the server certificate fingerprint. Each installation proves
possession of its Ed25519 device key during the WSS handshake and is remembered
for reconnects. A display name, IP address, or copied bearer value is not an
identity.

## Accepting a server authority handoff

When a server owner moves the authoritative database to a prepared destination,
the source prints a signed `ccx-transfer1.` certificate. Paste it into the
resident client before reconnecting to the new endpoint:

```powershell
cocodex accept-transfer --code 'ccx-transfer1....'
cocodex connect --json-lines
```

The client verifies the source identity it already trusts, the destination
identity and TLS certificate, the signature, and a strictly newer server epoch
before atomically replacing its endpoint. Replaying the certificate, using a
stale epoch, or presenting a certificate from another server is rejected. The
device key and enrollment record do not change, so approval is not repeated.

## Shared work

The client subscribes to project chat, prompt revisions, presence, and the
shared Final Goal. Chat order and context revisions come from the server. Prompt
text uses Yjs updates. When a project key is available, the client encrypts each
Yjs update before sending it through `project.prompt.*`; the server orders and
deduplicates the opaque update but never applies Yjs, and each client decrypts
and applies it locally. Offline chat, private ciphertext, delivery/read receipt
frames, prompt updates, and context updates are kept in the protected local
outbox and replayed after reconnect. The private mailbox keeps a separate
bounded receipt cursor so sender-visible status survives a Server restart
without coupling it to the ciphertext message cursor.

Presence is deliberately ephemeral. The client publishes a normalized mouse
cursor plus a bounded prompt caret/selection and typing flag; local state keeps
those channels merged, batches typing updates, clears typing after idle/blur,
and republishes the state after reconnect. The GUI shows named awareness/status
chips for remote caret/selection/typing state. Offsets are advisory for the
current prompt snapshot, not stable Yjs RelativePositions or an inline overlay.

To instruct a local or remote named agent through the JSON-line session:

```json
{"id":"run-1","type":"agent.request","projectId":"PROJECT_ID","agentId":"lucas","prompt":"Inspect the authentication flow."}
```

The destination client validates the signed task, its server authorization, and
its local agent policy before invoking the local Codex runtime. Agent results
are streamed back into the authoritative project chat. Private messages are
decrypted locally and are never automatically added to an agent prompt. A host
may explicitly share one already-decrypted private message with one selected
project agent:

```json
{"id":"share-1","type":"private.share","projectId":"PROJECT_ID","agentId":"lucas","messageId":"PRIVATE_MESSAGE_ID"}
```

The command resolves only a message retained by the resident client, requires
an encrypted project, and sends the resulting prompt through the existing
signed/encrypted agent route. The server records the explicit-share marker and
opaque task/result envelopes, never the private text. A same-device task is
accepted only with this explicit marker; ordinary same-device agent requests
remain rejected. The GUI exposes the same action beside each private message
when an agent is selected.

After a private message is opened and its signed ciphertext is verified, the
Client queues a `delivered` receipt. The private panel exposes an explicit
**Mark read** action that queues `private.read`; the recipient never sends a
receipt before local decryption. Receipt state is metadata only and does not
change the single-device sealed-box limitations documented in ADRs 0014,
0022, and 0034.

The same session can request the project-scoped `agent.list` roster. The
server supplies the approved host name, readiness-derived status, and task
counts; the GUI refreshes it while connected and clears it from view when the
connection is lost. These cards are advisory discovery, not an execution
grant: a task still requires the full signed server route and local host policy
checks. Persistent activity history, dependency-graph editing, co-agents, and
full computer/browser helpers remain later requirements (ADR 0018).

The CoCodex page can now create the first agent hosted by this Client. Select a
Co-Project and enter its display name, the canonical local repository root,
workspace mode, and the trusted requester's device ID/fingerprint. The Client
preflights those local values, signs a self-hosted definition, waits for Server
acceptance, commits the local policy, and reconnects as ready. The Server never
receives the workspace path, sandbox, or access profile. The composer selects
agents from the verified roster instead of accepting a typed internal ID.

The same Client can host up to eight local agents for one project. It keeps one
shared collaboration connection and a separate authenticated worker
connection, safety record, execution journal, and worktree registry for each
agent. Version-1 single-agent policies migrate into the bounded version-2 store
when another agent is added. See ADR 0026.

The client also subscribes to `agent.task.list`. Its activity cards show the
server-derived task status, dependency count, event count, and whether the
task uses an encrypted project envelope. Prompt and result bodies continue to
arrive only through their normal local-decryption path; activity metadata is
not an authorization grant.

The owner member roster verifies device-signed key certificates against the
explicit trusted-device fingerprint store. Its Remove action generates a fresh
project key locally and durably submits membership removal plus one signed
sealed envelope for every verified survivor as a single operation. Removed
clients mark the local key ring revoked, purge queued project writes, clear
subscriptions, and emergency-stop local agents live or during authoritative
project-list reconciliation. A strictly newer valid envelope restores access
only after the server later re-adds the device. The older two-step path still
surfaces `rotation-required` without silently falling back to plaintext.

## Encrypted project context

New client installations also create a dedicated X25519 project-wrap keypair;
it is separate from the private-message key and remains in the protected
client state directory. An owner can initialize an encrypted project-context
epoch through the JSON-line session by supplying the approved members' project
wrap public keys:

```json
{"id":"keys-1","type":"project.key.initialize","projectId":"PROJECT_ID","keyEpoch":1,"recipients":[{"deviceId":"STEPHEN_DEVICE_ID","projectWrapPublicKeyPem":"..."},{"deviceId":"KAI_DEVICE_ID","projectWrapPublicKeyPem":"..."}]}
```

Initialization is one atomic owner-signed batch: the server requires every
currently approved member, persists all envelopes in one SQLite transaction,
and acknowledges the request before the client reports success. The client
persists the signed batch and generated key as a protected pending intent, so a
process restart can replay the same request ID before encrypted outbox traffic.
The staged key is removed on rejection or any acknowledgement whose envelope
set does not exactly match the request. Authenticated reconnects and project
discovery refresh all envelopes addressed to the device, so an offline member
does not need to repeat enrollment or depend on the original broadcast. This
prevents a partially shared key from silently putting the client into encrypted
mode.

Then use `project.key.get` on each member client and use
`project.context.get`/`project.context.update` for encrypted Final Goal and
structured context. The client unwraps and decrypts locally; the server stores
only signed opaque envelopes. The encrypted update is also durable in the
protected outbox while offline.

When a project key is available, `chat.subscribe` and `chat.send` select the
encrypted `project.chat.*` transport automatically. The client encrypts the
chat body locally, queues the opaque envelope offline, and emits the familiar
local chat event only after verifying and decrypting it. `project.key.rotate`
requires envelopes for every approved member; `project.member.remove` revokes
the removed client's local key ring. The owner should rotate immediately after
removal so remaining members receive a fresh epoch.

When a project key is available, `prompt.subscribe` and `prompt.update` likewise
select the encrypted `project.prompt.*` transport. The server persists only the
signed envelope and authoritative sequence in `project_prompt_updates`; it does
not receive the prompt text or apply the Yjs update. The client verifies the
sender and project epoch, decrypts locally, and passes the update to the normal
Yjs document. Legacy `prompt.*` remains available for projects without a key.

When a project key is available, `artifact.publish` and `artifact.list` select
the encrypted `project.artifact.*` transport. The client encrypts the artifact
type, title, summary, status, and body locally. The server stores only the
signed envelope plus minimal routing metadata (project, optional task, author,
and timestamps) in `project_artifacts`; receiving clients decrypt and validate
the complete artifact before exposing the familiar artifact frame. Encrypted
artifact publishes are durable in the protected outbox and lists are
automatically reissued after reconnect. Legacy `artifact.*` remains for
projects without a key.

When a project key is available, `agent.request` automatically seals the task
prompt as a `project.agent.request` envelope. The destination client verifies
the server dispatch proof, decrypts the prompt locally, and passes it to the
host's normal Codex adapter. Every streamed result is sealed by the host as an
`agent-response` envelope, journaled for reconnect replay, and exposed to the
UI only after local decryption. The server stores `[encrypted]` plus routing
metadata and cannot fabricate a host result during encrypted cancellation.
Projects without a key retain the legacy `agent.*` route. Private-message
ciphertext and file references are never added to agent context implicitly.

Keyed projects can publish immutable local file-reference metadata with
`project.file-reference.publish`. The client contains the path beneath the
declared workspace, rejects symbolic links/junctions and non-regular files,
hashes the file, and seals its relative path, workspace coordinates, digest,
size, and media type with the project key. Other members decrypt that metadata
locally; the server sees only routing UUIDs and ciphertext. The file bytes
remain on the host client and are not uploaded or made remotely accessible by
this feature. Publish retries use the protected outbox, and reference lists are
restored after reconnect. The Artifact handoffs panel groups decrypted
references beneath their artifact and labels whether the file is available on
this device or a remote host. A host can attach a file by selecting one of its
own artifacts and entering the local workspace root plus a contained path. The
workspace root is used only by the local client and is never included in the
sealed reference or exposed to other project members.

## Local access profiles and emergency stop

Agent policies default to `project-only`, preserving the configured Codex
`read-only` or `workspace-write` sandbox. A host can explicitly opt into the
official Codex `danger-full-access` mode with:

```powershell
cocodex configure-agent --project PROJECT_ID --agent AGENT_ID `
  --workspace PATH --trust-device DEVICE_ID --trust-fingerprint FINGERPRINT `
  --access full-computer --confirm-full-computer
```

This writes a protected local policy and an atomic safety state. The remote
server still cannot widen that policy. The resident session exposes local-only
controls for `agent.emergency.stop`, `agent.emergency.resume`,
`agent.full-computer.enable`, and `agent.full-computer.disable`; the CLI has
equivalent `emergency-stop`, `emergency-resume`, and full-computer enable /
disable commands. Emergency stop aborts active local Codex work, blocks queued
tasks, and remains effective while the server is offline. Full-computer enable
requires a second explicit confirmation after an emergency stop. The access
profile does not claim an elevated Windows helper, browser automation, or
remote desktop implementation; those are later, separately reviewed slices.

This is still not a claim that every project record is encrypted yet. Legacy
no-key routes, encrypted file-content transfer, and the full
multi-device/forward-secret messaging lifecycle remain on the explicitly
documented follow-up path.

## Usage sharing

The resident session aggregates local token counters and active-agent state into
a bounded report, signs it with the device identity, and stores a protected
copy for reconnect. The CoCodex page displays separate cards for project
members. Optional quota percentages and reset times appear only when the local
OpenCodex quota adapter has supplied them; missing data is shown as unreported.
Provider credentials, refresh tokens, and raw account records never leave the
client.

## Offline behavior and emergency control

When the server is offline, normal local OpenCodex use continues. The GUI shows
disconnected/reconnecting state; shared cursors and remote execution pause.
Queued events remain local until the server returns. `shutdown` on the
JSON-line session stops the resident collaboration process; local Codex
accounts and workspaces remain usable independently.

Do not copy `connection.json`, device private keys, messaging private keys, or
agent policy files to the server or another device. Use a fresh enrollment and
explicit trust for a replacement installation.
