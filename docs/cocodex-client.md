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

The GUI remains the normal OpenCodex GUI. Open the **CoCodex** page to enroll
the device, start the resident collaboration session, select a shared project,
edit the Yjs prompt, and set the server-authoritative **Final Goal**.

Client state defaults to `%USERPROFILE%\.cocodex` (or `COCODEX_HOME`). It is
separate from `.opencodex` and `.codex`; no import or migration overwrites
those directories.

## Enroll and connect

1. The server owner creates a one-time invite with `cocodex-server invite`.
2. Paste the complete invite into the GUI, or run:

   ```powershell
   cocodex-client enroll --invite CODE --name Kai
   ```

3. The owner approves the displayed device fingerprint.
4. Start the client session from the GUI, or run:

   ```powershell
   cocodex-client connect --json-lines
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
cocodex-client accept-transfer --code 'ccx-transfer1....'
cocodex-client connect --json-lines
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
and applies it locally. Offline chat, private ciphertext, prompt updates, and
context updates are kept in the protected local outbox and replayed after
reconnect.

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

This setup currently supports one enabled local agent per project. It does not
yet provide the multi-policy runtime store needed to host Lucas and Angela
concurrently from one Client. See ADR 0025.

The client also subscribes to `agent.task.list`. Its activity cards show the
server-derived task status, dependency count, event count, and whether the
task uses an encrypted project envelope. Prompt and result bodies continue to
arrive only through their normal local-decryption path; activity metadata is
not an authorization grant.

When the server removes a member, the client marks the local project key ring
as rotation-required and surfaces the notice without silently falling back to
plaintext. The owner can still load the current key for an explicit rotation;
only a strictly newer server-accepted epoch clears the local gate. If a key is
introduced after legacy context exists, the client durably re-encrypts the last
known context revision before switching its reconnect subscription to the
encrypted projection.

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

## Local access profiles and emergency stop

Agent policies default to `project-only`, preserving the configured Codex
`read-only` or `workspace-write` sandbox. A host can explicitly opt into the
official Codex `danger-full-access` mode with:

```powershell
cocodex-client configure-agent --project PROJECT_ID --agent AGENT_ID `
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

This is still not a claim that every project record is encrypted yet. File
references and the full multi-device/forward-secret messaging lifecycle remain
on the explicitly documented follow-up path.

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
