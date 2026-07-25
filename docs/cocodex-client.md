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

## Shared work

The client subscribes to project chat, prompt revisions, presence, and the
shared Final Goal. Chat order and context revisions come from the server. Prompt
text uses Yjs updates; the server authorizes project membership before applying
them. Offline chat, private ciphertext, prompt updates, and context updates are
kept in the protected local outbox and replayed after reconnect.

To instruct a local or remote named agent through the JSON-line session:

```json
{"id":"run-1","type":"agent.request","projectId":"PROJECT_ID","agentId":"lucas","prompt":"Inspect the authentication flow."}
```

The destination client validates the signed task, its server authorization, and
its local agent policy before invoking the local Codex runtime. Agent results
are streamed back into the authoritative project chat. Private messages are
decrypted locally and are never automatically added to an agent prompt.

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
