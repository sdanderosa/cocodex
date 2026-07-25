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

## Backup, transfer, and health

```powershell
cocodex-server backup --output backup.json
cocodex-server restore --input backup.json
COCODEX_TRANSFER_PASSPHRASE='use-a-secret-file' cocodex-server transfer-export --output transfer.json
COCODEX_TRANSFER_PASSPHRASE='use-a-secret-file' cocodex-server transfer-import --input transfer.json
cocodex-server migrate
```

Transfer exports are signed and encrypted with an operator passphrase. Import
advances the server epoch; clients reject a stale authority. Never place a
passphrase directly in shell history for a real deployment—prefer
`--passphrase-file` with a protected file. The health endpoint is
`GET /healthz`; authenticated admin status is `GET /v1/admin/status` with the
initialization token.

## Security boundary

The single TLS/WSS port carries authenticated, versioned protocol frames. The
server validates device proof, membership, signatures, task dependencies, and
replay rules, then routes a request to the host client. The host client
revalidates and executes locally. Private-message rows contain ciphertext and
routing metadata only; plaintext is not logged or passed into agent context.

Signed usage reports are a separate sanitized server record. The server checks
the reporting device's Ed25519 signature and revision, stores the latest report
only, and returns it only to approved members of a shared project. It never
receives provider credentials or raw quota/account records.

Project-content encryption is enabled for the explicit `project.key.*`,
`project.context.*`, `project.chat.*`, and `project.prompt.*` slices. The server
verifies owner-signed key envelopes, approved membership, signatures,
replay/idempotency, context revisions, and monotonic key epochs, then stores
only opaque envelope JSON in `project_key_envelopes`,
`encrypted_project_context`, `project_chat_events`, and
`project_prompt_updates`. It never receives the project key or opens the Final
Goal/context/chat/prompt ciphertext. For encrypted prompts it orders and
deduplicates Yjs updates without applying them; the clients perform the Yjs
state transition after local decryption.

This is not yet a whole-project E2EE claim. Legacy `context.*` frames, shared
task prompts, agent results, artifacts, and file references remain
server-readable until their own encrypted envelopes and end-to-end tests are
complete. Legacy `prompt.*` remains for projects without a project key. Key
rotation and project-member removal are implemented for the project-key
lifecycle, but a release still needs automatic rotation orchestration and UI
before claiming complete revocation UX.

The private alpha deliberately defers relay/libp2p traversal, automatic
failover, full multi-device ratchets, and cross-platform service installers.
Those are later requirements and must not be presented as available by the
current setup instructions.
