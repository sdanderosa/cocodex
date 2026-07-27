# Open-source reference implementations

This document records which proven systems inform CoCodex, which maintained
components may be reused, and which projects are architecture-only references
because of licensing or product-scope constraints.

CoCodex is based on an MIT-licensed project. Public source is not automatically
safe to copy. Exact resolved dependency and transitive licenses must be
reviewed again before release.

## Decision matrix

| Project | Relevant feature | Architecture learned | Reuse decision | License and compatibility | CoCodex differences and security considerations |
| --- | --- | --- | --- | --- | --- |
| [RustDesk](https://github.com/rustdesk/rustdesk) / [rustdesk-server](https://github.com/rustdesk/rustdesk-server) | Self-hosted direct connections, rendezvous, NAT traversal, relay fallback, reconnect | Separate clients from rendezvous/relay services; prefer direct transport and make fallback state visible | Concepts only; copy no source and take no dependency | AGPL-3.0; reference-only for the intended MIT distribution | Private alpha uses one forwarded TLS/WSS server port and no relay dependency. Test wrong server keys, direct-path failure, reconnect, NAT loopback guidance, and resource limits. |
| [MeshCentral](https://github.com/Ylianst/MeshCentral) / [design docs](https://docs.meshcentral.com/design/) | Authoritative server, installed agents, device enrollment, routed remote operations | Agents connect outward; server authenticates and scopes operations; the endpoint agent performs them | Adapt concepts independently; no source copied | Apache-2.0; compatible with required notices | CoCodex exposes no raw remote shell. Its signed agent-setup path lets an authenticated member self-register only its own host device, while workspace and execution policy remain local-only. Server and destination client both authorize task envelopes. Test revocation, replay, expiry, duplicate ready leases, capability escalation, cert mismatch, and server-compromise boundaries. |
| [Yjs](https://github.com/yjs/yjs) / [threat model](https://github.com/yjs/yjs/blob/main/THREAT_MODEL.md) | Collaborative prompt text, offline updates, convergence, awareness | Commutative and idempotent updates, state vectors, `Y.Text`, and ephemeral awareness | Reuse stable `yjs` 13.6.31 for project prompt documents | MIT; compatible | Yjs supplies convergence, not authentication, authorization, TLS, or safe rendering. Apply project/document ACLs before updates; cap bytes, depth, and rates; support snapshot recovery from malicious authorized edits. |
| [Hocuspocus](https://github.com/ueberdosis/hocuspocus) / [hooks](https://tiptap.dev/docs/hocuspocus/server/hooks) | Yjs WebSocket transport, auth hooks, reconnection, persistence | Typed TypeScript collaboration server/provider with pre-auth and persistence hooks | Concepts only for private alpha; defer the dependency while the existing authenticated WSS transport remains sufficient | MIT; compatible | Mount on the one TLS listener. Never treat document names or bearer strings as authorization. Persist exact binary Yjs data. Test pre-auth queue exhaustion, cross-project access, payload limits, restart reload, and apply/store crash behavior. |
| [Syncthing](https://github.com/syncthing/syncthing) / [security model](https://docs.syncthing.net/users/security.html) | Permanent device identity, fingerprints, explicit trust, unknown-device rejection | Device identity derives from cryptographic keys and explicit allowlists, not discovery names or addresses | Concepts only | MPL-2.0; avoid copying implementation files unless obligations are isolated and accepted | Use canonical public-key fingerprints and pending/approved/revoked states. Keep device auth, TLS server, and messaging keys separate. Test canonicalization, clone/key theft, invite replay, live revocation, and unknown devices. |
| [Matrix Olm/Megolm](https://spec.matrix.org/latest/olm-megolm/) / [vodozemac](https://github.com/matrix-org/vodozemac) | Per-device E2EE, offline delivery, device verification/revocation, replay handling | Signed identity keys, one-time keys, per-device sessions, ratchets, and ciphertext-only homeservers | Evaluated the official `@matrix-org/matrix-sdk-crypto-wasm@18.3.1` and `@matrix-org/matrix-sdk-crypto-nodejs@0.6.1` bindings; no Matrix source or dependency is shipped in this alpha | Apache-2.0; compatible in principle, but each binding's runtime and native-binary obligations still require release review | The Rust SDK exposes a no-network crypto state machine and durable SQLite store, but the WASM binding's durable IndexedDB path failed in Bun and the Node binding requires a native Node runtime. The alpha therefore keeps its reviewed sealed-box envelope and does not silently downgrade or claim Matrix/Signal interoperability. The future migration must test bad signatures, prekey reuse, replay indices, skipped/out-of-order messages, lost session state, new devices, rotation, attachments, and absence of plaintext in DB/logs. |
| [Matrix room creation](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3createroom) | Atomic Co-Project creation with initial state and members | Establish creator membership, permissions, metadata, encryption state, and invitations as one authenticated room-creation operation with defined ordering | Concepts only; CoCodex independently implements its device-key and SQLite transaction model | Matrix specification and SDKs are Apache-2.0; compatible, with no source copied or dependency added | CoCodex requires a complete owner-signed epoch-1 envelope set and commits project, membership, and opaque key state in one transaction. It does not federate, use Matrix room IDs, or expose encryption state to the Server as plaintext. Test incomplete/substituted rosters, altered metadata, conflicting replay, crash staging, acknowledgement loss, and recipient recovery. See ADR 0037. |
| [Signal specifications](https://signal.org/docs/) / [libsignal](https://github.com/signalapp/libsignal) | X3DH, Double Ratchet, Sesame multi-device session management | Asynchronous prekeys, forward secrecy, break-in recovery, offline multi-device delivery, bounded skipped-key state | Specifications and failure cases only; do not use or copy libsignal without accepting its license | libsignal is AGPL-3.0; incompatible with an MIT-only distribution absent an explicit licensing decision | Do not claim Signal Protocol compatibility. Apply its failure cases to the selected maintained Matrix implementation. |
| [libsodium](https://github.com/jedisct1/libsodium) / [sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes) | Private-alpha one-recipient message encryption | Anonymous X25519 sealed boxes provide reviewed authenticated public-key encryption without designing a cipher | Reuse `libsodium-wrappers-sumo` 0.8.2 for the narrow private-alpha envelope | ISC; compatible and notice preserved | Each device has a separate X25519 messaging key and Ed25519 signing identity. The server stores ciphertext envelopes only. Sealed boxes do not provide a Double Ratchet, forward secrecy after recipient-key compromise, multi-device sessions, or key rotation; those remain later Matrix-style requirements and CoCodex does not claim Signal compatibility. |
| [libsodium AEAD](https://doc.libsodium.org/secret-key_cryptography/aead) / [XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305) | Project key epochs and authenticated project records | Random project keys, per-device sealed key envelopes, nonce/AAD-bound ciphertext, and rotation after trust changes | Reuse `libsodium-wrappers-sumo` 0.8.2 for the shipped project-wrap, encrypted-context, encrypted-chat, encrypted-prompt, encrypted-artifact, encrypted local-file-reference metadata, and keyed-agent slices; do not copy source | ISC; compatible and covered by the existing notice review | The server stores opaque key/context/chat/prompt/artifact/file-reference/task/result envelopes and validates signatures, membership, revisions, and epoch monotonicity without decrypting. File bytes are not transferred; full multi-device message lifecycle remains explicitly incomplete. |
| [js-libp2p](https://github.com/libp2p/js-libp2p) / [specifications](https://github.com/libp2p/specs) | Future peer identity, Noise/TLS, TCP/QUIC, multiplexing, AutoNAT, hole punching, relay | Modular secure transports and resource-managed peer streams | Defer until the forwarded-port private alpha passes | js-libp2p is Apache-2.0; every selected module still requires exact license review | Never enable plaintext production transport. Later test peer-ID mismatch, address spoofing, stream exhaustion, relay abuse, downgrade, mapping lifecycle, and CGNAT diagnosis. |
| [OpenHands](https://github.com/OpenHands/OpenHands) / [architecture](https://docs.openhands.dev/sdk/arch/overview) | Typed agent events, runtime separation, streaming actions/observations, tool reporting | Append-only typed events and isolated execution boundaries | Concepts only where OpenCodex lacks behavior; reuse OpenCodex and official Codex runtime first | Core is MIT; `enterprise/` uses separate terms and is excluded | Task/result events are signed, typed, idempotent, and bounded. Test duplicate action IDs, resume cursors, forged observations, path escape, cancellation, output limits, and secret redaction. |
| [OpenCodex usage/quota modules](https://github.com/lidge-jun/opencodex) | Local token accounting, provider quota windows, reset times, and account selection | Keep credential and quota ownership on the client; publish only a sanitized signed projection | Reuse existing OpenCodex accounting concepts and DTO shapes; no provider credential code is moved into the server | OpenCodex base is MIT; selected dependency notices remain governed by the root lockfile | CoCodex signs bounded per-device reports, stores only the latest report server-side, filters by project membership, and renders explicit missing/stale state. It does not claim provider quota data when the local adapter has not supplied it. |
| [Automerge](https://github.com/automerge/automerge) / [concepts](https://automerge.org/docs/reference/concepts/) | Offline-first structured state and replicated JSON-like data | Transport-independent CRDT sync and immutable history | Reject for private alpha; reconsider only for a demonstrated structured-state need | MIT; compatible | Yjs/Hocuspocus already covers the required shared-text path. Maintaining two CRDT stacks would add needless security and operational complexity. |

## Selected private-alpha approach

- **Networking:** one forwarded TLS/WSS server port; manual forwarding first.
- **Authority handoff:** use a destination-bound, source-signed transfer
  certificate and monotonically increasing epoch; never run two writable server
  authorities for the same project state.
- **Execution boundary:** independently adapt MeshCentral's server-routes /
  local-agent-executes pattern.
- **Device identity:** independently adapt Syncthing's cryptographic
  fingerprint and explicit trust model using Ed25519 identities protected by
  the operating system. The Server now distributes a bounded directory of
  other approved certificate-bearing devices, but discovery never implies
  trust: the resident Client verifies the self-signed certificate and the
  local user must independently confirm and enter its enrolled fingerprint
  before encryption. The protected contact cache is bound to the authenticated
  Server authority, and raw certificates remain outside the renderer. See ADR
  0036.
- **Collaborative text:** use Yjs 13.6.31 now for bounded, persisted
  shared prompt text; keep Hocuspocus as a transport/awareness reference until
  its extra service surface is justified.
- **Private messages:** use libsodium sealed boxes plus signed, metadata-bound
  envelopes for the single-device private alpha. Keep the server
  ciphertext-only. The current implementation adds strict canonical ciphertext
  bounds, transactional replay-index insertion, a durable client cursor and
  bounded receipt/deferred-ciphertext sets, retry after trust/key recovery,
  self-sent delivery accounting, sender-visible delivered/read receipts with
  an independent recovery cursor, a bounded ciphertext-only local timeline for
  sender echo/restart replay/local search, and an active
  authorization-revocation sweep. The
  evaluated official Apache-2.0 Matrix bindings are not silently substituted
  until a supported Bun/package persistence path exists. Do not claim forward
  secrecy, rotation, or full multi-device messaging; do not invent a cipher or
  use AGPL libsignal in an MIT-only build. The exact boundary and migration
  conditions are recorded in ADR 0014, ADR 0022, ADR 0034, ADR 0035, and ADR
  0036.
  Receipt metadata
  uses the authenticated WSS session and server-side recipient binding; it is
  not a second cryptographic protocol. Decrypted private text exists only in
  the resident process; disk history contains self/recipient sealed ciphertext
  and enters an agent context only through the explicit signed/encrypted
  `private.share` path.
- **Project content:** use a separate X25519 project-wrap keypair and random
  per-project keys. Owner-signed sealed key envelopes and XChaCha20-Poly1305
  content envelopes keep the server blind to the shipped Final Goal/context,
  chat, prompt, artifact, encrypted local-file-reference metadata, and keyed
  agent task/result paths. File-content transfer, legacy no-key compatibility,
  and the remaining multi-device lifecycle stay explicitly scoped; no partial
  encryption claim is generalized to the whole project.
- **Atomic project bootstrap:** create a Co-Project from the resident Client
  with one signed request that binds its normalized name, owner, complete
  verified-device roster, and exact epoch-1 envelope set. The Server admits
  approved devices and commits project, membership, epoch, and envelopes in
  one immediate SQLite transaction. The Client stages the exact signed request
  and project key before network delivery, replays it after reconnect, and
  withholds all envelope material from the renderer. This independently adapts
  Matrix room-creation ordering, MeshCentral authority boundaries, and
  Syncthing-style explicit device trust; no reference source is copied. See
  ADR 0037.
- **Encrypted shared chat:** the shipped `project.chat.*` path uses the same
  signed XChaCha20 content envelopes, a server-assigned sequence, and a
  ciphertext-only SQLite table. The client decrypts locally and exposes the
  normal chat event shape. Legacy `chat.*` remains for old fixtures when no
  project key exists; a release must migrate every project record type before
  removing that compatibility path.
- **Encrypted shared prompt:** the shipped `project.prompt.*` path carries
  individually encrypted Yjs updates. The server orders and deduplicates
  opaque updates but never applies Yjs; each client decrypts locally and feeds
  the update to its existing Yjs document. Legacy `prompt.*` remains only when
  no project key is available.
- **Encrypted artifacts:** the shipped `project.artifact.*` path carries a
  signed opaque envelope whose plaintext includes type, title, summary, status,
  and body. The server stores only the envelope plus project/task/author
  routing metadata; clients decrypt and validate the familiar artifact shape.
  Legacy `artifact.*` remains only when no project key is available.
- **Encrypted agent prompts/results:** when a project key is available, the
  requester seals the prompt as a `task` envelope and the host seals every
  streamed result as an `agent-response` envelope. The server stores only
  `[encrypted]` and routing metadata, signs the dispatch transcript, and
  never executes or decrypts the task. The host verifies, decrypts, and runs
  the local Codex adapter; encrypted cancellation is completed by the host.
  Legacy agent frames remain only for projects without a key. See ADR 0016.
- **Agent events:** reuse OpenCodex and official Codex runtime behavior;
  borrow only typed event and isolation concepts from OpenHands. Server task
  dependencies are canonicalized before signing/idempotency checks, bounded by
  a graph walk that rejects cycles, and included in both plaintext and
  encrypted dispatch verification. A host never executes a task whose signed
  dependency proof does not validate.
- **Task Git isolation:** use Git's maintained worktree interface directly,
  not OpenHands source or a second runtime. New code-agent policies create a
  locked, task-owned branch/worktree from a clean named base; legacy policies
  retain explicit shared-directory behavior. The host signs sanitized branch,
  base, merge-target, and workspace-reference metadata, and official Codex
  starts only after the Server acknowledges it. CoCodex never force-resets,
  stashes, removes, or automatically cleans up user worktrees. See ADR 0024.
- **Artifact handoffs:** adapt MeshCentral's authoritative route/local
  execution boundary and OpenHands' typed tool-result concept without copying
  code. A task names a bounded explicit set of same-project artifact IDs; the
  server signs and routes their opaque envelopes, while only the trusted local
  Client verifies, decrypts, and supplies ready artifacts to Codex. Yjs and
  Automerge are not used for immutable handoff records. See ADR 0023.
- **Local access profiles:** reuse the installed official Codex runtime's
  supported `--sandbox danger-full-access` mode only after an explicit local
  policy opt-in. The Client owns the policy and emergency stop; the Server
  never receives a shell or desktop capability. No runtime source is copied.
  See ADR 0021. Elevated Windows helpers, browser control, and remote desktop
  remain separate requirements rather than metadata pretending to implement
  them.
  - **Agent roster:** adapt MeshCentral's authoritative server/device boundary.
    `agent.list.result` is server-derived from approved host readiness and task
    rows; the client renders discovery only, while every dispatch still passes
    signed server authorization and local execution policy. See ADR 0018.
  - **Multiple local agents:** keep the MeshCentral-style endpoint boundary but
    isolate each hosted agent behind its own authenticated worker lease,
    execution journal, safety record, and worktree registry. OpenHands informs
    runtime-session separation only; no reference source is copied. See ADR
    0026.
- **Revocation-safe key rotation:** retain Syncthing-style cryptographic device
  identity and explicit trust, then add a CoCodex-specific server epoch gate
  plus an atomic owner removal/complete-recipient rotation command. The
  resident Client, not the GUI or Server, generates the next key and sealed
  envelopes from device-signed key certificates whose signing fingerprints
  were explicitly trusted locally. Removed requesters
  and hosts have active tasks terminalized, and reconnect project-list
  reconciliation revokes devices that missed the live notice. No reference
  source code is copied; the transactions, immutable exact replay, strict
  notices, revoked-project outbox purge, and legacy-route rejection are
  independently implemented. See ADR 0019 and ADR 0031.
- **Authoritative project context:** the encrypted `project.context.*` path
  keeps only signed opaque envelopes in SQLite, with a monotonic server
  revision; stale optimistic writers receive a conflict instead of overwriting
  another member. Context updates are durable in the client outbox while
  offline, and the server broadcasts the accepted envelope to project members.
  The legacy `context.*` path remains for existing alpha fixtures and is
  explicitly server-readable. This is not a second CRDT system; Yjs remains
  reserved for concurrent prompt text.
- **Future connect layer:** defer libp2p, automatic NAT traversal, and relays
  until the direct server path is complete.
- **Structured CRDT:** do not add Automerge to the private alpha.

## Cross-cutting implementation rules

1. Authenticate and authorize before applying CRDT or command events.
2. Verify the pinned TLS server fingerprint before sending an enrollment
   token.
3. Hash invitation tokens at rest and consume them atomically.
4. Keep device signing, TLS server, project encryption, and private-message
   keys separate.
5. Require both server route authorization and local execution authorization.
6. Make event IDs idempotent and enforce nonce, expiry, and sequence replay
   bounds.
7. Keep private-message plaintext and attachment keys out of server storage,
   logs, agent context, and evidence artifacts.
8. Enforce bounded messages, queues, connections, streams, and persisted
   history.
9. Preserve MIT and Apache notices and patent terms. Keep MPL, GPL, AGPL, and
   source-available code out of the distribution unless an explicit licensing
   decision accepts the obligations.
10. Generate a lockfile license report or SBOM before shipping and review
    every resolved transitive dependency.
11. Keep project context and Final Goal separate from private-message
    plaintext. Context is shared project state and may enter agent context only
    through an explicit client-side selection; private ciphertext is never
    decoded by the server.

## Matrix binding evaluation record

The official Matrix Rust SDK documentation describes `OlmMachine` as a
no-network encryption state machine whose outgoing requests and sync changes
must be persisted and replayed in order. The JavaScript/WASM binding was
verified to initialize in Bun only without a durable store; its IndexedDB
store path failed because the Bun desktop runtime did not provide the required
IndexedDB implementation. The Node.js binding was verified with its SQLite
store under the cached Node runtime, but its native binary and Node-version
requirements are not a safe dependency for the Bun-compiled Client/Server
artifacts. These are runtime observations, not a license rejection.

Accordingly, the current alpha reuses only the Matrix architecture and failure
cases. It retains the existing reviewed sealed-box wire format while hardening
delivery and persistence. A Matrix migration is allowed only after a maintained
binding (or a separately supported crypto helper) provides durable encrypted
state, packaged-client support, key upload/claim and sync transport, device
verification/revocation mapping, and restart/offline/replay tests. The migration
must be recorded in a new ADR and cannot silently change the security claim of
existing private messages.

## Failure cases that become tests

- Unknown, revoked, cloned, or wrongly pinned device
- Expired, reused, intercepted, or cross-scope invitation
- Tampered signature, payload hash, nonce, expiry, sequence, or project scope
- Unauthorized CRDT document and oversized or malformed update
- Duplicate or out-of-order CRDT update with convergence verification
- Server authorization accepted but local execution policy rejected
- Duplicate task/action ID and forged result event
- Private-message replay, prekey reuse, unverified new device, lost session,
  rotation, and offline delivery
- Server DB/log scan proving a private-message canary is absent
- Server restart with per-device FIFO queue recovery and global authoritative
  event order
- Local OpenCodex request success while collaboration is offline
