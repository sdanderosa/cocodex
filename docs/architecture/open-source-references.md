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
| [MeshCentral](https://github.com/Ylianst/MeshCentral) / [design docs](https://docs.meshcentral.com/design/) | Authoritative server, installed agents, device enrollment, routed remote operations | Agents connect outward; server authenticates and scopes operations; the endpoint agent performs them | Adapt concepts independently | Apache-2.0; compatible with required notices | CoCodex exposes no raw remote shell. Server and destination client both authorize signed task envelopes. Test revocation, replay, expiry, capability escalation, cert mismatch, and server-compromise boundaries. |
| [Yjs](https://github.com/yjs/yjs) / [threat model](https://github.com/yjs/yjs/blob/main/THREAT_MODEL.md) | Collaborative prompt text, offline updates, convergence, awareness | Commutative and idempotent updates, state vectors, `Y.Text`, and ephemeral awareness | Reuse stable `yjs` 13.6.31 for project prompt documents | MIT; compatible | Yjs supplies convergence, not authentication, authorization, TLS, or safe rendering. Apply project/document ACLs before updates; cap bytes, depth, and rates; support snapshot recovery from malicious authorized edits. |
| [Hocuspocus](https://github.com/ueberdosis/hocuspocus) / [hooks](https://tiptap.dev/docs/hocuspocus/server/hooks) | Yjs WebSocket transport, auth hooks, reconnection, persistence | Typed TypeScript collaboration server/provider with pre-auth and persistence hooks | Concepts only for private alpha; defer the dependency while the existing authenticated WSS transport remains sufficient | MIT; compatible | Mount on the one TLS listener. Never treat document names or bearer strings as authorization. Persist exact binary Yjs data. Test pre-auth queue exhaustion, cross-project access, payload limits, restart reload, and apply/store crash behavior. |
| [Syncthing](https://github.com/syncthing/syncthing) / [security model](https://docs.syncthing.net/users/security.html) | Permanent device identity, fingerprints, explicit trust, unknown-device rejection | Device identity derives from cryptographic keys and explicit allowlists, not discovery names or addresses | Concepts only | MPL-2.0; avoid copying implementation files unless obligations are isolated and accepted | Use canonical public-key fingerprints and pending/approved/revoked states. Keep device auth, TLS server, and messaging keys separate. Test canonicalization, clone/key theft, invite replay, live revocation, and unknown devices. |
| [Matrix Olm/Megolm](https://spec.matrix.org/latest/olm-megolm/) / [vodozemac](https://github.com/matrix-org/vodozemac) | Per-device E2EE, offline delivery, device verification/revocation, replay handling | Signed identity keys, one-time keys, per-device sessions, ratchets, and ciphertext-only homeservers | Evaluate official Matrix crypto state-machine bindings; do not compose primitives by hand | vodozemac and Matrix SDKs are Apache-2.0; compatible with notices and exact-binding review | Server is only a key-bundle and ciphertext mailbox. Never silently downgrade. Test bad signatures, prekey reuse, replay indices, skipped/out-of-order messages, lost session state, new devices, rotation, attachments, and absence of plaintext in DB/logs. |
| [Signal specifications](https://signal.org/docs/) / [libsignal](https://github.com/signalapp/libsignal) | X3DH, Double Ratchet, Sesame multi-device session management | Asynchronous prekeys, forward secrecy, break-in recovery, offline multi-device delivery, bounded skipped-key state | Specifications and failure cases only; do not use or copy libsignal without accepting its license | libsignal is AGPL-3.0; incompatible with an MIT-only distribution absent an explicit licensing decision | Do not claim Signal Protocol compatibility. Apply its failure cases to the selected maintained Matrix implementation. |
| [libsodium](https://github.com/jedisct1/libsodium) / [sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes) | Private-alpha one-recipient message encryption | Anonymous X25519 sealed boxes provide reviewed authenticated public-key encryption without designing a cipher | Reuse `libsodium-wrappers-sumo` 0.8.2 for the narrow private-alpha envelope | ISC; compatible and notice preserved | Each device has a separate X25519 messaging key and Ed25519 signing identity. The server stores ciphertext envelopes only. Sealed boxes do not provide a Double Ratchet, forward secrecy after recipient-key compromise, multi-device sessions, or key rotation; those remain later Matrix-style requirements and CoCodex does not claim Signal compatibility. |
| [libsodium AEAD](https://doc.libsodium.org/secret-key_cryptography/aead) / [XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305) | Project key epochs and authenticated project records | Random project keys, per-device sealed key envelopes, nonce/AAD-bound ciphertext, and rotation after trust changes | Reuse `libsodium-wrappers-sumo` 0.8.2 for the shipped project-wrap, encrypted-context, encrypted-chat, and encrypted-prompt slices; do not copy source | ISC; compatible and covered by the existing notice review | The server stores opaque key/context/chat/prompt envelopes and validates signatures, membership, revisions, and epoch monotonicity without decrypting. Tasks, results, artifacts, and file references remain explicitly incomplete. |
| [js-libp2p](https://github.com/libp2p/js-libp2p) / [specifications](https://github.com/libp2p/specs) | Future peer identity, Noise/TLS, TCP/QUIC, multiplexing, AutoNAT, hole punching, relay | Modular secure transports and resource-managed peer streams | Defer until the forwarded-port private alpha passes | js-libp2p is Apache-2.0; every selected module still requires exact license review | Never enable plaintext production transport. Later test peer-ID mismatch, address spoofing, stream exhaustion, relay abuse, downgrade, mapping lifecycle, and CGNAT diagnosis. |
| [OpenHands](https://github.com/OpenHands/OpenHands) / [architecture](https://docs.openhands.dev/sdk/arch/overview) | Typed agent events, runtime separation, streaming actions/observations, tool reporting | Append-only typed events and isolated execution boundaries | Concepts only where OpenCodex lacks behavior; reuse OpenCodex and official Codex runtime first | Core is MIT; `enterprise/` uses separate terms and is excluded | Task/result events are signed, typed, idempotent, and bounded. Test duplicate action IDs, resume cursors, forged observations, path escape, cancellation, output limits, and secret redaction. |
| [OpenCodex usage/quota modules](https://github.com/lidge-jun/opencodex) | Local token accounting, provider quota windows, reset times, and account selection | Keep credential and quota ownership on the client; publish only a sanitized signed projection | Reuse existing OpenCodex accounting concepts and DTO shapes; no provider credential code is moved into the server | OpenCodex base is MIT; selected dependency notices remain governed by the root lockfile | CoCodex signs bounded per-device reports, stores only the latest report server-side, filters by project membership, and renders explicit missing/stale state. It does not claim provider quota data when the local adapter has not supplied it. |
| [Automerge](https://github.com/automerge/automerge) / [concepts](https://automerge.org/docs/reference/concepts/) | Offline-first structured state and replicated JSON-like data | Transport-independent CRDT sync and immutable history | Reject for private alpha; reconsider only for a demonstrated structured-state need | MIT; compatible | Yjs/Hocuspocus already covers the required shared-text path. Maintaining two CRDT stacks would add needless security and operational complexity. |

## Selected private-alpha approach

- **Networking:** one forwarded TLS/WSS server port; manual forwarding first.
- **Execution boundary:** independently adapt MeshCentral's server-routes /
  local-agent-executes pattern.
- **Device identity:** independently adapt Syncthing's cryptographic
  fingerprint and explicit trust model using Ed25519 identities protected by
  the operating system.
- **Collaborative text:** use Yjs 13.6.31 now for bounded, persisted
  shared prompt text; keep Hocuspocus as a transport/awareness reference until
  its extra service surface is justified.
- **Private messages:** use libsodium sealed boxes plus signed, metadata-bound
  envelopes for the single-device private alpha. Keep the server
  ciphertext-only. Evaluate official Apache-2.0 Matrix crypto bindings before
  claiming forward secrecy, rotation, or full multi-device messaging; do not
  invent a cipher or use AGPL libsignal in an MIT-only build.
- **Project content:** use a separate X25519 project-wrap keypair and random
  per-project keys. Owner-signed sealed key envelopes and XChaCha20-Poly1305
  content envelopes keep the server blind to the shipped Final Goal/context
  path. The remaining project record types stay on the legacy plaintext path
  until each one has the same end-to-end tests; no partial encryption claim is
  generalized to the whole project.
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
- **Agent events:** reuse OpenCodex and official Codex runtime behavior;
  borrow only typed event and isolation concepts from OpenHands.
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
