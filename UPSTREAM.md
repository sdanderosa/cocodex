# CoCodex and OpenCodex

CoCodex is an MIT-licensed fork of
[OpenCodex](https://github.com/lidge-jun/opencodex). OpenCodex remains the
foundation for the local provider proxy, Codex integration, account routing,
model catalog, quota reporting, transports, management API, and local
dashboard.

## Repository relationship

- CoCodex origin: `https://github.com/sdanderosa/cocodex.git`
- OpenCodex upstream: `https://github.com/lidge-jun/opencodex.git`
- Initial upstream base: `357acee6` (`v2.7.39`)
- CoCodex foundation branch: `feat/cocodex-foundation`
- Normal OpenCodex contribution base: `upstream/dev`

The CoCodex feature branch and pull requests must target the CoCodex fork.
Never push CoCodex work to `lidge-jun/opencodex`.

## Remote setup

```sh
git remote add upstream https://github.com/lidge-jun/opencodex.git
git fetch origin
git fetch upstream
```

Expected remotes:

```text
origin    https://github.com/sdanderosa/cocodex.git
upstream  https://github.com/lidge-jun/opencodex.git
```

## Updating from upstream

Fetch first, review the upstream range, and merge deliberately:

```sh
git fetch upstream
git log --oneline HEAD..upstream/dev
git merge upstream/dev
```

Run the complete OpenCodex and CoCodex validation gates after every upstream
merge. Do not resolve conflicts by discarding OpenCodex security, credential,
restore, transport, or privacy behavior.

## Intentional CoCodex differences

CoCodex adds systems that OpenCodex does not currently provide:

- A separate headless CoCodex Server process and package
- A versioned collaboration protocol over one TLS/WSS port
- Cryptographic device identity, enrollment, approval, and revocation
- Authoritative shared projects, chats, tasks, artifacts, and event ordering
- Client-local remote-agent execution with independent authorization
- End-to-end encrypted private-message delivery
- Offline client queues and ordered reconnect recovery
- Collaborative prompt editing using a maintained CRDT

The local OpenCodex proxy remains independently usable while the collaboration
server is offline. Provider credentials, Codex authentication state, device
private keys, and private-message keys never become server state.

## Expected conflict areas

- `package.json`, package binaries, and release metadata
- `src/cli/` entrypoint and lifecycle wiring
- `src/config.ts` and local-state ownership
- `src/server/` transport and authentication boundaries
- `gui/src/App.tsx`, navigation, API transport, and locale files
- Tests and cross-platform CI duration
- Public installation and security documentation

CoCodex-specific code should stay behind explicit modules and process
boundaries so upstream merges do not require invasive rewrites.

## Compatibility aliases

The CoCodex client commands are `cocodex` and `ccx`. Compatibility aliases
`opencodex` and `ocx` remain available where required to preserve existing
automation and local Codex behavior. The server commands are
`cocodex-server` and `ccx-server` and must never invoke the local OpenCodex
proxy lifecycle implicitly.
