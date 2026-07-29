# Authoritative project lifecycle evidence

Date: 2026-07-28

## Implemented boundary

CoCodex now implements owner-only rename, archive, restore, and permanent delete across the strict protocol, SQLite authority transaction, TLS/WSS Server, resident Client session, minimal renderer bridge, and native desktop UI.

The normative security and state contract is [ADR 0055](../adr/0055-cocodex-authoritative-project-lifecycle.md). Sunshine host-network non-interference remains independently binding under [ADR 0054](../adr/0054-sunshine-host-service-protection.md).

## Source evidence

- `packages/cocodex-protocol/src/project-lifecycle.ts` defines strict lifecycle request, transition, acknowledgement, deletion, and signing-transcript schemas.
- `apps/cocodex-server/src/project-lifecycle.ts` verifies approved owner authority, signature, Server fingerprint/epoch, validity, optimistic revision, transition preconditions, and idempotency inside one immediate transaction.
- migration 32 adds lifecycle state/revision and a deletion-surviving operation tombstone.
- `apps/cocodex-server/src/project-locks.ts` denies writes to archived projects.
- `apps/cocodex-server/src/server.ts` delivers personalized snapshots, clears presence, and broadcasts deletion to the pre-cascade member set.
- `src/cocodex/session.ts` signs commands and revokes local project access before exposing deletion.
- `src/cocodex/gui-bridge.ts` accepts only minimal unsigned renderer intent and rejects renderer-supplied signatures or extra authority fields.
- the CoCodex UI separates active and archived projects, exposes owner controls, requires exact deletion confirmation, and recovers selection after deletion.

## Test evidence

Focused lifecycle coverage passed before this evidence record:

- protocol lifecycle: 2 tests;
- Server lifecycle transaction: 2 tests;
- GUI lifecycle state: 2 tests;
- real TLS/WSS archive, restart, restore, and delete extension: 1 scenario;
- maintained CoCodex suite: 210 pass, 0 fail, 2,350 assertions across 42 files;
- complete GUI suite: 147 pass, 0 fail, 681 assertions across 31 files;
- complete inherited root suite after the final privacy-timeout repair: 4,265 pass, 4 skip, 0 fail, 21,761 assertions across 359 files in 265.19 seconds.

The root-suite privacy scan itself passed with all four assertions in 3.23 seconds. The outer test timeout was raised from Bun's 5-second default to 15 seconds only to provide loaded-suite orchestration headroom; the scan command and assertions were not weakened.

## Visual and host evidence

Browser DOM/computed-layout inspection of the lifecycle fixture proved both active and archived management panels fit the 280-pixel project rail without horizontal overflow or overlapping buttons; the browser screenshot facility returned only the fixture background, so no screenshot claim is made.

Before and after the Sunshine regression, the foreign OpenCodex listener remained PID 3704 on `127.0.0.1:10100`. Sunshine remained service PID 5044/application PID 11100 with TCP listeners 47984, 47989, 47990, and 48010. No process was stopped, adopted, signaled, or reconfigured.

Fresh clean-commit artifacts are preserved under `dist/release-evidence/d774fa6c/`. The private-alpha archive, NSIS, MSI, bundled runtime, and desktop hashes are recorded in `tauri-managed-client-runtime.md`. Both installer variants rejected foreign PID 3704, launched only WebView2, started no sidecar, and cleaned up exactly; the installed archive verifier also passed OpenCodex GUI/health and CoCodex Server restart on isolated non-10100 ports.
