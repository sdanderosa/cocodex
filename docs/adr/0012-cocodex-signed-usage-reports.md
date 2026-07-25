# ADR 0012: CoCodex signed sanitized usage reports

- Status: Accepted for the connected alpha path
- Date: 2026-07-25
- Scope: cross-device usage cards; not provider credential sharing

## Context

The client owns OpenCodex accounts, provider credentials, quota refreshes, and
local runtime usage. The server must show Stephen and Kai separate, useful
usage state without receiving credentials or trusting a client-supplied name.
The server also needs a durable latest value for reconnecting clients.

## Decision

The resident client session aggregates bounded local runtime counters and writes
the sanitized report to its protected client state. Each report is signed with
the device's Ed25519 identity and sent over the authenticated WSS connection.
The signed payload contains only device ID, revision/timestamp, token counters,
request count, active-agent count, an optional local account label, and optional
quota-window percentages/reset times. Missing quota data remains missing; the
client never fabricates a zero or a percentage.

The server verifies the signature against the enrolled device key, requires the
device to be approved, rejects stale revisions/timestamps, and stores only the
latest sanitized JSON plus its signature in `usage_reports`. `usage.get` is
project-membership scoped and returns approved project members with either a
report or an explicit `null` report. Usage changes are broadcast only to
clients that subscribed to that project.

The GUI renders separate cards from server views. It never receives provider
credentials, bearer tokens, refresh tokens, or raw local account records.

## Consequences

- Usage state survives server restarts and client reconnects.
- A compromised client can misreport its own counters, but cannot impersonate
  another enrolled device or alter another device's report.
- Server operators can see sanitized totals and optional quota windows, not
  provider secrets.
- The current runtime adapter reports token counters and active local tasks;
  a later local quota adapter may populate the optional OpenCodex quota fields.
- Reports are not project-encrypted content. Project encryption remains a
  separate required milestone and is not implied by this ADR.

## Evidence

- `packages/cocodex-protocol/tests/protocol.test.ts` covers bounds and signing
  transcript binding.
- `apps/cocodex-server/tests/usage.test.ts` covers signature validation,
  revision replay rejection, membership filtering, and persistence.
- `apps/cocodex-server/tests/collaboration-server.test.ts` covers real WSS
  report/get/broadcast/reconnect behavior.
- `tests/cocodex-private-alpha-process.test.ts` covers both isolated clients'
  reports across the real server restart.
