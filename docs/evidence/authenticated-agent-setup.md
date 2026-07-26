# Authenticated named-agent setup evidence

- Date: 2026-07-26
- Branch: `feat/cocodex-foundation`
- Status: connected slice complete; multi-agent local policy is implemented in
  ADR 0026, while crash-atomic cross-process setup remains a follow-up

## Focused integration gate

Command:

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\apps\cocodex-server\tests\collaboration-server.test.ts `
  .\tests\cocodex-gui-bridge.test.ts `
  .\tests\cocodex-project-encryption-session.test.ts
```

Exit status: `0`

Relevant output:

```text
32 pass
0 fail
299 expect() calls
Ran 32 tests across 5 files.
```

Named tests include:

- `self-registers one signed host agent idempotently and audits once`
- `creates a signed self-hosted agent over WSS and rejects spoofed authority`
- `configures a signed self-hosted agent and reconnects it as ready`
- `runs the resident session without exposing private ciphertext`

The last test starts a real TLS/WSS Server and resident Client, configures a
canonical temporary Git repository through the same JSON-line path used by the
GUI, verifies the protected local policy, observes reconnect, and checks the
server-derived roster reaches `available`.

## Supporting gates

```text
typecheck:cocodex  exit 0
lint:gui           exit 0 (one pre-existing hook warning)
build:gui          exit 0 (bundle-size advisory)
privacy:scan       exit 0
git diff --check   exit 0
```

## Final full gate

```text
test:cocodex         exit 0: 104 pass, 0 fail, 911 expectations
build:cocodex-client exit 0
build:cocodex-server exit 0
typecheck:cocodex    exit 0
build:gui             exit 0 (bundle-size advisory)
lint:gui              exit 0 (one pre-existing hook warning)
privacy:scan          exit 0
git diff --check      exit 0
```

The real three-process private-alpha scenario remained green in that historical
run. ADR 0026 and `docs/evidence/concurrent-local-agents.md` supersede the
single-agent count with a two-worker run (`1 pass`, `0 fail`, `71 expect()`
calls). The earlier checkpoint's complete
upstream OpenCodex chunk audit remains the latest full upstream baseline; this
slice changes only CoCodex modules, GUI code, documentation, and CoCodex tests.
