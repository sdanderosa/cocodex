# Codex CLI session efficiency evidence

- Date: 2026-07-28
- Installed runtime: `codex-cli 0.146.0-alpha.3.1`
- Branch: `feat/cocodex-foundation`
- Status: implemented and verified locally; not a claim of an app-specific caching defect

## Implemented behavior

Each configured local CoCodex agent now persists one independent Codex CLI
session per signed project/chat scope. The isolation fingerprint binds:

- project, chat, and agent IDs;
- configured workspace root;
- primary model and reasoning effort;
- co-agent model, effort, and concurrency limit;
- sandbox, access profile, and full-computer opt-in;
- selected Codex runtime version; and
- local approval mode and trusted-requester policy.

A changed project, chat, model, runtime, workspace boundary, access policy, or
trust policy starts a fresh session. Execution for one adapter is serialized so
two queued tasks cannot race the same session record.

Fresh turns use persisted `codex exec --json` and capture the UUID from
`thread.started`. Related turns use
`codex exec --json --sandbox <mode> resume <session-id> -`. One-off local
runs without a configured session store remain explicitly `--ephemeral`.

Session state is written atomically under the protected per-agent local state
directory. A failed resume is never retried with the same signed task, avoiding
duplicate side effects. If a resume fails before any activity, only that stale
record is discarded so the next distinct signed task can start cleanly.

The stable policy prefix is repeated byte-for-byte for the same agent policy.
The task scope contains only project/chat/agent identity, dependency task IDs,
accepted input artifact IDs, the authoritative final goal supplied by the
composer, the task prompt, and explicitly selected ready/accepted/integrated
artifacts. Shared-chat history is not copied into the agent prompt.

The installed noninteractive CLI exposes resume but no compact subcommand.
CoCodex therefore makes an honest controlled rotation before the next task
after 24 turns or after a turn reports at least 180,000 input tokens. This is
session rotation, not a false claim of noninteractive `/compact` support.

## Measured live proof

A two-turn read-only integration check ran through the production adapter and
the installed CLI with the same project, chat, agent, model, workspace, and
trust policy. Both exact expected responses completed. The protected session
record reported `turns: 2` for one captured session UUID.

| Turn | Input tokens | Cached input tokens | Measured cached share |
| --- | ---: | ---: | ---: |
| 1 | 21,715 | 1,920 | 8.8% |
| 2 (resumed) | 51,362 | 23,296 | 45.4% |

These are the CLI's provider-reported `turn.completed.usage` values on this
machine. They prove cache reuse occurred; they do not guarantee a fixed future
ratio or establish that the Codex desktop app has a caching bug.

Signed usage reports now include an optional bounded per-agent breakdown.
The desktop Usage rail renders the cached-input percentage for each host and
each local agent.

## Verification

- Persistent/resume/isolation/rotation adapter tests: 7 passed.
- Per-agent accounting test: passed.
- Protocol signing test binds the per-agent breakdown and rejects duplicate IDs.
- Live two-turn integration: completed with the measured values above.
- Complete repository regression after fixes: 4,240 passed, 4 skipped,
  0 failed, 21,630 expectations across 353 files.
- Explicit CoCodex suite: 177 passed, 0 failed, 2,048 expectations.
- GUI suite: 130 passed, 0 failed, 612 expectations.
- Root and CoCodex TypeScript checks, GUI production build/lint, Rust tests,
  and Clippy with warnings denied all exited 0.

Primary implementation files:

- `src/cocodex/codex-agent-adapter.ts`
- `src/cocodex/codex-session-store.ts`
- `src/cocodex/agent-runtime-paths.ts`
- `src/cocodex/usage.ts`
- `packages/cocodex-protocol/src/usage.ts`
- `gui/src/pages/CoCodex.tsx`
