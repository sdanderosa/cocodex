# Complete protected Server recovery evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `1f3d2c2fa430fceffb7fbe115998c0bb19d1168b`
- Implementation commit: recorded by the commit containing this file
- Status: complete CoCodex, inherited OpenCodex, GUI, build, privacy, and
  focused recovery gates pass

## Behavior proved

The stopped Server creates one passphrase-protected version-2 archive containing
its normalized configuration, checkpointed SQLite authority, Ed25519 identity,
and TLS identity. Restore into an empty state root reconstructs the same trusted
authority and rewrites TLS file paths for the destination root. Restore over an
initialized Server atomically retains the prior root as a timestamped rollback.

The version-1 unencrypted database-only command path is removed. The planned
destination-bound authority-transfer flow remains separate and unchanged.

## Focused library and real CLI evidence

```powershell
.\node_modules\.bin\bun.exe test `
  ./apps/cocodex-server/tests/backup.test.ts `
  ./apps/cocodex-server/tests/cli-process.test.ts
```

Exit status `0`: `5 pass`, `0 fail`, `54 expect()` calls.

The library test plants a database secret canary and uses a known admin token.
It proves the serialized archive contains neither canary, token, PEM private
key, nor path; rejects a wrong passphrase and modified ciphertext without
creating a destination; restores identity, TLS fingerprint, endpoint, active
epoch, and database content into an empty root; and preserves an initialized
replacement's former identity in the reported rollback directory. It also
rejects a TLS private key that does not match the archived certificate.

The CLI test initializes a standalone source, rejects backup without a protected
passphrase source, creates the encrypted complete archive, restores a different
empty root, verifies stopped status, then starts that restored Server and
receives a real TLS health response before stopping it cleanly.

## Static evidence

```powershell
.\node_modules\.bin\bun.exe run typecheck:cocodex
```

Exit status `0`.

## Complete CoCodex and inherited regression

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
.\node_modules\.bin\bun.exe run build:cocodex-server
.\node_modules\.bin\bun.exe run privacy:scan
.\node_modules\.bin\bun.exe run test:batched
```

Every command exited `0`:

- complete CoCodex: `158 pass`, `0 fail`, `1487 expect()` calls across 35
  files, including the 290-assertion compiled private-alpha process;
- production Server: 369 modules bundled and compiled;
- privacy scan: passed;
- inherited OpenCodex: all 346 files completed across 14 fresh isolated
  workers in 324.7 seconds.

## GUI regression

```powershell
cd gui
..\node_modules\.bin\bun.exe test
..\node_modules\.bin\bun.exe run lint
..\node_modules\.bin\bun.exe run lint:i18n
..\node_modules\.bin\bun.exe run build
```

Every command exited `0`: `122 pass`, `0 fail`, `579 expect()` calls across 22
GUI files; i18n lint and the TypeScript/Vite production build passed. Standard
lint reported zero errors and the existing unrelated
`use-app-route-state.ts` exhaustive-deps warning.

## Primary files

- `apps/cocodex-server/src/recovery-backup.ts`
- `apps/cocodex-server/src/cli.ts`
- `apps/cocodex-server/src/backup.ts`
- `apps/cocodex-server/tests/backup.test.ts`
- `apps/cocodex-server/tests/cli-process.test.ts`
- `docs/adr/0046-cocodex-complete-protected-server-recovery.md`

## Honest limits

This archive is intentionally an in-memory alpha format capped at a 1 GB
database and 1.5 GB serialized archive. The successful rollback directory is
preserved rather than deleted automatically. Same-identity recovery is unsafe
while the original authority can still run; planned moves must use authority
handoff. Live-disk OS-backed private-key protection is not claimed by this
checkpoint.
