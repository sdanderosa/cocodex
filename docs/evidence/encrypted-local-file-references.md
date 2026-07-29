# Encrypted local file-reference evidence

## Scope

This slice publishes, lists, decrypts, retries, and recovers encrypted metadata
for a regular file attached to an encrypted project artifact. File bytes remain
local; this evidence does not claim encrypted file-content transfer.

## Commands

```powershell
.\node_modules\.bin\bun.exe run typecheck:cocodex
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\apps\cocodex-server\tests\project-encryption-storage.test.ts `
  .\apps\cocodex-server\tests\project-encryption-server.test.ts `
  .\tests\cocodex-project-encryption.test.ts `
  .\tests\cocodex-project-encryption-session.test.ts `
  .\tests\cocodex-outbox.test.ts
.\node_modules\.bin\bun.exe run test:cocodex
.\node_modules\.bin\bun.exe run privacy:scan
```

## Assertions

- Strict protocol frames reject unknown plaintext routing fields and bind the
  envelope to the project, record type, and reference ID.
- SQLite stores only routing UUIDs, timestamps, and the signed ciphertext
  envelope.
- Only the artifact host may publish; membership, sender key, signature,
  current epoch, replay, and the hard 500-record recovery cap fail closed.
- Real authenticated TLS/WSS sockets publish, broadcast, and list references.
- Two resident clients decrypt identical metadata, while path and byte canaries
  remain absent from the server envelope.
- Local traversal and workspace escape fail closed. The implementation also
  rejects linked paths, non-regular files, files larger than 512 MiB, and
  mutation detected while hashing; focused race-platform coverage remains a
  follow-up.
- Offline outbox storage contains only sealed frames, and list recovery succeeds
  after server restart.

## Recorded result

- Focused encryption/reference suite: 52 passed, 0 failed, 392 assertions.
- Full `test:cocodex` gate: 115 passed, 0 failed, 1020 assertions across 30
  files, including the real three-process private-alpha process.
- Client build: exit 0.
- Server build: exit 0.
- Privacy scan: exit 0, `Privacy scan passed`.
- Implementation commit: `36feba4544f85c8b42ca3d88246e59c68541ce3b`.
