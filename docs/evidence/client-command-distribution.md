# CoCodex Client command-distribution evidence

- Date: 2026-07-26
- Branch: `feat/cocodex-foundation`
- Implementation commit: `49ba3bc61212eb51a62870b950d7d1dab4eb1364`
- Status: focused distribution and private-alpha gates pass

## Behavior proved

The root package now publishes four distinct compatibility-safe commands:

| Command | Launcher | Application |
| --- | --- | --- |
| `cocodex` | `bin/ccx.mjs` | CoCodex Client |
| `ccx` | `bin/ccx.mjs` | CoCodex Client |
| `opencodex` | `bin/ocx.mjs` | inherited OpenCodex proxy |
| `ocx` | `bin/ocx.mjs` | inherited OpenCodex proxy |

A real Node process launched `bin/ccx.mjs`; the launcher resolved the packaged
Bun runtime and printed the CoCodex Client help containing `cocodex enroll` and
`Short alias: ccx`. The separately compiled Windows client printed the same
public command contract.

## Commands and results

Focused package test:

```powershell
$env:OCX_TEST_NODE_EXE='C:\Users\Stephen\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
.\node_modules\bun\bin\bun.exe test --isolate `
  .\tests\install-scripts.test.ts --timeout 60000
```

Exit status: `0`

```text
8 pass
0 fail
62 expect() calls
```

Real installed-launcher path:

```powershell
& 'C:\Users\Stephen\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe' `
  .\bin\ccx.mjs --help
```

Exit status: `0`. Relevant output:

```text
CoCodex Client
Usage:
  cocodex enroll --invite CODE --name NAME [--state-root PATH]
Short alias: ccx
```

Separate client build:

```powershell
.\node_modules\bun\bin\bun.exe run build:cocodex-client
.\dist\cocodex-client.exe --help
```

Exit status: `0` for both commands. The build compiled 136 modules and the
executable printed the same public command contract.

Full focused CoCodex suite:

```powershell
.\node_modules\bun\bin\bun.exe run test:cocodex -- --max-concurrency=1
```

Exit status: `0`

```text
110 pass
0 fail
967 expect() calls
Ran 110 tests across 30 files.
```

The included three-process test launched the separate server, Stephen client,
and Kai client and passed with `241` assertions.

Isolated package verification:

```powershell
.\node_modules\bun\bin\bun.exe pm pack `
  --destination .\tmp\client-package-check-20260726-v2

pnpm install
.\node_modules\.bin\cocodex.CMD --help
.\node_modules\.bin\ccx.CMD --help
```

The package install used a fresh consumer directory with its own dependency
tree. Both package-manager-generated `.CMD` shims exited `0` and
printed the CoCodex Client help. Before the consumer explicitly approved Bun's
lifecycle build, the same shim exited `1` with the documented fail-closed
message; the launcher did not invoke an installer itself.

Tar inspection showed `bin/ccx.mjs` with executable mode, included the complete
client and protocol source needed by the package-relative imports, and found no
nested `node_modules` or workspace tests. The root tarball manifest contains no
`workspace:*` dependency.

Additional gates:

```text
typecheck                 exit 0
typecheck:cocodex         exit 0
build:cocodex-server      exit 0
privacy:scan              exit 0
lint:gui                  exit 0 (one pre-existing hook warning)
git diff --check          exit 0
```

The first combined CoCodex run exposed the 501-event WSS pagination test taking
`6089ms` under Bun's implicit `5000ms` timeout. The test already performs a real
WSS workload and was given an explicit `15000ms` budget. Its focused rerun
passed all `5` collaboration tests with `99` assertions; the subsequent full
run produced the clean `110/0` result above.

## Files involved

- `bin/ccx.mjs`
- `package.json`
- `src/cocodex/cli.ts`
- `tests/install-scripts.test.ts`
- `docs/cocodex-client.md`
- `docs/adr/0028-cocodex-client-command-distribution.md`
- `apps/cocodex-server/tests/collaboration-server.test.ts`
