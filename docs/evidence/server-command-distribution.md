# CoCodex Server command-distribution evidence

- Date: 2026-07-26
- Branch: `feat/cocodex-foundation`
- Implementation commit: `02a9fa0b4c702baa0895f11a316e7f0212b6771e`
- Status: separate installed Server commands and private-alpha gates pass

## Behavior proved

The root package publishes two Server-specific commands:

| Command | Launcher | Application |
| --- | --- | --- |
| `cocodex-server` | `bin/ccx-server.mjs` | headless CoCodex Server |
| `ccx-server` | `bin/ccx-server.mjs` | headless CoCodex Server |

The launcher invokes only `apps/cocodex-server/src/cli.ts`. The installed
Client commands remain mapped to `bin/ccx.mjs`, and the inherited proxy
commands remain mapped to `bin/ocx.mjs`.

## Clean package installation

The root artifact was packed, installed into a fresh consumer dependency tree,
and both generated Server shims were invoked:

```powershell
.\node_modules\bun\bin\bun.exe pm pack `
  --destination .\.tmp\server-package-check-v2

bun add ..\bitkyc08-opencodex-2.7.35.tgz
.\node_modules\.bin\cocodex-server.exe --help
.\node_modules\.bin\ccx-server.exe --help
```

Both shim commands exited `0` and printed:

```text
CoCodex Server
Usage:
  cocodex-server init --public-host HOST [--port PORT] [--state-root PATH]
...
Short alias: ccx-server
```

The clean install created all six expected command shims and installed `125`
packages. Tar inspection recorded `bin/ccx-server.mjs` with executable mode and
found no nested `node_modules` or workspace tests.

The first isolated install was intentionally treated as a failed gate: both
Server shims exited `1` because `selfsigned` existed only in the private Server
workspace manifest. The exact pinned `selfsigned@5.5.0` dependency was promoted
to the publishable root manifest and lockfile. A newly packed and newly
installed artifact then produced the two clean exits above.

## Commands and results

Focused install/distribution test:

```powershell
$env:OCX_TEST_NODE_EXE='C:\Users\Stephen\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
.\node_modules\bun\bin\bun.exe test --isolate `
  .\tests\install-scripts.test.ts --timeout 60000
```

Exit status: `0`

```text
9 pass
0 fail
74 expect() calls
```

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

The included three-process test launched a separate Server, Stephen Client, and
Kai Client and passed with `241` assertions.

Additional gates:

```text
typecheck                 exit 0
typecheck:cocodex         exit 0
build:cocodex-client      exit 0 (136 modules)
build:cocodex-server      exit 0 (353 modules)
privacy:scan              exit 0
lint:gui                  exit 0 (one pre-existing hook warning)
git diff --check          exit 0
```

An independent security review found no code or release blocker after staging.
It verified application separation, fail-closed runtime behavior, package
dependency closure, source inclusion, executable preparation, and the absence
of an automatic installer or first-launch download.

## Files involved

- `bin/ccx-server.mjs`
- `package.json`
- `bun.lock`
- `scripts/prepare-package.ts`
- `apps/cocodex-server/src/cli.ts`
- `tests/install-scripts.test.ts`
- `docs/cocodex-server.md`
- `docs/adr/0029-cocodex-server-command-distribution.md`
