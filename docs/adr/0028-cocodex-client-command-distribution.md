# ADR 0028: CoCodex Client command distribution

- Status: Accepted
- Date: 2026-07-26

## Context

The repository built `src/cocodex/cli.ts` into a standalone client executable,
but the published root package exposed only the inherited `opencodex` and `ocx`
commands. A normal npm installation therefore could not provide the required
`cocodex` command or its `ccx` short alias.

The inherited package already solves the cross-platform runtime problem with a
Node launcher and the maintained `bun` package dependency. CoCodex must reuse
that distribution boundary without routing collaboration commands through the
OpenCodex proxy CLI or requiring a separately installed Bun executable.

## Decision

Publish `cocodex` and `ccx` as two npm bin names pointing to
`bin/ccx.mjs`. The launcher:

- runs under the package's Node 18+ requirement;
- resolves the installed `bun` dependency by package identity;
- rejects the Bun placeholder stub with the same minimum-size boundary as the
  inherited launcher;
- invokes only `src/cocodex/cli.ts`;
- forwards termination signals, applies a five-second forced-termination bound,
  and propagates the child exit status; and
- fails closed if npm installation policy skipped Bun's lifecycle script or
  optional platform package.

Production CoCodex imports the protocol through package-relative source paths.
The root artifact therefore has no `workspace:*` runtime dependency: a clean
tarball contains both the client and protocol source required by the launcher.

Keep `opencodex` and `ocx` mapped to `bin/ocx.mjs`. They remain compatibility
commands for the inherited proxy and do not become aliases for collaboration
state or remote execution.

The compiled development/release artifact remains `dist/cocodex-client`; the
public installed command is `cocodex`, with `ccx` as its short alias.

## Security and compatibility

The launcher accepts no server address, credential, project state, or execution
request itself. It only transfers argv and inherited stdio to the local CoCodex
Client entrypoint. Device keys and provider credentials remain inside the
client-owned state boundary.

The launcher does not search `PATH` for Bun, invoke `bun/install.js`, or download
a runtime URL. Runtime selection is constrained to the installed `bun` package;
its lifecycle script and optional platform package are governed by npm install
policy. A missing or placeholder runtime produces reinstall instructions and a
nonzero exit.

## Alternatives rejected

- Pointing `cocodex` at `bin/ocx.mjs` would start the wrong application.
- Requiring `bun` on `PATH` would contradict the existing npm installation
  contract.
- Renaming or removing `ocx` would break inherited OpenCodex compatibility.
- Copying the complete OpenCodex update launcher would couple the collaboration
  client to proxy service/update behavior it does not own.

## Verification

`tests/install-scripts.test.ts` verifies the four bin mappings, the dedicated
entrypoint, fail-closed runtime resolution, bounded termination, and a real
Node-to-Bun `--help` launch. Package verification additionally creates and
inspects a tarball, installs it in an isolated directory, and runs both
package-manager-generated command shims. The CoCodex suite continues to run the
compiled client and separate server processes.
