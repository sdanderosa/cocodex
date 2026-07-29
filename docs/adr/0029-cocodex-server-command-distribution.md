# ADR 0029: CoCodex Server command distribution

- Status: Accepted
- Date: 2026-07-26

## Context

CoCodex Server already builds and runs as a separate headless process, but its
`cocodex-server` and `ccx-server` bin declarations existed only in a private
workspace package. Installing the publishable root artifact therefore exposed
the Client and inherited proxy commands without creating either documented
Server command.

## Decision

Publish `cocodex-server` and `ccx-server` as root bin names pointing to
`bin/ccx-server.mjs`. The Node 18+ launcher resolves the pinned installed Bun
dependency and invokes only `apps/cocodex-server/src/cli.ts`.

The Server launcher has the same runtime security boundary as the Client
launcher:

- no PATH search, automatic installer, or first-launch network download;
- reject Bun placeholder files by minimum binary size;
- inherit argv and stdio without a shell;
- forward termination signals with a five-second forced-termination bound; and
- propagate the child exit status.

The root package already includes the Server source, protocol source, and
runtime dependencies through package-relative imports. The Server workspace
package remains private and useful for monorepo development; it is not a
runtime dependency of the installed root artifact.

## Security and application separation

The launcher contains no administration token, state path, network endpoint,
or firewall privilege. It cannot invoke CoCodex Client, local Codex execution,
or the inherited OpenCodex proxy. Server administration continues through the
headless CLI and the separate `%USERPROFILE%\.cocodex-server` state root.

`cocodex`, `ccx`, `cocodex-server`, `ccx-server`, `opencodex`, and `ocx`
remain distinct commands with explicit application ownership.

## Verification

The install-script suite checks all six bin mappings, launcher invariants, and
a real Node-to-Bun Server `--help` process. Tarball verification must include
both Server command shims and executable launcher mode.
