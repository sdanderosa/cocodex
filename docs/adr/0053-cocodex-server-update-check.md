# ADR 0053: Verified standalone Server update-check UX

- **Status:** Accepted
- **Date:** 2026-07-28
- **Scope:** CoCodex Server release validation and operator update readiness

## Context

The product brief requires the standalone Server to have its own update flow.
ADR 0048 deliberately distributes Client and Server application files in one
verified private-alpha bundle while preserving their independent state roots.
The inherited OpenCodex registry updater cannot update CoCodex safely, and a
running Server executable must not replace itself or silently stop unrelated
Client, proxy, or Windows-service processes.

Operators need a Server-facing workflow that proves a downloaded bundle and
explains exactly what must stop before mutation, without creating a second
package trust mechanism or executing a shell command assembled from user text.

## Decision

Add `cocodex-server update-check --bundle DIRECTORY`. It is read-only and
available only from the installed
`<prefix>/node_modules/@sdanderosa/cocodex` package layout on Windows.

The command independently requires ordinary non-linked bundle files, parses a
bounded release manifest and checksum list, and verifies SHA-256 for the
archive, release manifest, and installer. It binds the CoCodex package identity,
target version, source commit, archive digest, Node requirement, and npm
requirement. It then invokes the bundle's checksum-covered
`Install-CoCodex.ps1 -Action Check` through an exact executable and argv,
without a shell. The installer reuses its existing bounded tar, package,
shrinkwrap, Node, and npm validation and exits before writing the install-root
manifest or invoking npm.

The result reports current/target versions, source commit, archive digest,
application prefix, selected Server state root, direct Server PID, optional
Windows-service state, blockers, and exact argv for the supported external
`Update` action. It labels honestly that ADR 0048 updates shared application
files while preserving all four independent state roots.

The Server command does not execute the update. The operator must stop the
direct Server or optional service and any other CoCodex processes, then run the
reported external installer command. This keeps process quiescence and file
replacement inside the already verified installer. After update, service-mode
operators repair/start the service from the same state root and verify
`sameUser`, `automaticStart`, `binaryPathMatches`, and TLS readiness.

## Security consequences

A checksum file packaged beside an archive is integrity evidence, not an
independent publisher signature. The operator must still obtain the complete
bundle from the intended successful workflow/commit. The command rejects
redirected directories, links, path traversal, duplicate or malformed checksum
rows, oversized files, missing coverage, digest mismatch, wrong package
identity, inconsistent installer output, source checkouts, unknown SCM state,
and non-Windows execution.

The command never queries a registry, downloads code, invokes `cmd.exe`,
changes PATH, stops a process, writes Server state, or touches port 10100.
Bundle application remains an explicit operator action.

## Evidence requirement

Tests must prove every input digest, archive/manifest/installer tamper
rejection, wrong identity and traversal rejection, exact installed-prefix
ownership, source-checkout rejection, running PID/service blockers, unknown SCM
fail closure, shell-free argv, state-root preservation disclosure, and
side-effect-free CLI help. A clean-commit release gate must run `Check`, apply
`Update` to an isolated installed prefix with stopped processes, verify the
installed Client/Server launchers and Server lifecycle, and prove all state
canaries survive.
