# ADR 0048: Verified Windows private-alpha distribution

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** CoCodex Client and Server installation, update ownership, Windows
  package verification, and GitHub artifact delivery

## Context

The private-alpha network path can run as separate compiled Client and Server
applications, but sending a source checkout or a collection of loose
executables to another person is not an operational installation flow. The
OpenCodex foundation also owns an npm self-update command. Allowing that
upstream command to update a CoCodex installation would replace the fork with
`@bitkyc08/opencodex` and could silently remove the Server and collaboration
features.

CoCodex needs one recoverable Windows bundle that installs both public
applications while preserving four independently owned state roots:

- CoCodex Client: `~/.cocodex`;
- CoCodex Server: `~/.cocodex-server`;
- inherited OpenCodex local runtime: `~/.opencodex`;
- official Codex: `~/.codex`.

The private alpha is not yet an npm publication or a signed Windows installer.
The repository and GitHub Actions run are the trusted delivery boundary.

## Decision

Build a private package named `@sdanderosa/cocodex` from an explicit,
symlink-free source allowlist. The package contains the OpenCodex-based Client,
the separate headless Server, their launchers, the built GUI, protocol source,
licenses, and notices. It retains the inherited, pinned `bun` package
dependency so a standard npm install prepares the platform runtime during
installation rather than downloading executable code on first launch.
Every direct runtime dependency is rewritten to the exact version in
`bun.lock`. A committed npm shrinkwrap then pins every transitive package and
registry SHA-512 integrity. Every shipped dependency name/version/integrity
must also exist identically in `bun.lock`, and install-time lifecycle execution
is rejected for every package except the pinned Bun runtime. The archive
checksum therefore covers the complete
dependency resolution contract even though npm fetches those integrity-checked
package bytes during installation.

Distribute four files together:

- `sdanderosa-cocodex-<version>.tgz`;
- `SHA256SUMS.txt`;
- `RELEASE.json`;
- `Install-CoCodex.ps1`.

The release manifest binds the package name, version, archive digest, source
commit/tree, generated-GUI digest, shrinkwrap digest, required commands, build
time, minimum Node/npm requirement, and preserved state roots. The builder
refuses a dirty or untracked worktree, verifies `GITHUB_SHA` against `HEAD`,
builds the GUI itself, then repeats the clean commit/tree proof immediately
before copying release inputs. It rejects symbolic-link inputs, output paths
outside its release directory, archives larger than 512 MiB, and pre-existing
output directories.

The Windows PowerShell 5.1 installer:

1. resolves exactly one regular archive, checksum, and release-manifest file;
2. rejects directories and reparse points;
3. verifies the archive, manifest, and running installer against the checksum
   list before resolving npm or invoking an installation command;
4. parses the bounded tar stream without extraction and requires the exact
   package name/version, empty package lifecycle scripts, and shrinkwrap digest;
5. requires Node.js 22.12 or newer and npm 10 or newer;
6. installs into npm's user-selected or configured global prefix;
7. re-verifies the installed package identity/version and shrinkwrap;
8. verifies `cocodex`, `ccx`, `cocodex-server`, `ccx-server`, and `ocx`;
9. runs Client help, Server help, and inherited-runtime version smokes;
10. adds only the command prefix to the user's PATH when requested.

`Update` first proves no process is executing from the CoCodex package prefix,
then installs another verified local archive through the same path.
`Uninstall` removes only `@sdanderosa/cocodex`; it does not delete any Client,
Server, OpenCodex, or Codex state directory. The installer contains no
recursive deletion operation.

The inherited registry updater is disabled whenever installed package metadata
does not identify `@bitkyc08/opencodex`. A CoCodex installation directs the
operator back to a newer verified `Install-CoCodex.ps1` bundle before it makes
a registry query or package mutation.

Pull requests run the Windows build/install gates but cannot publish a
distributable artifact. Only an explicit maintainer `workflow_dispatch` with a
matching full expected commit SHA uploads the four-file release directory.
That job runs on both the minimum Node 22.12/npm 10 combination and current
Node 24. It runs CoCodex and inherited OpenCodex tests, GUI lint/tests/builds,
privacy scanning, standard-npm installation, exact installed dependency-tree
validation, installed GUI/local-runtime health, and installed Server
init/start/TLS-health/restart/stop/status. All third-party Actions are pinned
by full commit SHA, checkout credentials are not persisted, and the workflow
has read-only repository permission.

## Why not a single portable executable?

The Client and Server are distinct applications but share the maintained
OpenCodex TypeScript runtime and dependency graph. Two opaque self-extracting
executables would duplicate a large runtime, complicate notices and updates,
and still need an installer for command discovery and state preservation.
The npm archive is inspectable, deterministic in contents, and exercises the
same launchers used by development and CI.

The compiled `dist/cocodex-client.exe` and `dist/cocodex-server.exe` remain
useful build artifacts and process-boundary tests. The private-alpha installer
is the supported way to give an ordinary Windows user the complete Client,
Server, GUI, and compatibility commands together.

## Security and recovery consequences

SHA-256 detects corruption or modification only when the checksum and archive
come from the same trusted GitHub artifact. It is not a substitute for
Authenticode, Sigstore, or an independently published transparency record.
An attacker able to replace both local files can replace the installer too.
Kai and Stephen must download the complete bundle from the repository's
successful workflow run and compare its source commit with the intended
CoCodex commit.

npm lifecycle scripts and optional dependencies must remain enabled so the
integrity-locked Bun runtime can be prepared during installation. CoCodex
launchers fail closed when it is missing; they do not repair or download it at
first run.

An interrupted package update can be retried with the same verified archive
after all CoCodex processes are stopped.
Because application files live under the npm prefix and mutable state lives
outside it, reinstall and uninstall do not consume or migrate live identities,
Server authority, provider credentials, or official Codex state. Application
rollback means reinstalling an older trusted CoCodex archive; state-schema
rollback is not automatic and still requires the Server's protected backup
and restore procedures.

Windows code signing, an MSI/MSIX user installer, automatic update
notifications, optional Windows Service installation, and a public release
channel remain later requirements.

## Evidence requirement

Tests must prove archive branding and contents, dependency preservation,
checksum-before-install ordering, modified-archive rejection, and the upstream
registry update gate. Release validation must additionally install the exact
archive with standard npm, run every command smoke, serve the inherited local
GUI and health endpoint from isolated state, and run the installed Server
through init, detached start, TLS health, health-verified restart with a new
PID, stop, and stopped status.
