# ADR 0033: Explicit Local OpenCodex Import Flow

## Status

Accepted for the private-alpha client foundation.

## Context

CoCodex must preserve an existing OpenCodex installation while making local
provider configuration, catalog caches, and usage history available to the
new Client. Copying the entire OpenCodex home would duplicate credentials,
runtime locks, and private keys, and it would make it too easy to accidentally
send local provider secrets through the collaboration server.

## Decision

`cocodex import-opencodex` is a client-only preview/apply/list/status/rollback
flow. It scans an explicit allowlist of regular files in `OPENCODEX_HOME`,
reports a metadata-only plan, and applies a new staged copy beneath a separate
CoCodex-local target (by default `COCODEX_HOME/opencodex`). Every source read is
bounded and identity-checked; the apply operation validates and refreshes the
plan so callers cannot forge paths or bypass the allowlist.

The allowlist contains provider `config.json`, Codex `config.toml` and
`opencodex.config.toml`, recognized catalog JSON files, and non-sensitive usage
JSONL/JSON. Diagnostic/request logs are always excluded. JSON/TOML configuration
is structurally scrubbed for private-key, token, certificate, authorization,
password/passphrase, access-key, vendor-header, and nested secret fields, including PEM/Bearer strings in JSON arrays. Bare TOML
dotted keys are scrubbed by their final segment; quoted-key, inline-table, and
multiline-array forms that cannot be proven safe are rejected. Explicit provider
`apiKey`/`apiKeyPool` values survive only with `--include-secrets`.
Authentication and account stores are always excluded.
API-key fields outside provider objects or tables are scrubbed even with --include-secrets.
Runtime state, locks, sockets, symlinks, and unknown files are excluded as well.
The resulting files remain Client-local; no importer code or protocol frame sends
them to the CoCodex Server.

Apply stages into temporary directories, records a prepared journal, and then
atomically moves files into the destination. Journal and directory metadata are
fsynced where the platform supports it. The destination directory is ACL-hardened
before the first sensitive rename, with a forced reapplication path for reused
mutable names. Existing destination files are retained beneath a timestamped
`.cocodex-import-backups` directory with strict ACL checks and recorded hashes.
The journal phase and file-integrity schema are validated before rollback; imported
and collision-backup hashes are rechecked immediately before mutation. Rollback
binds both target roots, rejects target/backup-root overlap, refuses
edited/ambiguous destinations, and leaves
prepared staging roots for explicit manual cleanup instead of recursively deleting
manifest-supplied paths. The original OpenCodex directory is never changed.

## Alternatives considered

- **Merge into `~/.opencodex`:** rejected because it overwrites user state and
  makes rollback and secret ownership ambiguous. The default target is a
  separate CoCodex-local directory.
- **Copy the whole home directory:** rejected because authentication, private
  keys, locks, and arbitrary files do not belong in CoCodex collaboration
  state.
- **Upload imported files to CoCodex Server:** rejected because provider
  credentials and local usage history must remain client-local.
- **Silent startup migration:** rejected because the required preview,
  explicit consent, reversible apply, and failure evidence would be lost.

## Security and license notes

This is an independent filesystem implementation using the repository's
existing MIT-compatible code and Node/Bun standard-library APIs. It does not
copy code from OpenCodex or any other external project. The local bundle is
permission-hardened where the platform supports it, and CLI output contains
hashes and metadata rather than provider secret values.
