import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, resolve, sep } from "node:path";
import { expandUserPath } from "../config";
import { resolveCodexHomeDir } from "../codex/home";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";
import { defaultClientStateRoot } from "./paths";

export type ImportScope = "opencodex" | "codex";

export interface OpenCodexImportOptions {
  sourceOpenCodexHome: string;
  targetOpenCodexHome?: string;
  sourceCodexHome?: string;
  targetCodexHome?: string;
  includeSecrets?: boolean;
}

export interface OpenCodexImportFile {
  scope: ImportScope;
  relativePath: string;
  sourcePath: string;
  destinationPath: string;
  sensitive: boolean;
  status: "available" | "missing" | "excluded" | "collision";
  sizeBytes?: number;
  sourceSha256?: string;
  sourceMtimeMs?: number;
}

export interface OpenCodexImportPlan {
  version: 1;
  sourceOpenCodexHome: string;
  targetOpenCodexHome: string;
  sourceCodexHome: string | null;
  targetCodexHome: string | null;
  includeSecrets: boolean;
  files: OpenCodexImportFile[];
}

export interface OpenCodexImportResult {
  version: 1;
  imported: Array<Pick<OpenCodexImportFile, "scope" | "relativePath" | "sensitive" | "sizeBytes" | "sourceSha256">>;
  backupDirectory: string;
}

export interface OpenCodexImportBackup {
  backupDirectory: string;
  createdAt: string;
  fileCount: number;
  state?: "prepared" | "committed" | "rolled-back";
  rolledBackAt?: string;
}

export interface OpenCodexRollbackResult {
  rolledBack: true;
  backupDirectory: string;
  restored: number;
  removed: number;
}

type ImportEntry = {
  scope: ImportScope;
  relativePath: string;
  sensitive: boolean;
  alwaysExcluded?: boolean;
};

/** Maximum source size hashed/read by one import operation. */
export const MAX_IMPORT_FILE_BYTES = 16 * 1024 * 1024;

/**
 * Compatibility imports use an allowlist. Authentication, refresh grants,
 * runtime locks, pid files, sockets, private keys, symlinks, logs containing
 * request credentials, and unknown files never enter the CoCodex-local bundle.
 */
export const OPEN_CODEX_IMPORT_FILES: readonly ImportEntry[] = [
  { scope: "opencodex", relativePath: "config.json", sensitive: true },
  { scope: "opencodex", relativePath: "auth.json", sensitive: true, alwaysExcluded: true },
  { scope: "opencodex", relativePath: "codex-accounts.json", sensitive: true, alwaysExcluded: true },
  { scope: "opencodex", relativePath: "opencodex-catalog.json", sensitive: false },
  { scope: "opencodex", relativePath: "models_cache.json", sensitive: false },
  { scope: "opencodex", relativePath: "usage.jsonl", sensitive: false },
  { scope: "opencodex", relativePath: "usage.json", sensitive: false },
  { scope: "opencodex", relativePath: "usage-debug.jsonl", sensitive: true, alwaysExcluded: true },
  { scope: "opencodex", relativePath: "usage-debug.json", sensitive: true, alwaysExcluded: true },
  { scope: "opencodex", relativePath: "request-log.jsonl", sensitive: true, alwaysExcluded: true },
  { scope: "opencodex", relativePath: "logs.jsonl", sensitive: true, alwaysExcluded: true },
  { scope: "codex", relativePath: "config.toml", sensitive: true },
  { scope: "codex", relativePath: "opencodex.config.toml", sensitive: true },
  { scope: "codex", relativePath: "opencodex-catalog.json", sensitive: false },
  { scope: "codex", relativePath: "models_cache.json", sensitive: false },
  { scope: "codex", relativePath: "auth.json", sensitive: true, alwaysExcluded: true },
];

export class OpenCodexImportError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OpenCodexImportError";
  }
}

function canonicalRoot(path: string, label: string): string {
  const trimmed = path.trim();
  if (!trimmed) throw new OpenCodexImportError(`${label} must be a non-empty path`);
  const requested = resolve(expandUserPath(trimmed));
  if (safeLstat(requested)?.isSymbolicLink()) {
    throw new OpenCodexImportError(`${label} must not be a symbolic link`);
  }
  return physicalPath(requested, label);
}

function defaultTargetOpenCodexHome(): string {
  return resolve(defaultClientStateRoot(), "opencodex");
}

function defaultTargetCodexHome(): string {
  return resolve(defaultClientStateRoot(), "codex");
}

function comparablePath(path: string): string {
  const normalized = resolve(path).replace(/[\\/]+$/, "");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isPathWithin(parent: string, candidate: string): boolean {
  const normalizedParent = comparablePath(parent);
  const normalizedCandidate = comparablePath(candidate);
  const prefix = normalizedParent.endsWith(sep) ? normalizedParent : `${normalizedParent}${sep}`;
  return normalizedCandidate.startsWith(prefix);
}

function safeLstat(path: string): ReturnType<typeof lstatSync> | null {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && (error as { code?: string }).code === "ENOENT") return null;
    throw error;
  }
}

/** Reject symlink/junction ancestors, including broken symlinks. */
function assertNoSymlinkAncestors(path: string, label: string): void {
  let current = resolve(path);
  for (;;) {
    const stat = safeLstat(current);
    if (stat?.isSymbolicLink()) throw new OpenCodexImportError(`${label} contains a symbolic-link ancestor`);
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function assertDirectory(path: string, label: string, allowMissing: boolean): void {
  assertNoSymlinkAncestors(path, label);
  const stat = safeLstat(path);
  if (!stat) {
    if (allowMissing) return;
    throw new OpenCodexImportError(`${label} does not exist`);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new OpenCodexImportError(`${label} must be a real directory`);
}

function physicalPath(path: string, label = "OpenCodex import path"): string {
  let current = resolve(path);
  const suffix: string[] = [];
  for (;;) {
    const stat = safeLstat(current);
    if (stat) {
      try {
        return resolve(realpathSync.native(current), ...suffix);
      } catch {
        throw new OpenCodexImportError(`${label} could not be resolved safely`);
      }
    }
    const parent = dirname(current);
    if (parent === current) return resolve(path);
    suffix.unshift(basename(current));
    current = parent;
  }
}

function assertRootsDisjoint(a: string, b: string, label: string): void {
  if (comparablePath(a) === comparablePath(b) || isPathWithin(a, b) || isPathWithin(b, a)) {
    throw new OpenCodexImportError(`${label} paths must not contain one another`);
  }
  const physicalA = physicalPath(a);
  const physicalB = physicalPath(b);
  if (comparablePath(physicalA) === comparablePath(physicalB) || isPathWithin(physicalA, physicalB) || isPathWithin(physicalB, physicalA)) {
    throw new OpenCodexImportError(`${label} paths must not alias one another`);
  }
}

function assertAllRootsDisjoint(roots: Array<[string, string]>): void {
  for (let i = 0; i < roots.length; i += 1) {
    for (let j = i + 1; j < roots.length; j += 1) {
      assertRootsDisjoint(roots[i]![0], roots[j]![0], `${roots[i]![1]} and ${roots[j]![1]}`);
    }
  }
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

type StableFile = { bytes: Uint8Array; size: number; mtimeMs: number; sha256: string };

function sameFileIdentity(a: { size: number | bigint; mtimeMs: number | bigint; dev?: number | bigint; ino?: number | bigint }, b: { size: number | bigint; mtimeMs: number | bigint; dev?: number | bigint; ino?: number | bigint }): boolean {
  const identityMatches = !a.dev || !b.dev || !a.ino || !b.ino || (a.dev === b.dev && a.ino === b.ino);
  return identityMatches && String(a.size) === String(b.size) && String(a.mtimeMs) === String(b.mtimeMs);
}

/** Read through one file descriptor and verify it did not change while read. */
function readStableFile(path: string, label: string): StableFile {
  const before = safeLstat(path);
  if (!before || !before.isFile() || before.isSymbolicLink()) {
    throw new OpenCodexImportError(`OpenCodex import refuses non-regular or symbolic-link source ${label}`);
  }
  const beforeSize = Number(before.size);
  if (beforeSize > MAX_IMPORT_FILE_BYTES) throw new OpenCodexImportError(`OpenCodex import source exceeds ${MAX_IMPORT_FILE_BYTES} bytes: ${label}`);
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const opened = fstatSync(fd);
    if (!opened.isFile() || !sameFileIdentity(before, opened)) throw new OpenCodexImportError(`Source changed while reading ${label}`);
    const openedSize = Number(opened.size);
    if (!Number.isSafeInteger(openedSize) || openedSize > MAX_IMPORT_FILE_BYTES) throw new OpenCodexImportError(`OpenCodex import source exceeds ${MAX_IMPORT_FILE_BYTES} bytes: ${label}`);
    const chunks: Buffer[] = [];
    let remaining = openedSize;
    while (remaining > 0) {
      const chunk = Buffer.alloc(Math.min(64 * 1024, remaining));
      const count = readSync(fd, chunk, 0, chunk.length, null);
      if (count <= 0) throw new OpenCodexImportError(`Source ended while reading ${label}`);
      chunks.push(count === chunk.length ? chunk : chunk.subarray(0, count));
      remaining -= count;
    }
    const after = fstatSync(fd);
    const pathAfter = safeLstat(path);
    if (!pathAfter || !sameFileIdentity(opened, after) || !sameFileIdentity(after, pathAfter)) {
      throw new OpenCodexImportError(`Source changed while reading ${label}`);
    }
    const bytes = Buffer.concat(chunks, opened.size);
    return { bytes, size: opened.size, mtimeMs: opened.mtimeMs, sha256: sha256(bytes) };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function sourceMetadata(path: string, label: string): Omit<StableFile, "bytes"> {
  const { bytes: _bytes, ...metadata } = readStableFile(path, label);
  return metadata;
}

function publicEntry(entry: ImportEntry): Pick<OpenCodexImportFile, "scope" | "relativePath" | "sensitive"> {
  return { scope: entry.scope, relativePath: entry.relativePath, sensitive: entry.sensitive };
}

const SECRET_FIELD_NAMES = new Set([
  "privatekey", "privatekeypem", "privatepem", "sshkey", "sshprivatekey", "signingkey", "secretkey", "secret", "key",
  "refreshtoken", "accesstoken", "idtoken", "authtoken", "sessiontoken", "clientsecret", "bearer", "token", "tokens",
  "authorization", "proxyauthorization", "cookie", "setcookie", "xauthtoken", "xapikey", "accesskey", "pem", "certificate", "password", "passphrase", "passwd",
  "clientcertificate", "credential", "credentials", "private", "ssh", "jwt", "oauth",
]);

function normalizedFieldName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function shouldScrubField(name: string, allowGenericKey = false, allowApiKey = false): boolean {
  const normalized = normalizedFieldName(name);
  if ((normalized === "apikey" || normalized === "apikeypool") && allowApiKey) return false;
  if (normalized === "apikey" || normalized === "apikeypool") return true;
  if (normalized === "key" && allowGenericKey) return false;
  return SECRET_FIELD_NAMES.has(normalized)
    || /^(?:private|ssh|signing|client|server)(?:key|certificate|pem)$/.test(normalized)
    || /^(?:api|oauth|bearer|csrf|refresh|access|auth|session|id|device|account)(?:token|credential)$/.test(normalized)
    || /(?:authorization|proxyauthorization|cookie|secret)$/.test(normalized)
    || /(?:cert|certificate|pem|password|passphrase|passwd)$/.test(normalized)
    || /^x[a-z0-9]*(?:apikey|securitytoken)$/.test(normalized);
}

function containsSensitiveValue(value: unknown): boolean {
  return typeof value === "string" && (/-----BEGIN[^\n]*PRIVATE KEY-----/i.test(value) || /\bBearer\s+[A-Za-z0-9._~+/=-]+/i.test(value));
}

function scrubProviderConfig(bytes: Uint8Array): Uint8Array {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw new OpenCodexImportError("OpenCodex config.json is not valid JSON; refusing to import it");
  }
  let changed = false;
  const scrub = (value: unknown, depth: number, allowGenericKey = false, allowApiKey = false, insideHeaders = false, insideProvider = false): unknown => {
    if (depth > 32) throw new OpenCodexImportError("OpenCodex config.json nesting is too deep; refusing to import it");
    if (Array.isArray(value)) {
      const sanitizedItems: unknown[] = [];
      for (const item of value) {
        if (containsSensitiveValue(item)) {
          changed = true;
          continue;
        }
        sanitizedItems.push(scrub(item, depth + 1, allowGenericKey, allowApiKey, insideHeaders, insideProvider));
      }
      return sanitizedItems;
    }
    if (!value || typeof value !== "object") return value;
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      const normalizedKey = normalizedFieldName(key);
      const childInsideProvider = insideProvider || normalizedKey === "providers" || normalizedKey === "provider";
      const childAllowsGenericKey = normalizedKey === "apikeypool" && insideProvider;
      const childInsideHeaders = insideHeaders || normalizedKey === "headers";
      const childAllowsApiKey = childInsideProvider && !childInsideHeaders;
      if (shouldScrubField(key, allowGenericKey, allowApiKey) || containsSensitiveValue(child)) {
        changed = true;
        continue;
      }
      output[key] = scrub(child, depth + 1, childAllowsGenericKey, childAllowsApiKey, childInsideHeaders, childInsideProvider);
    }
    return output;
  };
  const sanitized = scrub(parsed, 0, false, false, false, false);
  return changed ? Buffer.from(`${JSON.stringify(sanitized, null, 2)}\n`, "utf8") : bytes;
}

function scrubProviderToml(bytes: Uint8Array): Uint8Array {
  const text = Buffer.from(bytes).toString("utf8");
  if (/[{}]/.test(text) || /\x27\x27\x27|\"\"\"/.test(text) || /^\s*["\x27].*["\x27]\s*=/m.test(text)) {
    throw new OpenCodexImportError("Codex TOML uses unsupported composite, multiline, or quoted-key syntax; refusing to import it");
  }
  const output: string[] = [];
  let providerTable = false;
  let changed = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*\[\[/.test(line)) throw new OpenCodexImportError("Codex TOML uses unsupported array-table syntax; refusing to import it");
    const table = line.match(/^\s*\[([^\[\]]+)\]\s*$/);
    if (table) {
      if (/["\x27]/.test(table[1]!)) throw new OpenCodexImportError("Codex TOML uses unsupported quoted table syntax; refusing to import it");
      providerTable = table[1]!.split(".").map(part => normalizedFieldName(part.trim())).some(part => part === "provider" || part === "providers");
      output.push(line);
      continue;
    }
    const assignment = line.match(/^\s*(.*?)\s*=/);
    const rawKey = assignment?.[1]?.trim();
    if (rawKey && /["\x27]/.test(rawKey)) {
      throw new OpenCodexImportError("Codex TOML uses unsupported composite, multiline, or quoted-key syntax; refusing to import it");
    }
    const valueStart = assignment ? line.indexOf("=", assignment.index ?? 0) + 1 : -1;
    const rawValue = valueStart >= 0 ? line.slice(valueStart).trim() : "";
    if (assignment && rawValue.includes("[") && !rawValue.includes("]")) {
      throw new OpenCodexImportError("Codex TOML uses unsupported composite, multiline, or quoted-key syntax; refusing to import it");
    }
    const keySegments = rawKey?.split(".").map(part => part.trim()).filter(Boolean) ?? [];
    const key = keySegments.at(-1);
    const providerScoped = providerTable || keySegments.some(part => part === "provider" || part === "providers");
    if (key && shouldScrubField(key, false, providerScoped)) {
      changed = true;
      continue;
    }
    if (containsSensitiveValue(line)) {
      changed = true;
      output.push("# CoCodex redacted sensitive value");
      continue;
    }
    output.push(line);
  }
  if (!changed) return bytes;
  const trailingNewline = text.endsWith("\n") ? "\n" : "";
  const sanitized = output.join("\n").replace(/\n+$/, "") + trailingNewline;
  return Buffer.from(sanitized, "utf8");
}
function describeFile(entry: ImportEntry, sourceRoot: string, destinationRoot: string, includeSecrets: boolean): OpenCodexImportFile {
  const sourcePath = resolve(sourceRoot, entry.relativePath);
  const destinationPath = resolve(destinationRoot, entry.relativePath);
  const base = publicEntry(entry);
  assertNoSymlinkAncestors(dirname(sourcePath), `OpenCodex import source ${entry.relativePath}`);
  assertNoSymlinkAncestors(dirname(destinationPath), `OpenCodex import destination ${entry.relativePath}`);
  if (entry.alwaysExcluded || (entry.sensitive && !includeSecrets)) return { ...base, sourcePath, destinationPath, status: "excluded" };
  const sourceStat = safeLstat(sourcePath);
  if (!sourceStat) return { ...base, sourcePath, destinationPath, status: "missing" };
  const metadata = sourceMetadata(sourcePath, `${entry.scope}/${entry.relativePath}`);
  const destinationStat = safeLstat(destinationPath);
  if (destinationStat && (!destinationStat.isFile() || destinationStat.isSymbolicLink())) {
    throw new OpenCodexImportError(`OpenCodex import refuses non-regular or symbolic-link destination ${entry.scope}/${entry.relativePath}`);
  }
  return {
    ...base,
    sourcePath,
    destinationPath,
    status: destinationStat ? "collision" : "available",
    sizeBytes: metadata.size,
    sourceSha256: metadata.sha256,
    sourceMtimeMs: metadata.mtimeMs,
  };
}

function createPlanUnchecked(options: OpenCodexImportOptions): OpenCodexImportPlan {
  const sourceOpenCodexHome = canonicalRoot(options.sourceOpenCodexHome, "OpenCodex import source");
  const targetOpenCodexHome = canonicalRoot(options.targetOpenCodexHome ?? defaultTargetOpenCodexHome(), "OpenCodex import destination");
  const sourceCodexHome = options.sourceCodexHome ? canonicalRoot(options.sourceCodexHome, "Codex import source") : null;
  const targetCodexHome = sourceCodexHome ? canonicalRoot(options.targetCodexHome ?? defaultTargetCodexHome(), "Codex import destination") : null;
  assertDirectory(sourceOpenCodexHome, "OpenCodex import source", false);
  assertDirectory(targetOpenCodexHome, "OpenCodex import destination", true);
  if (sourceCodexHome && targetCodexHome) {
    assertDirectory(sourceCodexHome, "Codex import source", false);
    assertDirectory(targetCodexHome, "Codex import destination", true);
  }
  const roots: Array<[string, string]> = [[sourceOpenCodexHome, "OpenCodex source"], [targetOpenCodexHome, "OpenCodex destination"]];
  if (sourceCodexHome && targetCodexHome) {
    roots.push([sourceCodexHome, "Codex source"], [targetCodexHome, "Codex destination"]);
  }
  const backupMetadataRoot = backupParent(targetOpenCodexHome);
  assertAllRootsDisjoint([...roots, [backupMetadataRoot, "OpenCodex backup metadata"] as [string, string]]);
  const includeSecrets = options.includeSecrets === true;
  const files = OPEN_CODEX_IMPORT_FILES.map(entry => {
    if (entry.scope === "codex" && (!sourceCodexHome || !targetCodexHome)) {
      return { ...publicEntry(entry), sourcePath: "", destinationPath: "", status: "excluded" as const };
    }
    const sourceRoot = entry.scope === "opencodex" ? sourceOpenCodexHome : sourceCodexHome!;
    const destinationRoot = entry.scope === "opencodex" ? targetOpenCodexHome : targetCodexHome!;
    return describeFile(entry, sourceRoot, destinationRoot, includeSecrets);
  });
  return { version: 1, sourceOpenCodexHome, targetOpenCodexHome, sourceCodexHome, targetCodexHome, includeSecrets, files };
}

export function createOpenCodexImportPlan(options: OpenCodexImportOptions): OpenCodexImportPlan {
  return createPlanUnchecked(options);
}

function selectedFiles(plan: OpenCodexImportPlan): OpenCodexImportFile[] {
  return plan.files.filter(file => file.status === "available" || file.status === "collision");
}

function backupParent(targetRoot: string): string {
  return resolve(dirname(targetRoot), ".cocodex-import-backups");
}

function safeBackupRoot(plan: OpenCodexImportPlan, now: Date): string {
  const parent = backupParent(plan.targetOpenCodexHome);
  assertNoSymlinkAncestors(parent, "OpenCodex import backup parent");
  const parentStat = safeLstat(parent);
  if (parentStat && (!parentStat.isDirectory() || parentStat.isSymbolicLink())) throw new OpenCodexImportError("OpenCodex import backup parent must be a real directory");
  const stamp = now.toISOString().replace(/[^0-9A-Z]/gi, "").slice(0, 16);
  return resolve(parent, `${stamp}-${randomUUID()}`);
}

function hardenRequiredPath(path: string, force = false): void {
  const result = hardenSecretPath(path, { required: true, force });
  if (!result.ok) throw new OpenCodexImportError(result.diagnostics ?? `ACL hardening failed for ${path}`);
}

function hardenRequiredDir(path: string, force = false): void {
  const result = hardenSecretDir(path, { required: true, force });
  if (!result.ok) throw new OpenCodexImportError(result.diagnostics ?? `ACL hardening failed for ${path}`);
}

function writeJsonAtomic(path: string, value: unknown): void {
  assertNoSymlinkAncestors(dirname(path), "OpenCodex import metadata");
  const temporary = `${path}.${randomUUID()}.tmp`;
  writeFileSync(temporary, JSON.stringify(value, null, 2) + "\n", { encoding: "utf8", mode: 0o600, flag: "wx" });
  const fd = openSync(temporary, "r+");
  try { fsyncSync(fd); } finally { closeSync(fd); }
  hardenRequiredPath(temporary);
  renameSync(temporary, path);
  hardenRequiredPath(path);
  if (process.platform !== "win32") {
    try { const directoryFd = openSync(dirname(path), "r"); try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); } } catch { /* Windows/virtual filesystems may not expose directory descriptors. */ }
  }
}

type ManifestFile = {
  scope: ImportScope;
  relativePath: string;
  sensitive: boolean;
  sourceSha256: string;
  importedSha256: string;
  sizeBytes: number;
  hadExisting: boolean;
  backupSha256?: string;
};

type ImportManifest = {
  version: 1;
  phase: "prepared" | "committed" | "rolled-back";
  createdAt: string;
  sourceOpenCodexHome: string;
  sourceCodexHome: string | null;
  targetOpenCodexHome: string;
  targetCodexHome: string | null;
  includeSecrets: boolean;
  stagingRoots?: string[];
  files: ManifestFile[];
  rolledBackAt?: string;
};

function readManifest(backupDirectory: string): ImportManifest {
  const directory = resolve(backupDirectory);
  assertNoSymlinkAncestors(directory, "OpenCodex import backup");
  const parent = dirname(directory);
  if (basename(parent) !== ".cocodex-import-backups") throw new OpenCodexImportError("Rollback path must be inside .cocodex-import-backups");
  const directoryStat = safeLstat(directory);
  if (!directoryStat?.isDirectory()) throw new OpenCodexImportError("Invalid import backup directory");
  const manifestPath = resolve(directory, "manifest.json");
  const manifestStat = safeLstat(manifestPath);
  if (!manifestStat?.isFile() || manifestStat.isSymbolicLink()) throw new OpenCodexImportError("Import backup manifest is missing");
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(manifestPath, "utf8")); } catch { throw new OpenCodexImportError("Import backup manifest is invalid"); }
  if (!parsed || typeof parsed !== "object" || (parsed as { version?: unknown }).version !== 1) throw new OpenCodexImportError("Import backup manifest has an unsupported version");
  const manifest = parsed as ImportManifest;
  if (!Array.isArray(manifest.files) || typeof manifest.targetOpenCodexHome !== "string") throw new OpenCodexImportError("Import backup manifest is malformed");
  const phase = manifest.phase;
  if (phase !== "prepared" && phase !== "committed" && phase !== "rolled-back") throw new OpenCodexImportError("Import backup manifest has an invalid phase");
  if (manifest.stagingRoots !== undefined && !Array.isArray(manifest.stagingRoots)) throw new OpenCodexImportError("Import backup manifest has malformed staging roots");
  return { ...manifest, phase };
}

function ensureRegularSource(file: OpenCodexImportFile): Uint8Array {
  const stable = readStableFile(file.sourcePath, `${file.scope}/${file.relativePath}`);
  if (stable.size !== file.sizeBytes || stable.mtimeMs !== file.sourceMtimeMs || stable.sha256 !== file.sourceSha256) {
    throw new OpenCodexImportError(`Source changed before import for ${file.scope}/${file.relativePath}`);
  }
  if (file.scope === "opencodex" && file.relativePath === "config.json") return scrubProviderConfig(stable.bytes);
  if (file.scope === "codex" && (file.relativePath === "config.toml" || file.relativePath === "opencodex.config.toml")) return scrubProviderToml(stable.bytes);
  return stable.bytes;
}

function entryFor(file: OpenCodexImportFile): ImportEntry | undefined {
  return OPEN_CODEX_IMPORT_FILES.find(entry => entry.scope === file.scope && entry.relativePath === file.relativePath);
}

function validatePlanShape(plan: OpenCodexImportPlan): void {
  if (!plan || plan.version !== 1 || typeof plan.sourceOpenCodexHome !== "string" || typeof plan.targetOpenCodexHome !== "string") throw new OpenCodexImportError("OpenCodex import plan is invalid");
  if (typeof plan.includeSecrets !== "boolean" || !Array.isArray(plan.files)) throw new OpenCodexImportError("OpenCodex import plan is malformed");
  const sourceOpen = canonicalRoot(plan.sourceOpenCodexHome, "OpenCodex import source");
  const targetOpen = canonicalRoot(plan.targetOpenCodexHome, "OpenCodex import destination");
  if (comparablePath(sourceOpen) !== comparablePath(plan.sourceOpenCodexHome) || comparablePath(targetOpen) !== comparablePath(plan.targetOpenCodexHome)) throw new OpenCodexImportError("OpenCodex import plan contains non-canonical roots");
  const hasCodex = plan.sourceCodexHome !== null || plan.targetCodexHome !== null;
  if (hasCodex !== (plan.sourceCodexHome !== null && plan.targetCodexHome !== null)) throw new OpenCodexImportError("OpenCodex import plan must provide both Codex roots or neither");
  const expectedEntries = OPEN_CODEX_IMPORT_FILES;
  if (plan.files.length !== expectedEntries.length) throw new OpenCodexImportError("OpenCodex import plan contains an unexpected file set");
  for (let i = 0; i < expectedEntries.length; i += 1) {
    const entry = expectedEntries[i]!;
    const file = plan.files[i]!;
    if (file.scope !== entry.scope || file.relativePath !== entry.relativePath || file.sensitive !== entry.sensitive || !entryFor(file)) throw new OpenCodexImportError("OpenCodex import plan contains an unauthorized file");
    const sourceRoot = entry.scope === "opencodex" ? sourceOpen : plan.sourceCodexHome ? canonicalRoot(plan.sourceCodexHome, "Codex import source") : "";
    const targetRoot = entry.scope === "opencodex" ? targetOpen : plan.targetCodexHome ? canonicalRoot(plan.targetCodexHome, "Codex import destination") : "";
    const expectedSource = sourceRoot ? resolve(sourceRoot, entry.relativePath) : "";
    const expectedDestination = targetRoot ? resolve(targetRoot, entry.relativePath) : "";
    if (comparablePath(file.sourcePath) !== comparablePath(expectedSource) || comparablePath(file.destinationPath) !== comparablePath(expectedDestination)) throw new OpenCodexImportError("OpenCodex import plan contains an escaped path");
    if (entry.alwaysExcluded && file.status !== "excluded") throw new OpenCodexImportError("OpenCodex import plan attempts to include an excluded credential file");
    if (file.sensitive && !plan.includeSecrets && file.status !== "excluded") throw new OpenCodexImportError("OpenCodex import plan attempts to include sensitive data without --include-secrets");
    if (!["available", "missing", "excluded", "collision"].includes(file.status)) throw new OpenCodexImportError("OpenCodex import plan contains an invalid file status");
    if ((file.status === "available" || file.status === "collision") && (!file.sourceSha256 || file.sizeBytes === undefined || file.sourceMtimeMs === undefined)) throw new OpenCodexImportError("OpenCodex import plan is missing source integrity metadata");
  }
}

function plansDiffer(a: OpenCodexImportPlan, b: OpenCodexImportPlan): { sourceChanged: boolean; destinationChanged: boolean } {
  let sourceChanged = false;
  let destinationChanged = false;
  for (let i = 0; i < a.files.length; i += 1) {
    const left = a.files[i]!;
    const right = b.files[i]!;
    if (left.sourceSha256 !== right.sourceSha256 || left.sizeBytes !== right.sizeBytes || left.sourceMtimeMs !== right.sourceMtimeMs) sourceChanged = true;
    if (left.status !== right.status) destinationChanged = true;
  }
  return { sourceChanged, destinationChanged };
}

function validateAndRefreshPlan(plan: OpenCodexImportPlan): OpenCodexImportPlan {
  validatePlanShape(plan);
  const fresh = createPlanUnchecked({
    sourceOpenCodexHome: plan.sourceOpenCodexHome,
    targetOpenCodexHome: plan.targetOpenCodexHome,
    sourceCodexHome: plan.sourceCodexHome ?? undefined,
    targetCodexHome: plan.targetCodexHome ?? undefined,
    includeSecrets: plan.includeSecrets,
  });
  const differences = plansDiffer(plan, fresh);
  if (differences.sourceChanged) throw new OpenCodexImportError("Source changed before import; preview is stale");
  if (differences.destinationChanged) throw new OpenCodexImportError("Destination changed before import; preview is stale");
  return fresh;
}

type PreparedFile = {
  file: OpenCodexImportFile;
  stagePath: string;
  backupPath: string | null;
  backupSha256?: string;
  importedSha256: string;
  movedExisting: boolean;
  committed: boolean;
};

function manifestFromPrepared(plan: OpenCodexImportPlan, prepared: PreparedFile[], now: Date, backupDirectory: string, phase: "prepared" | "committed", stageRoots: string[]): ImportManifest {
  return {
    version: 1,
    phase,
    createdAt: now.toISOString(),
    sourceOpenCodexHome: plan.sourceOpenCodexHome,
    sourceCodexHome: plan.sourceCodexHome,
    targetOpenCodexHome: plan.targetOpenCodexHome,
    targetCodexHome: plan.targetCodexHome,
    includeSecrets: plan.includeSecrets,
    stagingRoots: [...stageRoots],
    files: prepared.map(item => ({
      scope: item.file.scope,
      relativePath: item.file.relativePath,
      sensitive: item.file.sensitive,
      sourceSha256: item.file.sourceSha256!,
      importedSha256: item.importedSha256,
      sizeBytes: item.file.sizeBytes!,
      hadExisting: item.file.status === "collision",
      ...(item.backupSha256 ? { backupSha256: item.backupSha256 } : {}),
    })),
  };
}

function currentHash(path: string): string | null {
  const stat = safeLstat(path);
  if (!stat) return null;
  if (!stat.isFile() || stat.isSymbolicLink()) throw new OpenCodexImportError(`Rollback refuses non-regular destination ${path}`);
  return readStableFile(path, path).sha256;
}

function rollbackPrepared(prepared: PreparedFile[], stageRoots: string[]): string[] {
  const failures: string[] = [];
  for (const item of [...prepared].reverse()) {
    try {
      assertNoSymlinkAncestors(dirname(item.file.destinationPath), "OpenCodex import destination");
      if (item.committed) {
        const hash = currentHash(item.file.destinationPath);
        if (hash !== item.importedSha256) throw new OpenCodexImportError(`destination changed during recovery for ${item.file.relativePath}`);
        rmSync(item.file.destinationPath, { force: true });
      }
      if (item.movedExisting && item.backupPath) {
        if (item.backupSha256 && currentHash(item.backupPath) !== item.backupSha256) throw new OpenCodexImportError(`backup changed during recovery for ${item.file.relativePath}`);
        mkdirSync(dirname(item.file.destinationPath), { recursive: true, mode: 0o700 });
        renameSync(item.backupPath, item.file.destinationPath);
        hardenRequiredPath(item.file.destinationPath, true);
      }
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error));
    }
  }
  for (const root of stageRoots) {
    try {
      assertNoSymlinkAncestors(root, "OpenCodex import staging");
      const stageStat = safeLstat(root);
      if (stageStat && (!stageStat.isDirectory() || stageStat.isSymbolicLink())) throw new OpenCodexImportError("OpenCodex import staging root is not a real directory");
      rmSync(root, { recursive: true, force: true });
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error));
    }
  }
  return failures;
}

export function applyOpenCodexImport(inputPlan: OpenCodexImportPlan, now = new Date()): OpenCodexImportResult {
  const plan = validateAndRefreshPlan(inputPlan);
  const files = selectedFiles(plan);
  if (files.length === 0) throw new OpenCodexImportError("No importable OpenCodex files were found; nothing changed");
  assertNoSymlinkAncestors(dirname(plan.targetOpenCodexHome), "OpenCodex import destination");
  if (plan.targetCodexHome) assertNoSymlinkAncestors(dirname(plan.targetCodexHome), "Codex import destination");
  const backupDirectory = safeBackupRoot(plan, now);
  const stageRoots = [
    resolve(dirname(plan.targetOpenCodexHome), `.cocodex-import-staging-${randomUUID()}`),
    ...(plan.targetCodexHome ? [resolve(dirname(plan.targetCodexHome), `.cocodex-import-staging-${randomUUID()}`)] : []),
  ];
  const prepared: PreparedFile[] = [];
  try {
    const backupParentPath = dirname(backupDirectory);
    assertNoSymlinkAncestors(backupParentPath, "OpenCodex import backup parent");
    const existingBackupParent = safeLstat(backupParentPath);
    if (existingBackupParent && (!existingBackupParent.isDirectory() || existingBackupParent.isSymbolicLink())) throw new OpenCodexImportError("OpenCodex import backup parent must be a real directory");
    mkdirSync(backupParentPath, { recursive: true, mode: 0o700 });
    assertNoSymlinkAncestors(backupParentPath, "OpenCodex import backup parent");
    hardenRequiredDir(backupParentPath);
    assertNoSymlinkAncestors(backupDirectory, "OpenCodex import backup");
    const existingBackupDirectory = safeLstat(backupDirectory);
    if (existingBackupDirectory) throw new OpenCodexImportError("OpenCodex import backup directory already exists");
    mkdirSync(backupDirectory, { recursive: true, mode: 0o700 });
    assertNoSymlinkAncestors(backupDirectory, "OpenCodex import backup");
    const backupDirectoryStat = safeLstat(backupDirectory);
    if (!backupDirectoryStat?.isDirectory() || backupDirectoryStat.isSymbolicLink()) throw new OpenCodexImportError("OpenCodex import backup directory must be a real directory");
    hardenRequiredDir(backupDirectory);
    for (const file of files) {
      const stageRoot = file.scope === "opencodex" ? stageRoots[0]! : stageRoots[1]!;
      assertNoSymlinkAncestors(stageRoot, "OpenCodex import staging");
      const bytes = ensureRegularSource(file);
      const stagePath = resolve(stageRoot, file.relativePath);
      const backupPath = file.status === "collision" ? resolve(backupDirectory, file.scope, file.relativePath) : null;
      mkdirSync(dirname(stagePath), { recursive: true, mode: 0o700 });
      hardenRequiredDir(dirname(stagePath));
      writeFileSync(stagePath, bytes, { mode: 0o600, flag: "wx" });
      hardenRequiredPath(stagePath);
      if (backupPath) {
        assertNoSymlinkAncestors(dirname(backupPath), "OpenCodex import backup scope");
        mkdirSync(dirname(backupPath), { recursive: true, mode: 0o700 });
        const backupScope = safeLstat(dirname(backupPath));
        if (!backupScope?.isDirectory() || backupScope.isSymbolicLink()) throw new OpenCodexImportError("OpenCodex import backup scope must be a real directory");
        hardenRequiredDir(dirname(backupPath));
      }
      prepared.push({ file, stagePath, backupPath, importedSha256: sha256(bytes), movedExisting: false, committed: false });
    }
    for (const item of prepared) {
      assertNoSymlinkAncestors(dirname(item.file.destinationPath), "OpenCodex import destination");
      const destination = safeLstat(item.file.destinationPath);
      if (item.file.status === "collision" && (!destination || !destination.isFile() || destination.isSymbolicLink())) throw new OpenCodexImportError(`Destination changed before import for ${item.file.scope}/${item.file.relativePath}`);
      if (item.file.status === "available" && destination) throw new OpenCodexImportError(`Destination changed before import for ${item.file.scope}/${item.file.relativePath}`);
      if (item.backupPath && destination) item.backupSha256 = currentHash(item.file.destinationPath)!;
    }
    const preparedManifest = manifestFromPrepared(plan, prepared, now, backupDirectory, "prepared", stageRoots);
    writeJsonAtomic(resolve(backupDirectory, "manifest.json"), preparedManifest);
    for (const item of prepared) {
      assertNoSymlinkAncestors(dirname(item.file.destinationPath), "OpenCodex import destination");
      mkdirSync(dirname(item.file.destinationPath), { recursive: true, mode: 0o700 });
      hardenRequiredDir(dirname(item.file.destinationPath), true);
      assertNoSymlinkAncestors(dirname(item.stagePath), "OpenCodex import staging");
      const stageStat = safeLstat(item.stagePath);
      if (!stageStat?.isFile() || stageStat.isSymbolicLink() || currentHash(item.stagePath) !== item.importedSha256) throw new OpenCodexImportError(`OpenCodex import staging changed before commit for ${item.file.relativePath}`);
      if (item.backupPath) {
        assertNoSymlinkAncestors(dirname(item.backupPath), "OpenCodex import backup scope");
        const backupScope = safeLstat(dirname(item.backupPath));
        if (!backupScope?.isDirectory() || backupScope.isSymbolicLink()) throw new OpenCodexImportError("OpenCodex import backup scope must be a real directory");
        renameSync(item.file.destinationPath, item.backupPath);
        item.movedExisting = true;
        hardenRequiredPath(item.backupPath);
      }
      renameSync(item.stagePath, item.file.destinationPath);
      item.committed = true;
      hardenRequiredPath(item.file.destinationPath, true);
    }
    writeJsonAtomic(resolve(backupDirectory, "manifest.json"), manifestFromPrepared(plan, prepared, now, backupDirectory, "committed", stageRoots));
    for (const root of stageRoots) { try { rmSync(root, { recursive: true, force: true }); } catch { /* journal remains usable */ } }
    return { version: 1, imported: prepared.map(item => ({ scope: item.file.scope, relativePath: item.file.relativePath, sensitive: item.file.sensitive, sizeBytes: item.file.sizeBytes, sourceSha256: item.file.sourceSha256 })), backupDirectory };
  } catch (error) {
    const failures = rollbackPrepared(prepared, stageRoots);
    const recovery = failures.length ? ` Recovery required; backup directory: ${backupDirectory}. ${failures.join("; ")}` : "";
    throw new OpenCodexImportError(`OpenCodex import rolled back after failure: ${error instanceof Error ? error.message : String(error)}${recovery}`, { cause: error });
  }
}

function manifestTarget(manifest: ImportManifest, file: ManifestFile): string {
  const root = file.scope === "opencodex" ? manifest.targetOpenCodexHome : manifest.targetCodexHome;
  if (!root) throw new OpenCodexImportError(`Rollback manifest has no ${file.scope} destination`);
  const destination = resolve(root, file.relativePath);
  if (!isPathWithin(root, destination) || destination === resolve(root)) throw new OpenCodexImportError("Rollback path escaped its destination root");
  assertNoSymlinkAncestors(dirname(destination), "Rollback destination");
  return destination;
}

function manifestBackup(manifestDirectory: string, file: ManifestFile): string {
  if (!entryFor({ scope: file.scope, relativePath: file.relativePath } as OpenCodexImportFile)) throw new OpenCodexImportError("Rollback manifest contains an unauthorized file");
  const backup = resolve(manifestDirectory, file.scope, file.relativePath);
  if (!isPathWithin(manifestDirectory, backup) || backup === resolve(manifestDirectory)) throw new OpenCodexImportError("Rollback path escaped its backup root");
  assertNoSymlinkAncestors(dirname(backup), "Rollback backup");
  return backup;
}

function validateManifest(manifest: ImportManifest, directory: string, expectedTargetRoot?: string, expectedTargetCodexRoot?: string): void {
  if (manifest.phase !== "prepared" && manifest.phase !== "committed" && manifest.phase !== "rolled-back") throw new OpenCodexImportError("Rollback manifest has an invalid phase");
  if (typeof manifest.createdAt !== "string" || typeof manifest.sourceOpenCodexHome !== "string" || (manifest.sourceCodexHome !== null && typeof manifest.sourceCodexHome !== "string") || (manifest.targetCodexHome !== null && typeof manifest.targetCodexHome !== "string") || typeof manifest.includeSecrets !== "boolean" || !Array.isArray(manifest.files)) throw new OpenCodexImportError("Rollback manifest is malformed");
  if (manifest.stagingRoots !== undefined && (!Array.isArray(manifest.stagingRoots) || manifest.stagingRoots.some(root => typeof root !== "string"))) throw new OpenCodexImportError("Rollback manifest has malformed staging roots");
  const seenFiles = new Set<string>();
  for (const file of manifest.files) {
    if (!file || typeof file !== "object" || (file.scope !== "opencodex" && file.scope !== "codex") || typeof file.relativePath !== "string" || typeof file.sensitive !== "boolean" || !/^[0-9a-f]{64}$/i.test(file.sourceSha256) || !/^[0-9a-f]{64}$/i.test(file.importedSha256) || !Number.isSafeInteger(file.sizeBytes) || file.sizeBytes < 0 || file.sizeBytes > MAX_IMPORT_FILE_BYTES || typeof file.hadExisting !== "boolean" || (file.backupSha256 !== undefined && !/^[0-9a-f]{64}$/i.test(file.backupSha256))) throw new OpenCodexImportError("Rollback manifest contains malformed file integrity metadata");
    const fileKey = `${file.scope}:${file.relativePath}`;
    if (seenFiles.has(fileKey)) throw new OpenCodexImportError("Rollback manifest contains duplicate file entries");
    seenFiles.add(fileKey);
  }
  const expectedOpen = canonicalRoot(expectedTargetRoot ?? manifest.targetOpenCodexHome, "OpenCodex import destination");
  if (comparablePath(manifest.targetOpenCodexHome) !== comparablePath(expectedOpen)) throw new OpenCodexImportError("Rollback backup does not belong to the selected target");
  if (comparablePath(dirname(directory)) !== comparablePath(backupParent(expectedOpen))) throw new OpenCodexImportError("Rollback backup is outside the selected target backup parent");
  assertDirectory(manifest.targetOpenCodexHome, "Rollback OpenCodex destination", true);
  if (manifest.targetCodexHome) {
    if (!expectedTargetCodexRoot) throw new OpenCodexImportError("Rollback with a Codex scope requires the expected Codex target root");
    if (expectedTargetCodexRoot && comparablePath(manifest.targetCodexHome) !== comparablePath(canonicalRoot(expectedTargetCodexRoot, "Codex import destination"))) throw new OpenCodexImportError("Rollback backup does not belong to the selected Codex target");
    assertDirectory(manifest.targetCodexHome, "Rollback Codex destination", true);
  }
  const stagingParents = [dirname(manifest.targetOpenCodexHome), ...(manifest.targetCodexHome ? [dirname(manifest.targetCodexHome)] : [])].map(item => resolve(item));
  for (const stagingRoot of manifest.stagingRoots ?? []) {
    const canonical = resolve(stagingRoot);
    if (!/^\.cocodex-import-staging-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(basename(canonical)) || !stagingParents.some(parent => comparablePath(dirname(canonical)) === comparablePath(parent))) throw new OpenCodexImportError("Rollback manifest contains an unsafe staging root");
    assertNoSymlinkAncestors(canonical, "Rollback staging");
  }
  for (const file of manifest.files) {
    if (!entryFor({ scope: file.scope, relativePath: file.relativePath } as OpenCodexImportFile)) throw new OpenCodexImportError("Rollback manifest contains an unauthorized file");
    if (file.hadExisting && !file.backupSha256) throw new OpenCodexImportError("Rollback manifest lacks collision-backup integrity metadata");
    manifestTarget(manifest, file);
    manifestBackup(directory, file);
  }
}


export function rollbackOpenCodexImport(backupDirectory: string, expectedTargetRoot?: string, expectedTargetCodexRoot?: string): OpenCodexRollbackResult {
  const directory = resolve(backupDirectory);
  const manifest = readManifest(directory);
  if (manifest.phase === "rolled-back" || manifest.rolledBackAt) throw new OpenCodexImportError("Import backup was already rolled back");
  validateManifest(manifest, directory, expectedTargetRoot, expectedTargetCodexRoot);
  for (const file of manifest.files) {
    const destination = manifestTarget(manifest, file);
    const hash = currentHash(destination);
    if (manifest.phase === "prepared" && hash !== null && !file.hadExisting) throw new OpenCodexImportError(`Prepared rollback is ambiguous for ${file.scope}/${file.relativePath}; destination content was not journaled`);
    if (manifest.phase === "prepared" && hash !== null && file.hadExisting && !safeLstat(manifestBackup(directory, file))) throw new OpenCodexImportError(`Prepared rollback cannot prove collision ownership for ${file.scope}/${file.relativePath}`);
    if (hash !== null && hash !== file.importedSha256) throw new OpenCodexImportError(`Rollback refused because imported destination was edited: ${file.scope}/${file.relativePath}`);
    if (manifest.phase !== "prepared" && hash === null) throw new OpenCodexImportError(`Rollback imported destination is missing: ${file.scope}/${file.relativePath}`);
    if (file.hadExisting) {
      const backup = manifestBackup(directory, file);
      const backupStat = safeLstat(backup);
      if (backupStat) {
        if (!backupStat.isFile() || backupStat.isSymbolicLink() || (file.backupSha256 && currentHash(backup) !== file.backupSha256)) throw new OpenCodexImportError(`Rollback backup was edited: ${file.scope}/${file.relativePath}`);
      } else if (manifest.phase !== "prepared") {
        throw new OpenCodexImportError(`Rollback backup is missing: ${file.scope}/${file.relativePath}`);
      }
    }
  }
  let restored = 0;
  let removed = 0;
  try {
    for (const file of [...manifest.files].reverse()) {
      const destination = manifestTarget(manifest, file);
      const hash = currentHash(destination);
      assertNoSymlinkAncestors(dirname(destination), "Rollback destination");
      if (hash !== null) {
        if (hash !== file.importedSha256) throw new OpenCodexImportError(`Rollback refused because imported destination was edited: ${file.scope}/${file.relativePath}`);
        rmSync(destination, { force: true });
      }
      if (file.hadExisting) {
        const backup = manifestBackup(directory, file);
        if (safeLstat(backup)) {
          assertNoSymlinkAncestors(dirname(backup), "Rollback backup");
          const backupStat = safeLstat(backup);
          if (!backupStat?.isFile() || backupStat.isSymbolicLink() || !file.backupSha256 || currentHash(backup) !== file.backupSha256) throw new OpenCodexImportError(`Rollback backup changed before restore for ${file.relativePath}`);
          mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
          renameSync(backup, destination);
          hardenRequiredPath(destination, true);
          restored += 1;
        }
      } else if (hash !== null) {
        removed += 1;
      }
    }
    // Prepared journal staging roots are intentionally left for manual cleanup; never recursively delete a manifest-supplied path during recovery.
    writeJsonAtomic(resolve(directory, "manifest.json"), { ...manifest, phase: "rolled-back", rolledBackAt: new Date().toISOString() });
  } catch (error) {
    throw new OpenCodexImportError(`Rollback stopped; recovery required in ${directory}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  }
  return { rolledBack: true, backupDirectory: directory, restored, removed };
}

export function listOpenCodexImportBackups(targetRoot: string): OpenCodexImportBackup[] {
  const canonicalTarget = canonicalRoot(targetRoot, "OpenCodex import destination");
  const root = backupParent(canonicalTarget);
  assertNoSymlinkAncestors(root, "OpenCodex import backup parent");
  const rootStat = safeLstat(root);
  if (!rootStat) return [];
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new OpenCodexImportError("OpenCodex import backup parent must be a real directory");
  const entries: OpenCodexImportBackup[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    const directory = resolve(root, entry.name);
    try {
      const manifest = readManifest(directory);
      if (comparablePath(manifest.targetOpenCodexHome) !== comparablePath(canonicalTarget)) continue;
      entries.push({ backupDirectory: directory, createdAt: manifest.createdAt, fileCount: manifest.files.length, state: manifest.phase, ...(manifest.rolledBackAt ? { rolledBackAt: manifest.rolledBackAt } : {}) });
    } catch {
      // Ignore incomplete or unrelated directories in the local backup root.
    }
  }
  return entries.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export function summarizeOpenCodexImportPlan(plan: OpenCodexImportPlan): { available: number; collisions: number; excluded: number; missing: number; files: OpenCodexImportFile[] } {
  return {
    available: plan.files.filter(file => file.status === "available").length,
    collisions: plan.files.filter(file => file.status === "collision").length,
    excluded: plan.files.filter(file => file.status === "excluded").length,
    missing: plan.files.filter(file => file.status === "missing").length,
    files: plan.files,
  };
}

export function isImportPathWithin(parent: string, candidate: string): boolean {
  return isPathWithin(resolve(parent), resolve(candidate));
}

export function resolveOpenCodexImportSource(): string {
  return resolveCodexHomeDir();
}
