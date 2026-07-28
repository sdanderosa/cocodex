import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { closeSync, existsSync, lstatSync, openSync, readFileSync, readSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import type { ServerPaths } from "./paths";
import { windowsServerServiceState, type ServerServiceState } from "./windows-service";

const PACKAGE_NAME = "@sdanderosa/cocodex";
const ARCHIVE_MAX_BYTES = 512 * 1024 * 1024;
const TEXT_MAX_BYTES = 1024 * 1024;

export interface ServerUpdateBundle {
  directory: string;
  installer: string;
  checksumFile: string;
  releaseManifest: string;
  archive: string;
  packageName: typeof PACKAGE_NAME;
  version: string;
  sourceCommit: string;
  sha256: string;
  requiredNodeVersion: string;
  requiredNpmMajor: number;
}

export interface ServerUpdateReadiness {
  ready: boolean;
  directServerPid: number | null;
  serviceState: ServerServiceState;
  applicationProcesses: Array<{ processId: number; name: string }>;
  blockers: string[];
}

export interface ServerUpdateCheck {
  verified: true;
  currentVersion: string;
  targetVersion: string;
  sourceCommit: string;
  archiveSha256: string;
  applicationPrefix: string;
  stateRoot: string;
  readiness: ServerUpdateReadiness;
  apply: {
    executable: string;
    arguments: string[];
    updatesSharedApplicationFiles: true;
    preservesStateRoots: string[];
  };
}

export interface ServerUpdateDeps {
  packageStart?: string;
  platform?: NodeJS.Platform;
  serviceState?: (paths: ServerPaths) => ServerServiceState;
  runInstallerCheck?: (bundle: ServerUpdateBundle, prefix: string) => Record<string, unknown>;
}

function regularFile(path: string, maxBytes: number, label: string): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(label + " must be one regular file");
  if (stat.size < 1 || stat.size > maxBytes) throw new Error(label + " has an invalid size");
}

function boundedFile(path: string, maxBytes: number, label: string): Buffer {
  regularFile(path, maxBytes, label);
  return readFileSync(path);
}

function sha256(path: string): string {
  const hash = createHash("sha256");
  const descriptor = openSync(path, "r");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    while (true) {
      const length = readSync(descriptor, buffer, 0, buffer.length, null);
      if (length === 0) break;
      hash.update(buffer.subarray(0, length));
    }
  } finally {
    closeSync(descriptor);
  }
  return hash.digest("hex");
}
function strictObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function strictString(value: unknown, label: string, pattern?: RegExp): string {
  if (typeof value !== "string" || !value || value.length > 512 || (pattern && !pattern.test(value))) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function parseChecksums(text: string): Map<string, string> {
  const entries = new Map<string, string>();
  for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
    if (!line) continue;
    const match = /^([0-9a-fA-F]{64}) [ *]([^\\/\r\n]+)$/.exec(line);
    if (!match) throw new Error("SHA256SUMS.txt contains an invalid line");
    if (entries.has(match[2])) throw new Error("SHA256SUMS.txt contains a duplicate filename");
    entries.set(match[2], match[1].toLowerCase());
  }
  return entries;
}

function requireBundleFile(directory: string, name: string, maxBytes: number, label: string): string {
  if (basename(name) !== name || name === "." || name === "..") throw new Error(`${label} filename is invalid`);
  const path = resolve(directory, name);
  regularFile(path, maxBytes, label);
  if (dirname(path).toLowerCase() !== directory.toLowerCase()) throw new Error(`${label} escaped the bundle directory`);
  return path;
}

export function inspectServerUpdateBundle(bundleDirectory: string): ServerUpdateBundle {
  const directory = resolve(bundleDirectory);
  const directoryStat = lstatSync(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error("Update bundle must be one ordinary directory");
  }
  const realDirectory = realpathSync.native(directory);
  if (realDirectory.toLowerCase() !== directory.toLowerCase()) {
    throw new Error("Update bundle directory cannot be redirected through a link");
  }

  const checksumFile = requireBundleFile(directory, "SHA256SUMS.txt", TEXT_MAX_BYTES, "checksum file");
  const releaseManifest = requireBundleFile(directory, "RELEASE.json", 65_536, "release manifest");
  const installer = requireBundleFile(directory, "Install-CoCodex.ps1", TEXT_MAX_BYTES, "installer");
  const release = strictObject(JSON.parse(boundedFile(releaseManifest, 65_536, "release manifest").toString("utf8")), "RELEASE.json");
  const packageName = strictString(release.packageName, "release package name");
  if (packageName !== PACKAGE_NAME) throw new Error("Release bundle is not a CoCodex package");
  const archiveName = strictString(release.archive, "release archive", /^[A-Za-z0-9._-]+\.tgz$/);
  const archive = requireBundleFile(directory, archiveName, ARCHIVE_MAX_BYTES, "package archive");
  const version = strictString(release.version, "release version", /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  const sourceCommit = strictString(release.sourceCommit, "source commit", /^[0-9a-f]{40}$/);
  const releaseSha = strictString(release.sha256, "archive SHA-256", /^[0-9a-f]{64}$/).toLowerCase();
  const requiredNodeVersion = strictString(release.requiredNodeVersion, "required Node version", /^\d+\.\d+\.\d+$/);
  const requiredNpmMajor = release.requiredNpmMajor;
  if (!Number.isInteger(requiredNpmMajor) || Number(requiredNpmMajor) < 10 || Number(requiredNpmMajor) > 99) {
    throw new Error("required npm major is invalid");
  }

  const checksums = parseChecksums(boundedFile(checksumFile, TEXT_MAX_BYTES, "checksum file").toString("utf8"));
  for (const [path, label] of [[archive, "package archive"], [releaseManifest, "release manifest"], [installer, "installer"]] as const) {
    const expected = checksums.get(basename(path));
    if (!expected) throw new Error(`SHA256SUMS.txt does not cover the ${label}`);
    const actual = sha256(path);
    if (actual !== expected) throw new Error(`${label} failed SHA-256 verification`);
  }
  if (sha256(archive) !== releaseSha) throw new Error("RELEASE.json archive digest does not match the package");

  return {
    directory,
    installer,
    checksumFile,
    releaseManifest,
    archive,
    packageName: PACKAGE_NAME,
    version,
    sourceCommit,
    sha256: releaseSha,
    requiredNodeVersion,
    requiredNpmMajor: Number(requiredNpmMajor),
  };
}

function packageRoot(start: string): { root: string; version: string } {
  let cursor = resolve(start);
  for (let depth = 0; depth < 8; depth += 1) {
    const manifestPath = join(cursor, "package.json");
    if (existsSync(manifestPath)) {
      const manifest = strictObject(JSON.parse(boundedFile(manifestPath, TEXT_MAX_BYTES, "package manifest").toString("utf8")), "package manifest");
      if (manifest.name === PACKAGE_NAME) {
        return { root: cursor, version: strictString(manifest.version, "installed package version") };
      }
    }
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  throw new Error("Server update is available only from an installed CoCodex package");
}

function powershellPath(): string {
  const exact = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  if (!existsSync(exact)) throw new Error("Exact Windows PowerShell executable is unavailable");
  return exact;
}

function runInstallerCheck(bundle: ServerUpdateBundle, prefix: string): Record<string, unknown> {
  const output = execFileSync(powershellPath(), [
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", bundle.installer,
    "-Action", "Check",
    "-PackagePath", bundle.archive,
    "-ChecksumPath", bundle.checksumFile,
    "-ReleaseManifestPath", bundle.releaseManifest,
    "-NpmPrefix", prefix,
    "-SkipPathUpdate",
  ], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    timeout: 60_000,
    maxBuffer: 1024 * 1024,
  }).trim();
  const line = output.split(/\r?\n/).findLast(candidate => candidate.trim().startsWith("{"));
  if (!line) throw new Error("Verified installer check returned no JSON result");
  return strictObject(JSON.parse(line), "installer check");
}

function installerBlockingProcesses(value: unknown): Array<{ processId: number; name: string }> {
  if (!Array.isArray(value) || value.length > 128) throw new Error("Installer process-blocker result is invalid");
  return value.map(entry => {
    const item = strictObject(entry, "installer process blocker");
    if (!Number.isInteger(item.processId) || Number(item.processId) <= 0
      || typeof item.name !== "string" || !item.name || item.name.length > 260) {
      throw new Error("Installer process-blocker result is invalid");
    }
    return { processId: Number(item.processId), name: item.name };
  });
}
function livePid(paths: ServerPaths): number | undefined {
  if (!existsSync(paths.pid)) return undefined;
  const value = Number(readFileSync(paths.pid, "utf8").trim());
  if (!Number.isInteger(value) || value <= 0) return undefined;
  try { process.kill(value, 0); return value; }
  catch { return undefined; }
}

export function serverUpdateReadiness(
  paths: ServerPaths,
  serviceState: ServerServiceState,
  applicationProcesses: Array<{ processId: number; name: string }> = [],
): ServerUpdateReadiness {
  const directServerPid = livePid(paths) ?? null;
  const blockers: string[] = [];
  if (directServerPid) blockers.push(`Stop direct CoCodex Server PID ${directServerPid}`);
  if (serviceState === "started") blockers.push("Stop the CoCodex Server Windows service");
  if (serviceState === "unknown") blockers.push("Repair or verify the CoCodex Server Windows service state");
  for (const applicationProcess of applicationProcesses) {
    if (applicationProcess.processId !== directServerPid) blockers.push("Close CoCodex process " + applicationProcess.processId + " (" + applicationProcess.name + ")");
  }
  return { ready: blockers.length === 0, directServerPid, serviceState, applicationProcesses, blockers };
}

export function checkServerUpdate(
  paths: ServerPaths,
  bundleDirectory: string,
  deps: ServerUpdateDeps = {},
): ServerUpdateCheck {
  if ((deps.platform ?? process.platform) !== "win32") {
    throw new Error("Verified CoCodex Server update bundles are currently supported only on Windows");
  }
  const bundle = inspectServerUpdateBundle(bundleDirectory);
  const installed = packageRoot(deps.packageStart ?? import.meta.dir);
  const scopeDirectory = dirname(installed.root);
  const nodeModulesDirectory = dirname(scopeDirectory);
  if (basename(scopeDirectory).toLowerCase() !== "@sdanderosa"
    || basename(nodeModulesDirectory).toLowerCase() !== "node_modules") {
    throw new Error("Server update is available only from the verified installed package layout");
  }
  const prefix = dirname(nodeModulesDirectory);
  const result = (deps.runInstallerCheck ?? runInstallerCheck)(bundle, prefix);
  if (result.verified !== true || result.packageName !== PACKAGE_NAME || result.version !== bundle.version
    || String(result.sha256).toLowerCase() !== bundle.sha256) {
    throw new Error("Verified installer check returned inconsistent release metadata");
  }
  const applicationProcesses = installerBlockingProcesses(result.blockingProcesses);
  if (result.readyForUpdate !== (applicationProcesses.length === 0)) {
    throw new Error("Verified installer check returned inconsistent process readiness");
  }
  const serviceState = (deps.serviceState ?? windowsServerServiceState)(paths);
  const readiness = serverUpdateReadiness(paths, serviceState, applicationProcesses);
  return {
    verified: true,
    currentVersion: installed.version,
    targetVersion: bundle.version,
    sourceCommit: bundle.sourceCommit,
    archiveSha256: bundle.sha256,
    applicationPrefix: prefix,
    stateRoot: paths.root,
    readiness,
    apply: {
      executable: powershellPath(),
      arguments: [
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", bundle.installer,
        "-Action", "Update",
        "-PackagePath", bundle.archive,
        "-ChecksumPath", bundle.checksumFile,
        "-ReleaseManifestPath", bundle.releaseManifest,
        "-NpmPrefix", prefix,
        "-SkipPathUpdate",
      ],
      updatesSharedApplicationFiles: true,
      preservesStateRoots: ["~/.cocodex", "~/.cocodex-server", "~/.opencodex", "~/.codex"],
    },
  };
}
