#!/usr/bin/env bun
import {
  copyFileSync,
  cpSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DISTRIBUTION_NAME = "@sdanderosa/cocodex";
const SHRINKWRAP_SOURCE = resolve(ROOT, "scripts", "private-alpha", "npm-shrinkwrap.json");
const COPY_PATHS = [
  "bin",
  "src",
  "apps/cocodex-server/package.json",
  "apps/cocodex-server/src",
  "packages/cocodex-protocol/package.json",
  "packages/cocodex-protocol/src",
  "gui/dist",
  "assets",
  "README.md",
  "LICENSE",
  "THIRD_PARTY_NOTICES.md",
] as const;
const PACKAGE_FILES = [...COPY_PATHS, "npm-shrinkwrap.json"] as const;

function option(name: string): string | undefined {
  const index = Bun.argv.indexOf(name);
  return index >= 0 ? Bun.argv[index + 1] : undefined;
}

function assertRegularTree(path: string): void {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) throw new Error(`Release input must not be a symbolic link: ${path}`);
  if (stat.isDirectory()) {
    for (const entry of readdirSync(path)) assertRegularTree(join(path, entry));
    return;
  }
  if (!stat.isFile()) throw new Error(`Release input must be a regular file or directory: ${path}`);
}

function copyReleaseInput(stage: string, relativePath: string): void {
  const source = resolve(ROOT, relativePath);
  if (!existsSync(source)) throw new Error(`Required release input is missing: ${relativePath}`);
  assertRegularTree(source);
  const destination = resolve(stage, relativePath);
  mkdirSync(dirname(destination), { recursive: true });
  if (lstatSync(source).isDirectory()) {
    cpSync(source, destination, { recursive: true, errorOnExist: true, force: false });
  } else {
    copyFileSync(source, destination);
  }
}

function packageVersion(): string {
  const serverPackage = JSON.parse(
    readFileSync(resolve(ROOT, "apps", "cocodex-server", "package.json"), "utf8"),
  ) as { version?: unknown };
  if (typeof serverPackage.version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(serverPackage.version)) {
    throw new Error("CoCodex Server package has an invalid release version");
  }
  return serverPackage.version;
}

export function bunLockOverrides(): Record<string, string> {
  const versions = new Map<string, Set<string>>();
  for (const line of readFileSync(resolve(ROOT, "bun.lock"), "utf8").split(/\r?\n/)) {
    const resolved = line.match(/:\s*\[\s*"([^"]+)"/)?.[1];
    const match = resolved?.match(/^(.+)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/);
    if (!match) continue;
    const [, name, version] = match;
    const values = versions.get(name) ?? new Set<string>();
    values.add(version);
    versions.set(name, values);
  }
  return Object.fromEntries(
    [...versions]
      .filter(([, values]) => values.size === 1)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, values]) => [name, [...values][0]]),
  );
}

export function privateAlphaPackageJson(
  source: Record<string, any>,
  version = packageVersion(),
): Record<string, any> {
  const bunLockLines = readFileSync(resolve(ROOT, "bun.lock"), "utf8").split(/\r?\n/);
  const dependencies = Object.fromEntries(
    Object.keys(source.dependencies ?? {}).sort().map(name => {
      const prefixText = `${JSON.stringify(name)}: [`;
      const line = bunLockLines.find(candidate => candidate.trimStart().startsWith(prefixText));
      const resolved = line?.match(/:\s*\[\s*"([^"]+)"/)?.[1];
      const prefix = `${name}@`;
      const exact = typeof resolved === "string" && resolved.startsWith(prefix)
        ? resolved.slice(prefix.length)
        : "";
      if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(exact)) {
        throw new Error(`bun.lock does not contain an exact registry version for ${name}`);
      }
      return [name, exact];
    }),
  );
  return {
    ...source,
    name: DISTRIBUTION_NAME,
    version,
    description: "CoCodex private alpha: trusted shared Codex projects with separate Client and Server applications",
    repository: {
      type: "git",
      url: "git+https://github.com/sdanderosa/cocodex.git",
    },
    homepage: "https://github.com/sdanderosa/cocodex",
    bugs: { url: "https://github.com/sdanderosa/cocodex/issues" },
    dependencies,
    engines: { node: ">=22.12.0" },
    files: [...PACKAGE_FILES],
    scripts: {},
    workspaces: undefined,
    devDependencies: undefined,
    overrides: bunLockOverrides(),
    private: undefined,
  };
}

type SourceProvenance = { commit: string; tree: string };

function gitCommand(): string {
  const explicit = option("--git-command");
  const command = explicit
    ? resolve(explicit)
    : Bun.which(process.platform === "win32" ? "git.exe" : "git") ?? Bun.which("git");
  if (!command || !existsSync(command) || !lstatSync(command).isFile()) {
    throw new Error("git is required to prove private-alpha source provenance; pass --git-command PATH");
  }
  return command;
}

function runGit(git: string, args: string[]): string {
  const result = Bun.spawnSync([git, "-c", `safe.directory=${ROOT}`, ...args], {
    cwd: ROOT,
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  });
  if (result.exitCode !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${Buffer.from(result.stderr).toString("utf8").trim()}`);
  }
  return Buffer.from(result.stdout).toString("utf8").trim();
}

function sourceProvenance(): SourceProvenance {
  const git = gitCommand();
  const dirty = runGit(git, ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (dirty) {
    const entries = dirty.split(/\r?\n/);
    const summary = entries.slice(0, 50).join("\n");
    const remainder = entries.length > 50 ? `\n... and ${entries.length - 50} more entries` : "";
    throw new Error(`Refusing to attribute a dirty worktree to a release commit:\n${summary}${remainder}`);
  }
  const commit = runGit(git, ["rev-parse", "--verify", "HEAD"]).toLowerCase();
  const tree = runGit(git, ["rev-parse", "--verify", "HEAD^{tree}"]).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree)) {
    throw new Error("git returned invalid source commit or tree identifiers");
  }
  const expected = process.env.GITHUB_SHA?.trim().toLowerCase();
  if (expected && (!/^[0-9a-f]{40}$/.test(expected) || expected !== commit)) {
    throw new Error(`GITHUB_SHA does not match the checked-out commit (${expected} != ${commit})`);
  }
  return { commit, tree };
}

function sha256(path: string): string {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Release archive must be a regular non-symbolic file");
  if (stat.size > 512 * 1024 * 1024) throw new Error("Release archive exceeds the 512 MiB private-alpha limit");
  const hash = createHash("sha256");
  const descriptor = openSync(path, "r");
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const count = readSync(descriptor, chunk, 0, chunk.byteLength, null);
      if (count === 0) break;
      hash.update(chunk.subarray(0, count));
    }
  } finally {
    closeSync(descriptor);
  }
  return hash.digest("hex");
}

function treeSha256(root: string): string {
  const hash = createHash("sha256");
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) throw new Error(`Generated GUI contains a symbolic link: ${path}`);
      const relativePath = relative(root, path).replaceAll("\\", "/");
      hash.update(`${stat.isDirectory() ? "d" : "f"}\0${relativePath}\0`);
      if (stat.isDirectory()) visit(path);
      else if (stat.isFile()) hash.update(readFileSync(path));
      else throw new Error(`Generated GUI contains a non-regular entry: ${path}`);
    }
  };
  visit(root);
  return hash.digest("hex");
}

function buildGui(): void {
  const result = Bun.spawnSync([process.execPath, "run", "--cwd", "gui", "build"], {
    cwd: ROOT,
    stdout: "inherit",
    stderr: "inherit",
    windowsHide: true,
  });
  if (result.exitCode !== 0) throw new Error("CoCodex GUI production build failed");
}

function packCommand(explicit?: string): string {
  const command = explicit
    ? resolve(explicit)
    : Bun.which(process.platform === "win32" ? "npm.cmd" : "npm")
      ?? Bun.which("npm");
  if (!command || !existsSync(command) || !lstatSync(command).isFile()) {
    throw new Error("npm is required to create the private-alpha archive; pass --pack-command PATH when it is not on PATH");
  }
  if (!/^npm(?:\.cmd)?$/i.test(basename(command))) throw new Error("The private-alpha pack command must be npm");
  return command;
}

export function assertShrinkwrap(manifest: Record<string, any>, version: string): void {
  if (!existsSync(SHRINKWRAP_SOURCE) || !lstatSync(SHRINKWRAP_SOURCE).isFile()) {
    throw new Error("The committed private-alpha npm-shrinkwrap.json is missing");
  }
  const lock = JSON.parse(readFileSync(SHRINKWRAP_SOURCE, "utf8")) as {
    name?: unknown;
    version?: unknown;
    lockfileVersion?: unknown;
    packages?: Record<string, Record<string, any>>;
  };
  if (lock.name !== DISTRIBUTION_NAME || lock.version !== version || lock.lockfileVersion !== 3) {
    throw new Error("The private-alpha shrinkwrap identity/version is stale");
  }
  const root = lock.packages?.[""];
  if (!root || root.name !== DISTRIBUTION_NAME || root.version !== version) {
    throw new Error("The private-alpha shrinkwrap root package is invalid");
  }
  if (JSON.stringify(root.dependencies) !== JSON.stringify(manifest.dependencies)) {
    throw new Error("The private-alpha shrinkwrap dependencies do not match the release manifest");
  }
  const bunPackages = new Map<string, string>();
  for (const line of readFileSync(resolve(ROOT, "bun.lock"), "utf8").split(/\r?\n/)) {
    const resolved = line.match(/:\s*\[\s*"([^"]+)"/)?.[1];
    const packageMatch = resolved?.match(/^(.+)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/);
    const integrity = line.match(/"(sha512-[A-Za-z0-9+/]+={0,2})"\],?\s*$/)?.[1];
    if (packageMatch && integrity) {
      bunPackages.set(`${packageMatch[1]}@${packageMatch[2]}`, integrity);
    }
  }
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (!path) continue;
    if (entry.link === true) throw new Error(`Shrinkwrap contains a linked dependency: ${path}`);
    if (typeof entry.version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(entry.version)) {
      throw new Error(`Shrinkwrap contains a non-exact dependency version: ${path}`);
    }
    if (typeof entry.resolved !== "string" || !entry.resolved.startsWith("https://registry.npmjs.org/")) {
      throw new Error(`Shrinkwrap contains a non-registry dependency: ${path}`);
    }
    if (typeof entry.integrity !== "string" || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(entry.integrity)) {
      throw new Error(`Shrinkwrap dependency is missing SHA-512 integrity: ${path}`);
    }
    if (entry.hasInstallScript === true && path !== "node_modules/bun") {
      throw new Error(`Shrinkwrap contains an unapproved lifecycle script: ${path}`);
    }
    const dependencyName = path.split("node_modules/").at(-1);
    const bunIntegrity = bunPackages.get(`${dependencyName}@${entry.version}`);
    if (!bunIntegrity || bunIntegrity !== entry.integrity) {
      throw new Error(`Shrinkwrap dependency does not match bun.lock: ${path}@${entry.version}`);
    }
  }
}

function createOutputDirectory(raw: string | undefined, version: string): string {
  const output = resolve(raw ?? join(ROOT, "dist", "private-alpha", version));
  if (existsSync(output)) {
    throw new Error(`Release output already exists; choose a new --output directory: ${output}`);
  }
  mkdirSync(output, { recursive: true });
  return output;
}

function safeRemoveStage(stage: string, expectedParent: string): void {
  const absolute = resolve(stage);
  const parent = resolve(expectedParent);
  const rel = relative(parent, absolute);
  if (!rel || rel.startsWith("..") || resolve(parent, rel) !== absolute) {
    throw new Error("Refusing to remove a staging path outside the generated temporary root");
  }
  rmSync(absolute, { recursive: true, force: true });
}

export function buildPrivateAlphaPackage(outputOption?: string): {
  output: string;
  archive: string;
  sha256: string;
  version: string;
} {
  const initialProvenance = sourceProvenance();
  buildGui();
  const provenance = sourceProvenance();
  if (
    provenance.commit !== initialProvenance.commit
    || provenance.tree !== initialProvenance.tree
  ) {
    throw new Error("Source provenance changed while building the private-alpha GUI");
  }
  const guiRoot = resolve(ROOT, "gui", "dist");
  if (!existsSync(resolve(guiRoot, "index.html"))) throw new Error("GUI production build is missing");
  const guiDigest = treeSha256(guiRoot);
  const version = packageVersion();
  const output = createOutputDirectory(outputOption, version);
  const tempParent = mkdtempSync(join(tmpdir(), "cocodex-private-alpha-"));
  const stage = join(tempParent, "package");
  mkdirSync(stage);
  let completed = false;
  try {
    for (const path of COPY_PATHS) copyReleaseInput(stage, path);
    const sourcePackage = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")) as Record<string, any>;
    const manifest = privateAlphaPackageJson(sourcePackage, version);
    assertShrinkwrap(manifest, version);
    writeFileSync(join(stage, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    copyFileSync(SHRINKWRAP_SOURCE, join(stage, "npm-shrinkwrap.json"));

    const packer = packCommand(option("--pack-command"));
    const packed = Bun.spawnSync([packer, "pack", stage, "--pack-destination", output, "--ignore-scripts", "--json"], {
      cwd: ROOT,
      stdout: "pipe",
      stderr: "pipe",
      windowsHide: true,
    });
    if (packed.exitCode !== 0) {
      throw new Error(`npm pack failed: ${Buffer.from(packed.stderr).toString("utf8").trim()}`);
    }
    const result = JSON.parse(Buffer.from(packed.stdout).toString("utf8")) as
      | Array<{ filename?: unknown }>
      | { filename?: unknown };
    const packedFilename = Array.isArray(result) ? result[0]?.filename : result.filename;
    if (typeof packedFilename !== "string" || !packedFilename.endsWith(".tgz")) {
      throw new Error("npm pack returned an invalid archive filename");
    }
    const archive = isAbsolute(packedFilename) ? resolve(packedFilename) : resolve(output, packedFilename);
    const archiveRelative = relative(output, archive);
    if (!archiveRelative || archiveRelative.startsWith("..") || resolve(output, archiveRelative) !== archive) {
      throw new Error("Package manager wrote the archive outside the release output directory");
    }
    const filename = basename(archive);
    if (!existsSync(archive) || !statSync(archive).isFile()) throw new Error("npm pack did not create the release archive");
    const digest = sha256(archive);
    const installer = resolve(output, "Install-CoCodex.ps1");
    const releaseManifest = resolve(output, "RELEASE.json");
    copyFileSync(resolve(ROOT, "scripts", "Install-CoCodex.ps1"), installer);
    writeFileSync(releaseManifest, `${JSON.stringify({
      product: "CoCodex",
      channel: "private-alpha",
      version,
      packageName: DISTRIBUTION_NAME,
      archive: filename,
      sha256: digest,
      sourceCommit: provenance.commit,
      sourceTree: provenance.tree,
      guiSha256: guiDigest,
      shrinkwrapSha256: sha256(SHRINKWRAP_SOURCE),
      builtAt: new Date().toISOString(),
      requiredNodeVersion: "22.12.0",
      requiredNpmMajor: 10,
      commands: ["cocodex", "ccx", "cocodex-server", "ccx-server", "ocx"],
      statePreservedAcrossUpdates: [
        "~/.cocodex",
        "~/.cocodex-server",
        "~/.opencodex",
        "~/.codex",
      ],
    }, null, 2)}\n`, "utf8");
    writeFileSync(resolve(output, "SHA256SUMS.txt"), [
      `${digest} *${filename}`,
      `${sha256(releaseManifest)} *${basename(releaseManifest)}`,
      `${sha256(installer)} *${basename(installer)}`,
      "",
    ].join("\n"), "utf8");
    completed = true;
    return { output, archive, sha256: digest, version };
  } finally {
    safeRemoveStage(stage, tempParent);
    safeRemoveStage(tempParent, tmpdir());
    if (!completed && existsSync(output)) safeRemoveStage(output, dirname(output));
  }
}

if (import.meta.main) {
  const result = buildPrivateAlphaPackage(option("--output"));
  console.log(JSON.stringify(result, null, 2));
}
