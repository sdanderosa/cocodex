#!/usr/bin/env bun
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { privateAlphaPackageJson } from "./build-cocodex-private-alpha";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DESTINATION = resolve(ROOT, "scripts", "private-alpha", "npm-shrinkwrap.json");

function bunLockOverrides(): Record<string, string> {
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

function option(name: string): string | undefined {
  const index = Bun.argv.indexOf(name);
  return index >= 0 ? Bun.argv[index + 1] : undefined;
}

function npmCommand(): string {
  const explicit = option("--npm-command");
  const command = explicit
    ? resolve(explicit)
    : Bun.which(process.platform === "win32" ? "npm.cmd" : "npm") ?? Bun.which("npm");
  if (!command || !existsSync(command) || !lstatSync(command).isFile() || !/^npm(?:\.cmd)?$/i.test(basename(command))) {
    throw new Error("npm is required to regenerate the private-alpha shrinkwrap; pass --npm-command PATH");
  }
  return command;
}

const source = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")) as Record<string, any>;
const manifest = privateAlphaPackageJson(source);
manifest.overrides = { ...(manifest.overrides ?? {}), ...bunLockOverrides() };
const temporary = mkdtempSync(resolve(tmpdir(), "cocodex-shrinkwrap-"));

try {
  writeFileSync(resolve(temporary, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const generated = Bun.spawnSync([
    npmCommand(),
    "install",
    "--package-lock-only",
    "--ignore-scripts",
    "--omit=dev",
    "--no-audit",
    "--no-fund",
  ], {
    cwd: temporary,
    stdout: "inherit",
    stderr: "inherit",
    windowsHide: true,
  });
  if (generated.exitCode !== 0) throw new Error("npm failed to resolve the private-alpha dependency graph");

  const lock = JSON.parse(readFileSync(resolve(temporary, "package-lock.json"), "utf8")) as Record<string, any>;
  lock.name = manifest.name;
  lock.version = manifest.version;
  if (lock.packages?.[""]) {
    lock.packages[""].name = manifest.name;
    lock.packages[""].version = manifest.version;
  }
  mkdirSync(dirname(DESTINATION), { recursive: true });
  writeFileSync(DESTINATION, `${JSON.stringify(lock, null, 2)}\n`, "utf8");
  console.log(`Updated ${DESTINATION}`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
