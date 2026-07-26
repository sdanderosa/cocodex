#!/usr/bin/env node
/**
 * CoCodex Client npm launcher.
 *
 * The published package includes Bun as a dependency, so `cocodex` and `ccx`
 * work after a normal npm install without requiring Bun on PATH.
 */
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const cliPath = join(here, "..", "src", "cocodex", "cli.ts");
const REAL_BUN_MIN_BYTES = 1_000_000;

function findBunBinary(bunDirectory) {
  for (const name of ["bun.exe", "bun"]) {
    const candidate = join(bunDirectory, "bin", name);
    if (existsSync(candidate) && statSync(candidate).size >= REAL_BUN_MIN_BYTES) {
      return candidate;
    }
  }
  return null;
}

function fail(message) {
  console.error(
    `CoCodex Client: ${message}\n` +
      "The installed Bun runtime is unavailable. Reinstall with lifecycle\n" +
      "scripts and optional dependencies enabled:\n" +
      "  npm install -g @bitkyc08/opencodex\n" +
      "If your package manager blocks dependency builds, explicitly approve bun.",
  );
  process.exit(1);
}

function resolveBun() {
  let bunDirectory;
  try {
    bunDirectory = dirname(require.resolve("bun/package.json"));
  } catch {
    fail("the `bun` dependency is not installed.");
  }

  let binary = findBunBinary(bunDirectory);
  if (binary) return binary;

  fail("the installed `bun` dependency does not contain a valid runtime binary.");
}

const child = spawn(resolveBun(), [cliPath, ...process.argv.slice(2)], {
  stdio: "inherit",
  windowsHide: true,
});

const forwardedSignals = process.platform === "win32"
  ? ["SIGINT", "SIGTERM"]
  : ["SIGINT", "SIGTERM", "SIGHUP"];
let terminationTimer;
const handlers = forwardedSignals.map(signal => {
  const handler = () => {
    try {
      child.kill(signal);
      terminationTimer ??= setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          // The child exited during the grace period.
        }
      }, 5_000);
      terminationTimer.unref();
    } catch {
      // The child already exited.
    }
  };
  process.on(signal, handler);
  return [signal, handler];
});
const clearHandlers = () => {
  if (terminationTimer) clearTimeout(terminationTimer);
  for (const [signal, handler] of handlers) process.removeListener(signal, handler);
};

child.on("error", error => {
  clearHandlers();
  console.error(`CoCodex Client: failed to launch Bun runtime: ${error.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  clearHandlers();
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
