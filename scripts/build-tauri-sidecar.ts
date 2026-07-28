import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");

export function parseRustHostTriple(output: string): string {
  const host = output
    .split(/\r?\n/)
    .find(line => line.startsWith("host:"))
    ?.slice("host:".length)
    .trim();
  if (!host) throw new Error("rustc did not report a host target triple");
  return validateTargetTriple(host);
}

export function validateTargetTriple(value: string): string {
  const triple = value.trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(triple)) {
    throw new Error(`invalid Rust target triple: ${JSON.stringify(value)}`);
  }
  return triple;
}

export function detectTargetTriple(): string {
  const configured = process.env.TAURI_ENV_TARGET_TRIPLE?.trim();
  if (configured) return validateTargetTriple(configured);

  // The inherited test runner intentionally replaces USERPROFILE with an
  // isolated state root and preserves the real Windows profile in this
  // OCX_TEST_* bridge. Toolchain discovery must not mistake test state for
  // the Rust installation.
  const windowsToolchainProfile = process.env.OCX_TEST_WINDOWS_USERPROFILE
    || process.env.USERPROFILE;
  const userCargoRustc = windowsToolchainProfile
    ? join(windowsToolchainProfile, ".cargo", "bin", "rustc.exe")
    : "";
  const rustc = process.env.RUSTC?.trim()
    || (userCargoRustc && existsSync(userCargoRustc) ? userCargoRustc : "rustc");
  const result = Bun.spawnSync([rustc, "-vV"], {
    cwd: repoRoot,
    stdout: "pipe",
    stderr: "pipe",
    env: windowsToolchainProfile
      ? {
          ...process.env,
          CARGO_HOME: process.env.CARGO_HOME || join(windowsToolchainProfile, ".cargo"),
          RUSTUP_HOME: process.env.RUSTUP_HOME || join(windowsToolchainProfile, ".rustup"),
        }
      : process.env,
  });
  if (result.exitCode !== 0) {
    const detail = result.stderr.toString().trim();
    throw new Error(`could not determine the Rust host target${detail ? `: ${detail}` : ""}`);
  }
  return parseRustHostTriple(result.stdout.toString());
}

export function sidecarOutputPath(targetTriple = detectTargetTriple()): string {
  const extension = targetTriple.includes("windows") ? ".exe" : "";
  return process.env.COCODEX_TAURI_SIDECAR_OUTPUT?.trim()
    ? resolve(process.env.COCODEX_TAURI_SIDECAR_OUTPUT)
    : resolve(repoRoot, "gui", "src-tauri", "binaries", `cocodex-runtime-${targetTriple}${extension}`);
}

export async function buildTauriSidecar(): Promise<string> {
  const output = sidecarOutputPath();
  const packageVersion = (JSON.parse(
    readFileSync(resolve(repoRoot, "package.json"), "utf8"),
  ) as { version: string }).version;
  mkdirSync(dirname(output), { recursive: true });

  const child = Bun.spawn(
    [
      process.execPath,
      "build",
      resolve(repoRoot, "src", "cli", "index.ts"),
      "--compile",
      "--define",
      `process.env.OPENCODEX_BUNDLED_VERSION=${JSON.stringify(packageVersion)}`,
      "--outfile",
      output,
    ],
    {
      cwd: repoRoot,
      stdout: "inherit",
      stderr: "inherit",
      env: {
        ...process.env,
        OCX_SERVICE: "1",
      },
    },
  );
  const exitCode = await child.exited;
  if (exitCode !== 0) {
    throw new Error(`failed to compile the CoCodex desktop runtime (exit ${exitCode})`);
  }
  return output;
}

if (import.meta.main) {
  const output = await buildTauriSidecar();
  console.log(`CoCodex desktop runtime: ${output}`);
}
