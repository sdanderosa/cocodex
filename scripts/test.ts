import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface IsolatedTestEnvironment {
  root: string;
  env: Record<string, string | undefined>;
  cleanup(): void;
}

const SAFE_TEST_ENVIRONMENT_KEYS = new Set([
  "APPDATA",
  "CI",
  "COLORTERM",
  "COMSPEC",
  "FORCE_COLOR",
  "LANG",
  "LC_ALL",
  "LOCALAPPDATA",
  "NO_COLOR",
  "NUMBER_OF_PROCESSORS",
  "OS",
  "PATH",
  "PATHEXT",
  "PROCESSOR_ARCHITECTURE",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TERM",
  "TMP",
  "TMPDIR",
  "TZ",
  "WINDIR",
]);

export function sanitizedTestEnvironment(
  source: Record<string, string | undefined>,
): Record<string, string> {
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined) continue;
    const upper = key.toUpperCase();
    if (
      SAFE_TEST_ENVIRONMENT_KEYS.has(upper)
      || upper.startsWith("BUN_")
      || upper.startsWith("OCX_TEST_")
    ) {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

export function testTimeoutArgs(
  env: Record<string, string | undefined> = process.env,
): string[] {
  const raw = env.OCX_TEST_TIMEOUT_MS?.trim();
  if (!raw) return [];
  const timeout = Number(raw);
  if (!Number.isSafeInteger(timeout) || timeout < 1) {
    throw new Error(`OCX_TEST_TIMEOUT_MS must be a positive integer; received ${raw}`);
  }
  return ["--timeout", String(timeout)];
}

export function createIsolatedTestEnvironment(
  baseEnv: Record<string, string | undefined> = process.env,
): IsolatedTestEnvironment {
  const root = mkdtempSync(join(tmpdir(), "opencodex-test-"));
  const opencodexHome = join(root, ".opencodex");
  const codexHome = join(root, ".codex");
  mkdirSync(opencodexHome, { recursive: true });
  mkdirSync(codexHome, { recursive: true });

  return {
    root,
    env: {
      ...sanitizedTestEnvironment(baseEnv),
      HOME: root,
      USERPROFILE: root,
      OPENCODEX_HOME: opencodexHome,
      CODEX_HOME: codexHome,
    },
    cleanup() {
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
  };
}

if (import.meta.main) {
  const isolated = createIsolatedTestEnvironment();
  try {
    const requestedTests = process.argv.slice(2);
    const child = Bun.spawnSync(
      [
        process.execPath,
        "test",
        "--isolate",
        ...testTimeoutArgs(isolated.env),
        ...(requestedTests.length > 0 ? requestedTests : ["./tests/"]),
      ],
      {
        env: isolated.env,
        stdin: "inherit",
        stdout: "inherit",
        stderr: "inherit",
      },
    );
    process.exitCode = child.exitCode ?? 1;
  } finally {
    isolated.cleanup();
  }
}
