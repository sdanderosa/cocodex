import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";

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
  "PSMODULEPATH",
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

function validatedWindowsProfile(source: Record<string, string | undefined>): string | undefined {
  const candidate = (
    source.OCX_TEST_ISOLATED_ENV === "1"
      ? source.OCX_TEST_WINDOWS_USERPROFILE
      : source.USERPROFILE
  )?.trim();
  return candidate
    && win32.isAbsolute(candidate)
    && !/[\u0000-\u001f]/.test(candidate)
    ? candidate
    : undefined;
}

export function isolatedWorkerEnvironment(
  source: Record<string, string | undefined>,
): Record<string, string> {
  const sanitized = sanitizedTestEnvironment(source);
  const profile = process.platform === "win32" ? validatedWindowsProfile(source) : undefined;
  if (profile) {
    sanitized.OCX_TEST_ISOLATED_ENV = "1";
    sanitized.OCX_TEST_WINDOWS_USERPROFILE = profile;
  }
  return sanitized;
}

export function windowsTestProcessEnvironment(
  source: Record<string, string | undefined> = process.env,
): Record<string, string | undefined> {
  const child = { ...source };
  const profile = process.platform === "win32" && source.OCX_TEST_ISOLATED_ENV === "1"
    ? validatedWindowsProfile(source)
    : undefined;
  delete child.OCX_TEST_ISOLATED_ENV;
  delete child.OCX_TEST_WINDOWS_USERPROFILE;
  if (!profile) return child;
  const parsed = win32.parse(profile);
  child.USERPROFILE = profile;
  child.HOME = profile;
  child.HOMEDRIVE = parsed.root.slice(0, 2);
  child.HOMEPATH = profile.slice(2) || "\\";
  return child;
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
  const originalWindowsProfile = process.platform === "win32"
    ? validatedWindowsProfile(baseEnv)
    : undefined;
  const windowsProfileBridge = originalWindowsProfile
    ? {
        OCX_TEST_ISOLATED_ENV: "1",
        OCX_TEST_WINDOWS_USERPROFILE: originalWindowsProfile,
      }
    : {};

  return {
    root,
    env: {
      ...sanitizedTestEnvironment(baseEnv),
      ...windowsProfileBridge,
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
