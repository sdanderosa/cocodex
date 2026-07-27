import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  createIsolatedTestEnvironment,
  isolatedWorkerEnvironment,
  sanitizedTestEnvironment,
  testTimeoutArgs,
  windowsTestProcessEnvironment,
} from "../scripts/test";
import {
  batchItems,
  discoverRootTests,
  spawnWithTreeTimeout,
} from "../scripts/test-batched";
import { isProcessAlive, killProxy } from "../src/lib/process-control";

describe("test runner isolation", () => {
  test("redirects user homes to a disposable root", () => {
    const topLevel = {
      PATH: "/test/bin",
      HOME: "/real/home",
      USERPROFILE: "C:\\Users\\real-profile",
    };
    const worker = isolatedWorkerEnvironment(topLevel);
    const isolated = createIsolatedTestEnvironment(worker);
    try {
      expect(isolated.env).toMatchObject({
        PATH: "/test/bin",
        HOME: isolated.root,
        USERPROFILE: isolated.root,
        OPENCODEX_HOME: join(isolated.root, ".opencodex"),
        CODEX_HOME: join(isolated.root, ".codex"),
      });
      expect(isolated.env.OCX_TEST_WINDOWS_USERPROFILE).toBe(
        process.platform === "win32" ? "C:\\Users\\real-profile" : undefined,
      );
      expect(isolated.env.OCX_TEST_ISOLATED_ENV).toBe(
        process.platform === "win32" ? "1" : undefined,
      );
      expect(existsSync(isolated.env.OPENCODEX_HOME!)).toBe(true);
      expect(existsSync(isolated.env.CODEX_HOME!)).toBe(true);
    } finally {
      isolated.cleanup();
    }
    expect(existsSync(isolated.root)).toBe(false);
  });

  test("restores the real profile only for explicit Windows subprocess tests", () => {
    const child = windowsTestProcessEnvironment({
      USERPROFILE: "C:\\isolated-test-home",
      HOME: "C:\\isolated-test-home",
      OCX_TEST_ISOLATED_ENV: "1",
      OCX_TEST_WINDOWS_USERPROFILE: "C:\\Users\\runneradmin",
    });
    expect(child.OCX_TEST_ISOLATED_ENV).toBeUndefined();
    expect(child.OCX_TEST_WINDOWS_USERPROFILE).toBeUndefined();
    expect(child).toMatchObject(process.platform === "win32" ? {
      USERPROFILE: "C:\\Users\\runneradmin",
      HOME: "C:\\Users\\runneradmin",
      HOMEDRIVE: "C:",
      HOMEPATH: "\\Users\\runneradmin",
    } : {
      USERPROFILE: "C:\\isolated-test-home",
      HOME: "C:\\isolated-test-home",
    });
  });

  test("partitions every inherited test exactly once", () => {
    const files = Array.from({ length: 23 }, (_, index) => `test-${index}`);
    const batches = batchItems(files, 10);

    expect(batches.map((batch) => batch.length)).toEqual([10, 10, 3]);
    expect(batches.flat()).toEqual(files);
    expect(() => batchItems(files, 0)).toThrow("positive integer");
  });

  test("discovers nested inherited tests exactly once", () => {
    const isolated = createIsolatedTestEnvironment();
    try {
      mkdirSync(join(isolated.root, "nested"), { recursive: true });
      writeFileSync(join(isolated.root, "root.test.ts"), "");
      writeFileSync(join(isolated.root, "nested", "child.test.ts"), "");
      writeFileSync(join(isolated.root, "nested", "fixture.ts"), "");

      expect(discoverRootTests(isolated.root)).toEqual([
        "./tests/nested/child.test.ts",
        "./tests/root.test.ts",
      ]);
    } finally {
      isolated.cleanup();
    }
  });

  test("does not expose ambient credentials to test children", () => {
    expect(sanitizedTestEnvironment({
      PATH: "/test/bin",
      OPENAI_API_KEY: "real-secret",
      AWS_SECRET_ACCESS_KEY: "real-secret",
      HTTPS_PROXY: "http://user:password@example.test",
      OCX_TEST_TIMEOUT_MS: "120000",
    })).toEqual({
      PATH: "/test/bin",
      OCX_TEST_TIMEOUT_MS: "120000",
    });
  });

  test("timeout terminates an owned descendant process tree", async () => {
    const isolated = createIsolatedTestEnvironment();
    const pidPath = join(isolated.root, "grandchild.pid");
    let grandchildPid = 0;
    try {
      const parentSource = [
        `const child = Bun.spawn([process.execPath, "-e", "await Bun.sleep(30000)"]);`,
        `await Bun.write(${JSON.stringify(pidPath)}, String(child.pid));`,
        "await Bun.sleep(30000);",
      ].join("\n");
      const outcome = await spawnWithTreeTimeout(
        [process.execPath, "-e", parentSource],
        {
          env: isolated.env,
          stdin: "ignore",
          stdout: "ignore",
          stderr: "ignore",
        },
        1_000,
      );

      expect(outcome.timedOut).toBe(true);
      grandchildPid = Number(readFileSync(pidPath, "utf8"));
      expect(Number.isSafeInteger(grandchildPid)).toBe(true);
      expect(isProcessAlive(grandchildPid)).toBe(false);
    } finally {
      if (grandchildPid > 0 && isProcessAlive(grandchildPid)) killProxy(grandchildPid);
      isolated.cleanup();
    }
  }, 15_000);

  test("adds only a validated explicit test timeout", () => {
    expect(testTimeoutArgs({})).toEqual([]);
    expect(testTimeoutArgs({ OCX_TEST_TIMEOUT_MS: "120000" })).toEqual([
      "--timeout",
      "120000",
    ]);
    expect(() => testTimeoutArgs({ OCX_TEST_TIMEOUT_MS: "0" })).toThrow(
      "positive integer",
    );
  });
});
