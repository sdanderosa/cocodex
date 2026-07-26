import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  createIsolatedTestEnvironment,
  sanitizedTestEnvironment,
  testTimeoutArgs,
} from "../scripts/test";
import {
  batchItems,
  discoverRootTests,
  spawnWithTreeTimeout,
} from "../scripts/test-batched";
import { isProcessAlive, killProxy } from "../src/lib/process-control";

describe("test runner isolation", () => {
  test("redirects user homes to a disposable root", () => {
    const isolated = createIsolatedTestEnvironment({ PATH: "/test/bin", HOME: "/real/home" });
    try {
      expect(isolated.env).toMatchObject({
        PATH: "/test/bin",
        HOME: isolated.root,
        USERPROFILE: isolated.root,
        OPENCODEX_HOME: join(isolated.root, ".opencodex"),
        CODEX_HOME: join(isolated.root, ".codex"),
      });
      expect(existsSync(isolated.env.OPENCODEX_HOME!)).toBe(true);
      expect(existsSync(isolated.env.CODEX_HOME!)).toBe(true);
    } finally {
      isolated.cleanup();
    }
    expect(existsSync(isolated.root)).toBe(false);
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
