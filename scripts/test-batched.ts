import { readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { killProxy } from "../src/lib/process-control";
import { createIsolatedTestEnvironment, isolatedWorkerEnvironment } from "./test";

export interface TestBatchFailure {
  batch: number;
  files: string[];
  exitCode: number | null;
  timedOut: boolean;
  signalCode?: string;
}

export function batchItems<T>(items: readonly T[], batchSize: number): T[][] {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
    throw new Error(`Batch size must be a positive integer; received ${batchSize}`);
  }

  const batches: T[][] = [];
  for (let offset = 0; offset < items.length; offset += batchSize) {
    batches.push(items.slice(offset, offset + batchSize));
  }
  return batches;
}

export function discoverRootTests(root = join(import.meta.dir, "..", "tests")): string[] {
  const discovered: string[] = [];
  const visit = (directory: string, relativeDirectory = ""): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const relativePath = relativeDirectory
        ? join(relativeDirectory, entry.name)
        : entry.name;
      if (entry.isDirectory()) {
        visit(join(directory, entry.name), relativePath);
      } else if (entry.isFile() && entry.name.endsWith(".test.ts")) {
        discovered.push(`./tests/${relativePath.replaceAll("\\", "/")}`);
      }
    }
  };
  visit(root);
  return discovered.sort((left, right) => left.localeCompare(right));
}

interface SpawnOutcome {
  success: boolean;
  exitCode: number | null;
  timedOut: boolean;
}

export async function spawnWithTreeTimeout(
  command: string[],
  options: Parameters<typeof Bun.spawn>[1],
  timeoutMs: number,
): Promise<SpawnOutcome> {
  const child = Bun.spawn(command, {
    ...options,
    detached: process.platform !== "win32",
  });
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const outcome = await Promise.race([
    child.exited.then((exitCode) => ({ exitCode, timedOut: false })),
    new Promise<{ exitCode: null; timedOut: true }>((resolve) => {
      timeout = setTimeout(() => resolve({ exitCode: null, timedOut: true }), timeoutMs);
    }),
  ]);
  if (timeout) clearTimeout(timeout);
  if (outcome.timedOut) {
    if (process.platform === "win32") {
      try {
        killProxy(child.pid);
      } catch {
        // Some constrained Windows runners deny taskkill even for owned children.
        // Bun's direct kill is still required so the harness itself cannot hang.
        if (child.exitCode === null) child.kill();
      }
    } else {
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {
        if (child.exitCode === null) child.kill("SIGTERM");
      }
      await Promise.race([child.exited, Bun.sleep(500)]);
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
      }
    }
    await child.exited;
  }
  return {
    success: !outcome.timedOut && outcome.exitCode === 0,
    exitCode: outcome.exitCode,
    timedOut: outcome.timedOut,
  };
}

function positiveIntegerFromEnv(name: string, fallback: number): number {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer; received ${raw}`);
  }
  return parsed;
}

export async function runRootTestsInBatches(
  files = discoverRootTests(),
  displayOffset = 0,
  displayTotal = files.length,
): Promise<TestBatchFailure[]> {
  const batchSize = positiveIntegerFromEnv("OCX_TEST_BATCH_SIZE", 1);
  const timeoutMs = positiveIntegerFromEnv("OCX_TEST_BATCH_TIMEOUT_MS", 300_000);
  const testTimeoutMs = positiveIntegerFromEnv("OCX_TEST_TIMEOUT_MS", 120_000);
  const batches = batchItems(files, batchSize);
  const failures: TestBatchFailure[] = [];

  console.log(
    `[test:batched] worker has ${files.length} files in ${batches.length} isolated batches `
      + `(size=${batchSize}, timeout=${timeoutMs}ms)`,
  );

  for (const [index, batch] of batches.entries()) {
    const batchNumber = displayOffset + index + 1;
    const first = batch[0]!;
    const last = batch.at(-1)!;
    console.log(
      `\n[test:batched] batch ${batchNumber}/${displayTotal}: `
        + `${first} .. ${last}`,
    );

    const isolated = createIsolatedTestEnvironment();
    let completed: SpawnOutcome;
    try {
      completed = await spawnWithTreeTimeout(
        [
          process.execPath,
          "test",
          "--isolate",
          "--timeout",
          String(testTimeoutMs),
          ...batch,
        ],
        {
          cwd: join(import.meta.dir, ".."),
          env: isolated.env,
          stdin: "inherit",
          stdout: "inherit",
          stderr: "inherit",
        },
        timeoutMs,
      );
    } finally {
      isolated.cleanup();
    }

    if (!completed.success) {
      failures.push({
        batch: batchNumber,
        files: batch,
        exitCode: completed.exitCode,
        timedOut: completed.timedOut,
      });
      console.error(
        `[test:batched] batch ${batchNumber} failed: exit=${completed.exitCode}`
          + `${completed.timedOut ? " timeout=true" : ""}`,
      );
    }
  }

  if (failures.length === 0) {
    console.log(`\n[test:batched] PASS: all ${files.length} files completed`);
  } else {
    console.error(
      `\n[test:batched] FAIL: ${failures.length}/${batches.length} batches failed`,
    );
    for (const failure of failures) {
      console.error(
        `[test:batched] batch ${failure.batch}: ${failure.files.join(", ")}`,
      );
    }
  }

  return failures;
}

if (import.meta.main) {
  try {
    const files = discoverRootTests();
    if (process.env.OCX_TEST_BATCH_WORKER === "1") {
      const start = positiveIntegerFromEnv("OCX_TEST_BATCH_START", 1) - 1;
      const end = positiveIntegerFromEnv("OCX_TEST_BATCH_END", files.length);
      if (start < 0 || end <= start || end > files.length) {
        throw new Error(
          `Invalid worker range ${start + 1}..${end} for ${files.length} files`,
        );
      }
      const failures = await runRootTestsInBatches(
        files.slice(start, end),
        start,
        files.length,
      );
      process.exitCode = failures.length === 0 ? 0 : 1;
    } else {
      const workerSize = positiveIntegerFromEnv("OCX_TEST_WORKER_SIZE", 25);
      const workerTimeoutMs = positiveIntegerFromEnv(
        "OCX_TEST_WORKER_TIMEOUT_MS",
        900_000,
      );
      const workerRanges = batchItems(files, workerSize);
      let failedWorkers = 0;
      let start = 0;

      console.log(
        `[test:batched] ${files.length} files across ${workerRanges.length} `
          + `fresh workers (worker size=${workerSize})`,
      );
      for (const [workerIndex, workerFiles] of workerRanges.entries()) {
        const end = start + workerFiles.length;
        console.log(
          `\n[test:batched] worker ${workerIndex + 1}/${workerRanges.length}: `
            + `files ${start + 1}..${end}`,
        );
        const result = await spawnWithTreeTimeout(
          [process.execPath, fileURLToPath(import.meta.url)],
          {
            cwd: join(import.meta.dir, ".."),
            env: {
              ...isolatedWorkerEnvironment(process.env),
              OCX_TEST_BATCH_WORKER: "1",
              OCX_TEST_BATCH_START: String(start + 1),
              OCX_TEST_BATCH_END: String(end),
            },
            stdin: "inherit",
            stdout: "inherit",
            stderr: "inherit",
          },
          workerTimeoutMs,
        );
        if (!result.success) {
          failedWorkers += 1;
          console.error(
            `[test:batched] worker ${workerIndex + 1} failed: `
              + `exit=${result.exitCode}`
              + `${result.timedOut ? " timeout=true" : ""}`,
          );
        }
        start = end;
      }

      if (failedWorkers === 0) {
        console.log(
          `\n[test:batched] PASS: all ${files.length} files completed across `
            + `${workerRanges.length} fresh workers`,
        );
        process.exitCode = 0;
      } else {
        console.error(
          `\n[test:batched] FAIL: ${failedWorkers}/${workerRanges.length} `
            + "workers failed",
        );
        process.exitCode = 1;
      }
    }
  } catch (error) {
    console.error(
      `[test:batched] ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exitCode = 1;
  }
}
