import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const roots: string[] = [];
const children: Bun.Subprocess[] = [];

afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null) child.kill();
    await child.exited;
  }
  for (const root of roots.splice(0)) {
    const absolute = resolve(root);
    if (!absolute.startsWith(resolve(tmpdir()))) throw new Error(`Refusing to remove non-temporary path: ${absolute}`);
    rmSync(absolute, { recursive: true, force: true });
  }
});

function reservePort(): number {
  const reservation = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() });
  const port = reservation.port;
  reservation.stop(true);
  if (port === undefined) throw new Error("Bun did not allocate a test port");
  return port;
}

async function readReadyLine(child: Bun.Subprocess<"ignore", "pipe", "pipe">): Promise<Record<string, unknown>> {
  const reader = child.stdout.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    const result = await Promise.race([
      reader.read(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Server readiness timed out")), remaining)),
    ]);
    if (result.done) throw new Error(`Server exited before readiness with code ${await child.exited}`);
    buffered += decoder.decode(result.value, { stream: true });
    const newline = buffered.indexOf("\n");
    if (newline >= 0) return JSON.parse(buffered.slice(0, newline));
  }
  throw new Error("Server readiness timed out");
}

describe("standalone CoCodex Server process", () => {
  test("initializes, runs independently, serves TLS health, and shuts down", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-process-"));
    roots.push(root);
    const port = reservePort();
    const cli = join(import.meta.dir, "..", "src", "cli.ts");
    const init = Bun.spawn([
      process.execPath,
      cli,
      "init",
      "--public-host",
      "127.0.0.1",
      "--port",
      String(port),
      "--state-root",
      root,
    ], { stdout: "pipe", stderr: "pipe" });
    expect(await init.exited).toBe(0);

    const child = Bun.spawn([
      process.execPath,
      cli,
      "start",
      "--state-root",
      root,
    ], { stdout: "pipe", stderr: "pipe" });
    children.push(child);
    const ready = await readReadyLine(child);
    expect(ready.ready).toBeTrue();
    expect(ready.port).toBe(port);

    const health = await fetch(`https://127.0.0.1:${port}/healthz`, {
      tls: { rejectUnauthorized: false },
    });
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true, service: "cocodex-server", protocol: 1 });

    child.kill();
    expect(await child.exited).toBe(143);
  }, 20_000);
});
