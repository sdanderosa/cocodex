import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function reservePort(): number {
  const listener = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: { data() {} },
  });
  const port = listener.port;
  listener.stop(true);
  return port;
}

async function waitForHealth(port: number): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(`https://127.0.0.1:${port}/healthz`, {
        tls: { rejectUnauthorized: false },
      });
      if (response.ok) return response;
    } catch (error) {
      lastError = error;
    }
    await Bun.sleep(20);
  }
  throw lastError ?? new Error("Server did not become healthy");
}

test("the separate server process initializes, serves TLS, and restarts after termination", async () => {
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
  expect(await new Response(init.stdout).text()).toContain('"initialized":true');

  const start = () => Bun.spawn([
    process.execPath,
    cli,
    "start",
    "--state-root",
    root,
  ], { stdout: "pipe", stderr: "pipe" });

  const first = start();
  const firstHealth = await waitForHealth(port);
  expect(await firstHealth.json()).toEqual({ ok: true, service: "cocodex-server", protocol: 1 });
  first.kill(9);
  await first.exited;

  const second = start();
  try {
    const secondHealth = await waitForHealth(port);
    expect(secondHealth.status).toBe(200);
  } finally {
    second.kill(9);
    await second.exited;
  }
});
