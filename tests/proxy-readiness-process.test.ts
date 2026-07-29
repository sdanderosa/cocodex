import { createServer } from "node:net";
import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function unusedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  if (!port) throw new Error("failed to allocate test port");
  return port;
}

async function runReadiness(auth: object | null): Promise<{ status: number; body: Record<string, unknown> }> {
  const root = join(import.meta.dir, `.tmp-readyz-process-${process.pid}-${randomUUID()}`);
  roots.push(root);
  const opencodexHome = join(root, "opencodex");
  const codexHome = join(root, "codex");
  mkdirSync(opencodexHome, { recursive: true });
  mkdirSync(codexHome, { recursive: true });
  const port = await unusedPort();
  writeFileSync(join(opencodexHome, "config.json"), JSON.stringify({
    port,
    hostname: "127.0.0.1",
    openaiProviderTierVersion: 2,
    providers: {
      openai: {
        adapter: "openai-responses",
        baseUrl: "https://chatgpt.com/backend-api/codex",
        authMode: "forward",
        codexAccountMode: "direct",
      },
    },
    defaultProvider: "openai",
  }));
  if (auth) writeFileSync(join(codexHome, "auth.json"), JSON.stringify(auth));

  const script = `
    const { startServer } = await import(${JSON.stringify(new URL("../src/server/index.ts", import.meta.url).href)});
    const server = startServer(${port});
    try {
      const response = await fetch("http://127.0.0.1:${port}/readyz");
      console.log(JSON.stringify({ status: response.status, body: await response.json() }));
    } finally {
      await server.stop(true);
    }
  `;
  const child = Bun.spawnSync([process.execPath, "-e", script], {
    cwd: join(import.meta.dir, ".."),
    env: {
      ...process.env,
      OPENCODEX_HOME: opencodexHome,
      CODEX_HOME: codexHome,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(child.exitCode).toBe(0);
  const line = child.stdout.toString().trim().split(/\r?\n/).at(-1) ?? "{}";
  return JSON.parse(line);
}

describe("process-level /readyz credential failures", () => {
  test("reports missing Direct credentials without claiming readiness", async () => {
    const result = await runReadiness(null);
    expect(result).toMatchObject({
      status: 503,
      body: {
        status: "not_ready",
        code: "credential_missing",
        checks: { proxy: true, configuration: true, provider: true, credentials: false },
      },
    });
  }, 30_000);

  test("reports an expired Direct credential without claiming readiness", async () => {
    const expiredPayload = Buffer.from(JSON.stringify({ exp: 1 })).toString("base64url");
    const result = await runReadiness({
      tokens: {
        access_token: `e30.${expiredPayload}.signature`,
        account_id: "expired-test-account",
      },
    });
    expect(result).toMatchObject({
      status: 503,
      body: {
        status: "not_ready",
        code: "credential_expired",
        checks: { proxy: true, configuration: true, provider: true, credentials: false },
      },
    });
  }, 30_000);
});
