import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  buildTauriSidecar,
  buildTauriServerSidecar,
  detectTargetTriple,
  serverSidecarOutputPath,
  sidecarOutputPath,
} from "../scripts/build-tauri-sidecar";

const repoRoot = resolve(import.meta.dir, "..");
const temporaryRoot = join(
  repoRoot,
  "tests",
  `.tmp-tauri-sidecar-${process.pid}-${randomUUID()}`,
);

let child: Bun.Subprocess | undefined;
let baseUrl = "";
let codexConfigPath = "";
const nativeCodexConfig = 'model = "gpt-5.4"' + "\r\n";

async function waitForHealth(timeoutMs = 15_000): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  let lastError = "not started";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/healthz`, {
        signal: AbortSignal.timeout(1_000),
      });
      const body = await response.json() as Record<string, unknown>;
      if (response.ok && body.status === "ok" && body.service === "opencodex") return body;
      lastError = `${response.status}: ${JSON.stringify(body)}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await Bun.sleep(100);
  }
  throw new Error(`compiled desktop runtime did not become healthy: ${lastError}`);
}

describe("compiled CoCodex Tauri sidecar", () => {
  beforeAll(async () => {
    mkdirSync(temporaryRoot, { recursive: true });
    mkdirSync(join(temporaryRoot, "codex"), { recursive: true });
    mkdirSync(join(temporaryRoot, "cocodex", "runtime", "opencodex"), { recursive: true });
    codexConfigPath = join(temporaryRoot, "codex", "config.toml");
    writeFileSync(codexConfigPath, nativeCodexConfig, "utf8");
    const reservation = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => new Response("reserved"),
    });
    const port = reservation.port;
    await reservation.stop(true);
    baseUrl = `http://127.0.0.1:${port}`;

    await buildTauriSidecar();
    child = Bun.spawn(
      [sidecarOutputPath(detectTargetTriple()), "start", "--port", String(port)],
      {
        cwd: repoRoot,
        stdout: "pipe",
        stderr: "pipe",
        env: {
          ...process.env,
          OCX_SERVICE: "1",
          COCODEX_DESKTOP_MANAGED: "1",
          OPENCODEX_HOME: join(temporaryRoot, "cocodex", "runtime", "opencodex"),
          CODEX_HOME: join(temporaryRoot, "codex"),
          COCODEX_HOME: join(temporaryRoot, "cocodex"),
        },
      },
    );
  }, 60_000);

  afterAll(async () => {
    try {
      child?.kill();
      if (child) await child.exited;
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("serves health and the capability-protected API to the fixed Tauri origin", async () => {
    const health = await waitForHealth();
    const packageVersion = (JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as {
      version: string;
    }).version;
    expect(health.port).toBe(Number(new URL(baseUrl).port));
    expect(Number(health.pid)).toBe(child?.pid);
    expect(health.version).toBe(packageVersion);
    await Bun.sleep(300);
    expect(readFileSync(codexConfigPath, "utf8")).toBe(nativeCodexConfig);
    expect(existsSync(join(temporaryRoot, "cocodex", "runtime", "opencodex", "config.json"))).toBe(true);

    const origin = "tauri://localhost";
    const issued = await fetch(`${baseUrl}/api/cocodex/capability`, {
      signal: AbortSignal.timeout(5_000),
      headers: { Origin: origin, "Sec-Fetch-Site": "cross-site" },
    });
    expect(issued.status).toBe(200);
    expect(issued.headers.get("access-control-allow-origin")).toBe(origin);
    const capability = String((await issued.json() as { capability: string }).capability);
    expect(capability.length).toBeGreaterThan(32);

    const status = await fetch(`${baseUrl}/api/cocodex/status`, {
      signal: AbortSignal.timeout(5_000),
      headers: {
        Origin: origin,
        "X-CoCodex-Capability": capability,
      },
    });
    expect(status.status).toBe(200);
    expect(status.headers.get("access-control-allow-origin")).toBe(origin);
  }, 45_000);

  test("runs the bundled CoCodex Server as a separate executable and state root", async () => {
    await buildTauriServerSidecar();
    const serverRoot = join(temporaryRoot, "server");
    const result = Bun.spawnSync([
      serverSidecarOutputPath(detectTargetTriple()),
      "status",
      "--state-root",
      serverRoot,
    ], {
      cwd: repoRoot,
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout.toString())).toMatchObject({
      initialized: false,
      running: false,
      stateRoot: serverRoot,
      pid: null,
    });
    expect(existsSync(join(serverRoot, "config.json"))).toBe(false);
  });
});
