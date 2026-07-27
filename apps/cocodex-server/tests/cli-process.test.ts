import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

async function runCli(
  cli: string,
  args: string[],
  environment?: Record<string, string | undefined>,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const child = Bun.spawn([process.execPath, cli, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    ...(environment ? { env: environment } : {}),
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  return { exitCode, stdout: stdout.trim(), stderr: stderr.trim() };
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
  const initializedStatus = await runCli(cli, ["status", "--state-root", root]);
  expect(initializedStatus.exitCode).toBe(0);
  expect(JSON.parse(initializedStatus.stdout)).toMatchObject({
    initialized: true,
    running: false,
    port,
    database: {
      health: "ok",
      quickCheck: "ok",
      foreignKeyViolations: 0,
      counts: {
        devices: { pending: 0, approved: 0, revoked: 0 },
        projects: 0,
        privateCiphertexts: 0,
      },
    },
  });

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
    const runningStatus = await runCli(cli, ["status", "--state-root", root]);
    expect(JSON.parse(runningStatus.stdout)).toMatchObject({ initialized: true, running: true });
  } finally {
    const stopped = await runCli(cli, ["stop", "--state-root", root]);
    expect(stopped.exitCode).toBe(0);
    await second.exited;
  }
}, 20_000);

test("the CLI creates a protected complete backup and restores an empty Server root", async () => {
  const root = mkdtempSync(join(tmpdir(), "cocodex-cli-recovery-"));
  roots.push(root);
  const sourceRoot = join(root, "source");
  const destinationRoot = join(root, "destination");
  const backupPath = join(root, "complete-recovery.json");
  const passphrasePath = join(root, "passphrase.txt");
  const port = reservePort();
  const cli = join(import.meta.dir, "..", "src", "cli.ts");
  writeFileSync(passphrasePath, "correct horse battery staple\n", { mode: 0o600 });
  const initialized = await runCli(cli, [
    "init",
    "--public-host", "127.0.0.1",
    "--port", String(port),
    "--state-root", sourceRoot,
  ], { ...process.env, COCODEX_DISABLE_PORT_MAPPING: "1" });
  expect(initialized.exitCode).toBe(0);

  const missingPassphrase = await runCli(cli, [
    "backup", "--output", backupPath, "--state-root", sourceRoot,
  ]);
  expect(missingPassphrase.exitCode).not.toBe(0);
  expect(missingPassphrase.stderr).toContain("COCODEX_BACKUP_PASSPHRASE");

  const backedUp = await runCli(cli, [
    "backup",
    "--output", backupPath,
    "--passphrase-file", passphrasePath,
    "--state-root", sourceRoot,
  ]);
  expect(backedUp.exitCode).toBe(0);
  const backupResult = JSON.parse(backedUp.stdout);
  const sourceFingerprint = backupResult.serverFingerprint;
  expect(typeof sourceFingerprint).toBe("string");
  expect(sourceFingerprint.length).toBeGreaterThanOrEqual(32);
  expect(backupResult).toMatchObject({
    backedUp: true,
    encrypted: true,
    completeServerState: true,
    serverFingerprint: sourceFingerprint,
    serverEpoch: 1,
  });
  const serialized = readFileSync(backupPath, "utf8");
  expect(serialized).not.toContain("PRIVATE KEY");
  expect(serialized).not.toContain(sourceRoot);

  const restored = await runCli(cli, [
    "restore",
    "--input", backupPath,
    "--passphrase-file", passphrasePath,
    "--state-root", destinationRoot,
  ]);
  expect(restored.exitCode).toBe(0);
  expect(JSON.parse(restored.stdout)).toMatchObject({
    restored: true,
    encrypted: true,
    completeServerState: true,
    serverFingerprint: sourceFingerprint,
    serverEpoch: 1,
    rollbackPath: null,
  });
  const status = await runCli(cli, ["status", "--state-root", destinationRoot]);
  expect(status.exitCode).toBe(0);
  expect(JSON.parse(status.stdout)).toMatchObject({
    initialized: true,
    running: false,
    publicHost: "127.0.0.1",
    port,
    authority: "active",
  });

  const server = Bun.spawn([
    process.execPath, cli, "start", "--state-root", destinationRoot,
  ], { stdout: "pipe", stderr: "pipe" });
  try {
    expect((await waitForHealth(port)).status).toBe(200);
  } finally {
    const stopped = await runCli(cli, ["stop", "--state-root", destinationRoot]);
    expect(stopped.exitCode).toBe(0);
    await server.exited;
  }
}, 30_000);
