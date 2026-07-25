import { afterEach, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { openDatabase } from "../apps/cocodex-server/src/database";
import { approveDevice } from "../apps/cocodex-server/src/enrollment";
import { createInvitation } from "../apps/cocodex-server/src/invitations";
import { loadServerIdentity } from "../apps/cocodex-server/src/identity";
import { serverPaths } from "../apps/cocodex-server/src/paths";
import { createProject } from "../apps/cocodex-server/src/shared-state";
import { tlsCertificateFingerprint } from "../apps/cocodex-server/src/tls";
import {
  acceptServerAuthorityTransfer,
  connectAuthenticatedClient,
  enrollClient,
} from "../src/cocodex/client";
import { clientPaths } from "../src/cocodex/paths";

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

async function runCli(
  cli: string,
  args: string[],
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const child = Bun.spawn([process.execPath, cli, ...args], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stdout: stdout.trim(), stderr: stderr.trim() };
}

async function waitForHealth(port: number): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 150; attempt += 1) {
    try {
      const response = await fetch(`https://127.0.0.1:${port}/healthz`, {
        tls: { rejectUnauthorized: false },
      });
      if (response.ok) return;
    } catch (error) {
      lastError = error;
    }
    await Bun.sleep(20);
  }
  throw lastError ?? new Error(`Server on port ${port} did not become healthy`);
}

async function startServer(cli: string, root: string): Promise<Bun.Subprocess> {
  const child = Bun.spawn([
    process.execPath,
    cli,
    "start",
    "--state-root",
    root,
  ], { stdout: "pipe", stderr: "pipe" });
  children.push(child);
  const reader = child.stdout.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    const result = await Promise.race([
      reader.read(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Server readiness timed out")), remaining)),
    ]);
    if (result.done) {
      throw new Error(`Server exited before readiness with code ${await child.exited}`);
    }
    buffered += decoder.decode(result.value, { stream: true });
    const newline = buffered.indexOf("\n");
    if (newline >= 0) {
      const ready = JSON.parse(buffered.slice(0, newline)) as { ready?: boolean; port?: number };
      expect(ready.ready).toBeTrue();
      return child;
    }
  }
  throw new Error("Server readiness timed out");
}

async function nextFrame(socket: WebSocket, expectedType: string): Promise<Record<string, unknown>> {
  return await new Promise((resolveFrame, reject) => {
    const timeout = setTimeout(() => {
      socket.removeEventListener("message", onMessage);
      reject(new Error(`Timed out waiting for ${expectedType}`));
    }, 10_000);
    const onMessage = (event: MessageEvent) => {
      let frame: Record<string, unknown>;
      try { frame = JSON.parse(String(event.data)) as Record<string, unknown>; }
      catch { return; }
      if (frame.type !== expectedType) return;
      clearTimeout(timeout);
      socket.removeEventListener("message", onMessage);
      resolveFrame(frame);
    };
    socket.addEventListener("message", onMessage);
  });
}

test("hands a live server to a prepared process and reconnects a resident client", async () => {
  const sourceRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-source-process-"));
  const destinationRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-destination-process-"));
  const clientRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-client-process-"));
  roots.push(sourceRoot, destinationRoot, clientRoot);

  const sourcePort = reservePort();
  const destinationPort = reservePort();
  const cli = join(import.meta.dir, "..", "apps", "cocodex-server", "src", "cli.ts");
  const targetRequestPath = join(sourceRoot, "target-request.json");
  const transferPath = join(sourceRoot, "authority-transfer.json");
  const passphrasePath = join(sourceRoot, "transfer-passphrase.txt");
  writeFileSync(passphrasePath, "private-alpha-transfer-passphrase\n", { encoding: "utf8", mode: 0o600 });

  const initialized = await runCli(cli, [
    "init", "--public-host", "127.0.0.1", "--port", String(sourcePort), "--state-root", sourceRoot,
  ]);
  expect(initialized.exitCode).toBe(0);
  expect(JSON.parse(initialized.stdout)).toMatchObject({ initialized: true, port: sourcePort });

  const prepared = await runCli(cli, [
    "transfer-prepare",
    "--public-host", "127.0.0.1",
    "--port", String(destinationPort),
    "--output", targetRequestPath,
    "--state-root", destinationRoot,
  ]);
  expect(prepared.exitCode).toBe(0);
  expect(JSON.parse(prepared.stdout)).toMatchObject({ prepared: true, targetRequest: targetRequestPath });

  const sourcePaths = serverPaths(sourceRoot);
  const sourceIdentity = loadServerIdentity(sourcePaths);
  const sourceDatabase = openDatabase(sourcePaths.database);
  const invitation = createInvitation(sourceDatabase, {
    host: "127.0.0.1",
    port: sourcePort,
    serverFingerprint: tlsCertificateFingerprint(sourcePaths.tlsCertificate),
  });
  sourceDatabase.close();

  const source = await startServer(cli, sourceRoot);
  await waitForHealth(sourcePort);

  const kaiPaths = clientPaths(clientRoot);
  const connection = await enrollClient(invitation, "Kai", kaiPaths);
  const approvalDatabase = openDatabase(sourcePaths.database);
  const pending = approvalDatabase.query("SELECT fingerprint FROM devices WHERE id = ?")
    .get(connection.deviceId) as { fingerprint: string } | null;
  expect(pending?.fingerprint).toBeTruthy();
  expect(approveDevice(approvalDatabase, pending!.fingerprint)).toBeTrue();
  const project = createProject(approvalDatabase, "Transfer Alpha", connection.deviceId);
  approvalDatabase.close();

  const stopped = await runCli(cli, ["stop", "--state-root", sourceRoot]);
  expect(stopped.exitCode).toBe(0);
  await source.exited;

  const exported = await runCli(cli, [
    "transfer-export",
    "--target-request", targetRequestPath,
    "--output", transferPath,
    "--passphrase-file", passphrasePath,
    "--state-root", sourceRoot,
  ]);
  expect(exported.exitCode).toBe(0);
  const exportResult = JSON.parse(exported.stdout) as {
    authorityCode: string;
    sourceServerEpoch: number;
    targetServerEpoch: number;
  };
  expect(exportResult).toMatchObject({ sourceServerEpoch: 1, targetServerEpoch: 2 });
  expect(exportResult.authorityCode).toStartWith("ccx-transfer1.");

  const retired = JSON.parse((await runCli(cli, ["status", "--state-root", sourceRoot])).stdout) as Record<string, unknown>;
  expect(retired.authority).toBe("retired");
  const refused = await runCli(cli, ["start", "--state-root", sourceRoot]);
  expect(refused.exitCode).not.toBe(0);
  expect(refused.stderr).toContain("authority is retired");
  expect(existsSync(join(sourceRoot, "server.pid"))).toBeFalse();

  const imported = await runCli(cli, [
    "transfer-import",
    "--input", transferPath,
    "--passphrase-file", passphrasePath,
    "--state-root", destinationRoot,
  ]);
  expect(imported.exitCode).toBe(0);
  expect(JSON.parse(imported.stdout)).toMatchObject({ authorityHandoff: true, serverEpoch: 2 });
  const destinationStatus = JSON.parse((await runCli(cli, ["status", "--state-root", destinationRoot])).stdout) as Record<string, unknown>;
  expect(destinationStatus).toMatchObject({ authority: "active", port: destinationPort });

  const destination = await startServer(cli, destinationRoot);
  await waitForHealth(destinationPort);
  acceptServerAuthorityTransfer(exportResult.authorityCode, kaiPaths);
  const socket = await connectAuthenticatedClient(kaiPaths);
  try {
    const requestId = randomUUID();
    socket.send(JSON.stringify({ version: 1, type: "project.list", requestId }));
    const result = await nextFrame(socket, "project.list.result");
    expect(result.requestId).toBe(requestId);
    expect(result.projects).toEqual([{ id: project.id, name: "Transfer Alpha", role: "owner" }]);
  } finally {
    socket.close();
  }
  const finalStatus = JSON.parse((await runCli(cli, ["status", "--state-root", destinationRoot])).stdout) as Record<string, unknown>;
  expect(finalStatus.running).toBeTrue();
  const destinationStopped = await runCli(cli, ["stop", "--state-root", destinationRoot]);
  expect(destinationStopped.exitCode).toBe(0);
  await destination.exited;
  expect(readFileSync(join(destinationRoot, "config.json"), "utf8")).toContain(String(destinationPort));
}, 60_000);
