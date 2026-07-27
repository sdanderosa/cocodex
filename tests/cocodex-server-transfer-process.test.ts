import { afterEach, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { openDatabase } from "../apps/cocodex-server/src/database";
import { approveDevice, devicePublicKeys } from "../apps/cocodex-server/src/enrollment";
import { createInvitation } from "../apps/cocodex-server/src/invitations";
import { loadServerIdentity } from "../apps/cocodex-server/src/identity";
import { serverPaths } from "../apps/cocodex-server/src/paths";
import { addProjectMember, createProject } from "../apps/cocodex-server/src/shared-state";
import { tlsCertificateFingerprint } from "../apps/cocodex-server/src/tls";
import {
  acceptServerAuthorityTransfer,
  connectAuthenticatedClient,
  enrollClient,
  loadClientConnection,
} from "../src/cocodex/client";
import { loadOrCreateClientIdentity } from "../src/cocodex/identity";
import { clientPaths } from "../src/cocodex/paths";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "../src/cocodex/private-messaging";

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

test("hands a live server to a prepared process and reconnects both resident clients with shared state", async () => {
  const sourceRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-source-process-"));
  const destinationRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-destination-process-"));
  const stephenRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-stephen-process-"));
  const kaiRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-kai-process-"));
  const staleRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-stale-process-"));
  roots.push(sourceRoot, destinationRoot, stephenRoot, kaiRoot, staleRoot);

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
  const sourceDatabase = openDatabase(sourcePaths.database);
  const sourceFingerprint = tlsCertificateFingerprint(sourcePaths.tlsCertificate);
  const stephenInvitation = createInvitation(sourceDatabase, {
    host: "127.0.0.1",
    port: sourcePort,
    serverFingerprint: sourceFingerprint,
  });
  const kaiInvitation = createInvitation(sourceDatabase, {
    host: "127.0.0.1",
    port: sourcePort,
    serverFingerprint: sourceFingerprint,
  });
  sourceDatabase.close();

  const source = await startServer(cli, sourceRoot);
  await waitForHealth(sourcePort);

  const stephenPaths = clientPaths(stephenRoot);
  const kaiPaths = clientPaths(kaiRoot);
  const stephenConnection = await enrollClient(stephenInvitation, "Stephen", stephenPaths);
  const kaiConnection = await enrollClient(kaiInvitation, "Kai", kaiPaths);
  const approvalDatabase = openDatabase(sourcePaths.database);
  const stephenPending = approvalDatabase.query("SELECT fingerprint FROM devices WHERE id = ?")
    .get(stephenConnection.deviceId) as { fingerprint: string } | null;
  const kaiPending = approvalDatabase.query("SELECT fingerprint FROM devices WHERE id = ?")
    .get(kaiConnection.deviceId) as { fingerprint: string } | null;
  expect(stephenPending?.fingerprint).toBeTruthy();
  expect(kaiPending?.fingerprint).toBeTruthy();
  expect(approveDevice(approvalDatabase, stephenPending!.fingerprint)).toBeTrue();
  expect(approveDevice(approvalDatabase, kaiPending!.fingerprint)).toBeTrue();
  const project = createProject(approvalDatabase, "Transfer Alpha", stephenConnection.deviceId);
  addProjectMember(approvalDatabase, project.id, stephenConnection.deviceId, kaiConnection.deviceId);
  approvalDatabase.close();

  const sourceStephen = await connectAuthenticatedClient(stephenPaths);
  const sourceKai = await connectAuthenticatedClient(kaiPaths);
  const transferMessageId = randomUUID();
  const transferMessageCreatedAt = new Date().toISOString();
  const stephenIdentity = loadOrCreateClientIdentity(stephenPaths);
  const sourceKeyDatabase = openDatabase(sourcePaths.database);
  const kaiDevice = devicePublicKeys(sourceKeyDatabase, kaiConnection.deviceId);
  sourceKeyDatabase.close();
  const transferCiphertext = await sealSignedPrivateMessage({
    messageId: transferMessageId,
    senderDeviceId: stephenConnection.deviceId,
    recipientDeviceId: kaiConnection.deviceId,
    text: "transfer-private-secret",
    clientCreatedAt: transferMessageCreatedAt,
  }, stephenIdentity.privateKeyPem, stephenIdentity.publicKeyPem, kaiDevice.messagingPublicKeyPem);
  try {
    const chatRequestId = randomUUID();
    sourceStephen.send(JSON.stringify({
      version: 1,
      type: "chat.send",
      requestId: chatRequestId,
      projectId: project.id,
      eventId: randomUUID(),
      content: "chat-before-transfer",
      clientCreatedAt: new Date().toISOString(),
    }));
    const chatAccepted = await nextFrame(sourceStephen, "chat.accepted");
    expect(chatAccepted.requestId).toBe(chatRequestId);
    expect((chatAccepted.event as Record<string, unknown>).content).toBe("chat-before-transfer");

    const privateRequestId = randomUUID();
    sourceStephen.send(JSON.stringify({
      version: 1,
      type: "private.send",
      requestId: privateRequestId,
      messageId: transferMessageId,
      recipientDeviceId: kaiConnection.deviceId,
      ciphertext: transferCiphertext,
      clientCreatedAt: transferMessageCreatedAt,
    }));
    const privateAccepted = await nextFrame(sourceStephen, "private.accepted");
    expect(privateAccepted.requestId).toBe(privateRequestId);
    expect((privateAccepted.message as Record<string, unknown>).messageId).toBe(transferMessageId);
  } finally {
    sourceStephen.close();
    sourceKai.close();
  }

  // Preserve a pre-transfer connection as a local replay/stale-authority fixture.
  rmSync(staleRoot, { recursive: true, force: true });
  cpSync(kaiRoot, staleRoot, { recursive: true });

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
  const destinationPaths = serverPaths(destinationRoot);
  const destinationIdentity = loadServerIdentity(destinationPaths);
  const destinationFingerprint = tlsCertificateFingerprint(destinationPaths.tlsCertificate);
  const stephenNext = acceptServerAuthorityTransfer(exportResult.authorityCode, stephenPaths);
  const kaiNext = acceptServerAuthorityTransfer(exportResult.authorityCode, kaiPaths);
  expect(stephenNext).toMatchObject({
    host: "127.0.0.1",
    port: destinationPort,
    serverFingerprint: destinationFingerprint,
    serverIdentityPublicKeyPem: destinationIdentity.publicKeyPem,
    serverEpoch: 2,
  });
  expect(kaiNext).toMatchObject({
    host: stephenNext.host,
    port: stephenNext.port,
    serverFingerprint: stephenNext.serverFingerprint,
    serverCertificatePem: stephenNext.serverCertificatePem,
    serverIdentityPublicKeyPem: stephenNext.serverIdentityPublicKeyPem,
    serverEpoch: stephenNext.serverEpoch,
  });
  expect(loadClientConnection(clientPaths(staleRoot)).serverEpoch).toBe(1);
  expect(() => acceptServerAuthorityTransfer(exportResult.authorityCode, kaiPaths))
    .toThrow("currently trusted server");

  const stephenSocket = await connectAuthenticatedClient(stephenPaths);
  const kaiSocket = await connectAuthenticatedClient(kaiPaths);
  try {
    for (const [socket, role] of [[stephenSocket, "owner"], [kaiSocket, "member"]] as const) {
      const requestId = randomUUID();
      socket.send(JSON.stringify({ version: 1, type: "project.list", requestId }));
      const result = await nextFrame(socket, "project.list.result");
      expect(result.requestId).toBe(requestId);
      expect(result.projects).toEqual([{
        id: project.id,
        name: "Transfer Alpha",
        role,
        lock: {
          state: "active",
          revision: 0,
          lockedAt: null,
          lockedByDeviceId: null,
          reason: null,
        },
      }]);

      const chatRequestId = randomUUID();
      socket.send(JSON.stringify({ version: 1, type: "chat.subscribe", requestId: chatRequestId, projectId: project.id, afterSequence: 0 }));
      const chatSnapshot = await nextFrame(socket, "chat.snapshot");
      expect(chatSnapshot.requestId).toBe(chatRequestId);
      expect((chatSnapshot.events as Array<Record<string, unknown>>).map(event => event.content))
        .toEqual(["chat-before-transfer"]);

      const privateRequestId = randomUUID();
      socket.send(JSON.stringify({ version: 1, type: "private.subscribe", requestId: privateRequestId, afterSequence: 0 }));
      const privateSnapshot = await nextFrame(socket, "private.snapshot");
      expect(privateSnapshot.requestId).toBe(privateRequestId);
      const messages = privateSnapshot.messages as Array<Record<string, unknown>>;
      expect(messages).toHaveLength(1);
      expect(messages[0]).toMatchObject({
        messageId: transferMessageId,
        senderDeviceId: stephenConnection.deviceId,
        recipientDeviceId: kaiConnection.deviceId,
        ciphertext: transferCiphertext,
      });
      if (role === "member") {
        const kaiIdentity = loadOrCreateClientIdentity(kaiPaths);
        const opened = await openSignedPrivateMessage(
          String(messages[0].ciphertext),
          kaiIdentity.messagingPrivateKeyPem,
          kaiIdentity.messagingPublicKeyPem,
          messages[0] as { messageId: string; senderDeviceId: string; recipientDeviceId: string; clientCreatedAt: string },
          stephenPending!.fingerprint,
        );
        expect(opened.text).toBe("transfer-private-secret");
      }
    }
  } finally {
    stephenSocket.close();
    kaiSocket.close();
  }
  const finalStatus = JSON.parse((await runCli(cli, ["status", "--state-root", destinationRoot])).stdout) as Record<string, unknown>;
  expect(finalStatus.running).toBeTrue();
  const destinationStopped = await runCli(cli, ["stop", "--state-root", destinationRoot]);
  expect(destinationStopped.exitCode).toBe(0);
  await destination.exited;
  expect(readFileSync(join(destinationRoot, "config.json"), "utf8")).toContain(String(destinationPort));
  const destinationDatabase = openDatabase(destinationPaths.database);
  const storedPrivate = destinationDatabase.query("SELECT ciphertext FROM private_messages WHERE message_id = ?")
    .get(transferMessageId) as { ciphertext: string } | null;
  destinationDatabase.close();
  expect(storedPrivate?.ciphertext).toBe(transferCiphertext);
  expect(storedPrivate?.ciphertext).not.toContain("transfer-private-secret");
}, 60_000);
