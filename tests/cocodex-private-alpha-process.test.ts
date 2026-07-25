import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";

const root = resolve(import.meta.dir, "..");
const bun = resolve(root, "node_modules/bun/bin/bun.exe");
const temporaryRoots: string[] = [];
const residents: Resident[] = [];

function traceCheckpoint(name: string): void {
  if (process.env.COCODEX_TEST_TRACE === "1") console.error(`[private-alpha] ${name}`);
}

interface Resident {
  process: ReturnType<typeof Bun.spawn>;
  lines: Array<Record<string, any>>;
  errors: string[];
  send(value: unknown): void;
}

afterEach(async () => {
  for (const resident of residents.splice(0)) {
    if (resident.process.exitCode === null) resident.process.kill("SIGKILL");
    await resident.process.exited;
  }
  Bun.gc(true);
  for (const directory of temporaryRoots.splice(0)) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        rmSync(directory, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 29) throw error;
        await Bun.sleep(50);
      }
    }
  }
});

async function run(command: string, args: string[], env: Record<string, string | undefined> = {}) {
  const child = Bun.spawn([command, ...args], {
    cwd: root,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) throw new Error(`${command} ${args.join(" ")} failed (${exitCode}): ${stderr || stdout}`);
  return stdout.trim();
}

function collectLines(
  stream: ReadableStream<Uint8Array>,
  onLine: (line: string) => void,
): void {
  void (async () => {
    let pending = "";
    for await (const chunk of stream) {
      pending += Buffer.from(chunk).toString("utf8");
      let newline: number;
      while ((newline = pending.indexOf("\n")) >= 0) {
        const line = pending.slice(0, newline).trim();
        pending = pending.slice(newline + 1);
        if (line) onLine(line);
      }
    }
    if (pending.trim()) onLine(pending.trim());
  })();
}

function startResident(command: string, args: string[], env: Record<string, string | undefined> = {}): Resident {
  const process = Bun.spawn([command, ...args], {
    cwd: root,
    env: { ...processEnv(), ...env },
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  });
  const resident: Resident = {
    process,
    lines: [],
    errors: [],
    send(value) {
      process.stdin.write(`${JSON.stringify(value)}\n`);
      process.stdin.flush();
    },
  };
  collectLines(process.stdout, line => {
    try {
      resident.lines.push(JSON.parse(line));
    } catch {
      resident.lines.push({ source: "raw", line });
    }
  });
  collectLines(process.stderr, line => resident.errors.push(line));
  residents.push(resident);
  return resident;
}

function processEnv(): Record<string, string | undefined> {
  return { ...process.env };
}

async function waitFor(
  resident: Resident,
  predicate: (line: Record<string, any>) => boolean,
  timeoutMs = 30_000,
): Promise<Record<string, any>> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = resident.lines.find(predicate);
    if (found) return found;
    if (resident.process.exitCode !== null) {
      throw new Error(`Resident exited ${resident.process.exitCode}: stderr=${resident.errors.join(" | ")} lines=${JSON.stringify(resident.lines.slice(-12))}`);
    }
    await Bun.sleep(25);
  }
  throw new Error(`Timed out. stderr=${resident.errors.join(" | ")} lines=${JSON.stringify(resident.lines.slice(-10))}`);
}

async function waitForAfter(
  resident: Resident,
  checkpoint: number,
  predicate: (line: Record<string, any>) => boolean,
  timeoutMs = 30_000,
): Promise<Record<string, any>> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = resident.lines.slice(checkpoint).find(predicate);
    if (found) return found;
    if (resident.process.exitCode !== null) {
      throw new Error(`Resident exited ${resident.process.exitCode}: stderr=${resident.errors.join(" | ")} lines=${JSON.stringify(resident.lines.slice(-12))}`);
    }
    await Bun.sleep(25);
  }
  throw new Error(`Timed out after checkpoint. stderr=${resident.errors.join(" | ")} lines=${JSON.stringify(resident.lines.slice(-10))}`);
}

async function waitForMailbox(path: string, expectedMinimumReceipts: number): Promise<{
  cursor: number;
  receipts: Array<{ messageId: string; sequence: number }>;
}> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (existsSync(path)) {
      const mailbox = JSON.parse(readFileSync(path, "utf8")) as {
        cursor: number;
        receipts: Array<{ messageId: string; sequence: number }>;
      };
      if (mailbox.receipts.length >= expectedMinimumReceipts) return mailbox;
    }
    await Bun.sleep(25);
  }
  throw new Error(`Timed out waiting for mailbox ${path}`);
}

async function buildArtifacts(serverExe: string, clientExe: string, fixtureExe: string): Promise<void> {
  await run(bun, [
    "build", "./apps/cocodex-server/src/cli.ts", "--compile", "--outfile", serverExe,
  ]);
  await run(bun, [
    "build", "./src/cocodex/cli.ts", "--compile", "--outfile", clientExe,
  ]);
  await run(bun, [
    "build",
    "./tests/fixtures/codex-runtime-fixture.ts",
    "--compile",
    "--outfile",
    fixtureExe,
  ]);
}

describe("three-process CoCodex private alpha", () => {
  test("two resident clients recover chat, local execution, and private ciphertext across restart", async () => {
    const temp = mkdtempSync(join(tmpdir(), "cocodex-private-alpha-"));
    temporaryRoots.push(temp);
    const serverRoot = join(temp, "server");
    const stephenRoot = join(temp, "stephen");
    const kaiRoot = join(temp, "kai");
    const stephenWorkspace = join(temp, "stephen-workspace");
    const kaiWorkspace = join(temp, "kai-workspace");
    const fixtureExe = join(temp, "codex-runtime-fixture.exe");
    const serverExe = join(temp, "cocodex-server.exe");
    const clientExe = join(temp, "cocodex-client.exe");
    const port = 25000 + Math.floor(Math.random() * 10000);
    mkdirSync(stephenWorkspace, { recursive: true });
    mkdirSync(kaiWorkspace, { recursive: true });
    await buildArtifacts(serverExe, clientExe, fixtureExe);
    traceCheckpoint("artifacts built");
    await run(serverExe, [
      "init", "--public-host", "127.0.0.1", "--port", String(port), "--state-root", serverRoot,
    ], { COCODEX_DISABLE_PORT_MAPPING: "1" });

    const startServer = () => startResident(serverExe, ["start", "--state-root", serverRoot]);
    let server = startServer();
    await waitFor(server, line => line.ready === true);

    const enroll = async (name: string, stateRoot: string) => {
      const invitation = await run(serverExe, ["invite", "--state-root", serverRoot]);
      const result = JSON.parse(await run(clientExe, [
        "enroll", "--invite", invitation, "--name", name, "--state-root", stateRoot,
      ]));
      const devices = JSON.parse(await run(serverExe, ["devices", "--state-root", serverRoot]));
      const device = devices.find((item: any) => item.id === result.deviceId);
      await run(serverExe, [
        "approve", "--fingerprint", device.fingerprint, "--state-root", serverRoot,
      ]);
      return device as { id: string; fingerprint: string };
    };
    const stephenDevice = await enroll("Stephen", stephenRoot);
    const kaiDevice = await enroll("Kai", kaiRoot);
    const stephenKeyCertificate = await run(clientExe, [
      "identity-card", "--state-root", stephenRoot,
    ]);
    const kaiKeyCertificate = await run(clientExe, [
      "identity-card", "--state-root", kaiRoot,
    ]);
    const stephenDeviceCard = JSON.parse(stephenKeyCertificate) as { projectWrapPublicKeyPem: string };
    const kaiDeviceCard = JSON.parse(kaiKeyCertificate) as { projectWrapPublicKeyPem: string };

    const project = JSON.parse(await run(serverExe, [
      "project-create", "--name", "Nocturne Launcher", "--owner-device", stephenDevice.id,
      "--state-root", serverRoot,
    ]));
    await run(serverExe, [
      "project-add-member", "--project", project.id, "--owner-device", stephenDevice.id,
      "--member-device", kaiDevice.id, "--state-root", serverRoot,
    ]);
    await run(serverExe, [
      "agent-add", "--id", "stephen-agent", "--project", project.id,
      "--host-device", stephenDevice.id, "--name", "Stephen Codex", "--state-root", serverRoot,
    ]);
    await run(serverExe, [
      "agent-add", "--id", "kai-agent", "--project", project.id,
      "--host-device", kaiDevice.id, "--name", "Kai Codex", "--state-root", serverRoot,
    ]);
    await run(clientExe, [
      "configure-agent", "--project", project.id, "--agent", "stephen-agent",
      "--workspace", stephenWorkspace, "--approval", "always", "--trust-device", kaiDevice.id,
      "--trust-fingerprint", kaiDevice.fingerprint, "--state-root", stephenRoot,
    ]);
    await run(clientExe, [
      "configure-agent", "--project", project.id, "--agent", "kai-agent",
      "--workspace", kaiWorkspace, "--approval", "always", "--trust-device", stephenDevice.id,
      "--trust-fingerprint", stephenDevice.fingerprint, "--state-root", kaiRoot,
    ]);

    const stephen = startResident(clientExe, ["connect", "--json-lines", "--state-root", stephenRoot], {
      CODEX_CLI_PATH: fixtureExe,
      COCODEX_ACCOUNT_FIXTURE: "stephen-account",
    });
    const kai = startResident(clientExe, ["connect", "--json-lines", "--state-root", kaiRoot], {
      CODEX_CLI_PATH: fixtureExe,
      COCODEX_ACCOUNT_FIXTURE: "kai-account",
    });
    await Promise.all([
      waitFor(stephen, line => line.source === "session" && line.state === "connected"),
      waitFor(kai, line => line.source === "session" && line.state === "connected"),
    ]);
    traceCheckpoint("clients connected");
    const stephenPid = stephen.process.pid;
    const kaiPid = kai.process.pid;

    const projectsS = randomUUID();
    const projectsK = randomUUID();
    stephen.send({ id: projectsS, type: "project.list" });
    kai.send({ id: projectsK, type: "project.list" });
    const [stephenProjects, kaiProjects] = await Promise.all([
      waitFor(stephen, line => line.frame?.type === "project.list.result" && line.frame.requestId === projectsS),
      waitFor(kai, line => line.frame?.type === "project.list.result" && line.frame.requestId === projectsK),
    ]);
    expect(stephenProjects.frame.projects.map((item: any) => item.id)).toEqual([project.id]);
    expect(kaiProjects.frame.projects.map((item: any) => item.id)).toEqual([project.id]);
    const subS = randomUUID();
    const subK = randomUUID();
    stephen.send({ id: subS, type: "chat.subscribe", projectId: project.id, afterSequence: 0 });
    kai.send({ id: subK, type: "chat.subscribe", projectId: project.id, afterSequence: 0 });
    await Promise.all([
      waitFor(stephen, line => line.frame?.type === "chat.snapshot" && line.frame.requestId === subS),
      waitFor(kai, line => line.frame?.type === "chat.snapshot" && line.frame.requestId === subK),
    ]);

    const contextGetS = randomUUID();
    const contextGetK = randomUUID();
    stephen.send({ id: contextGetS, type: "context.get", projectId: project.id });
    kai.send({ id: contextGetK, type: "context.get", projectId: project.id });
    const [initialContextS, initialContextK] = await Promise.all([
      waitFor(stephen, line => line.frame?.type === "context.result" && line.frame.requestId === contextGetS),
      waitFor(kai, line => line.frame?.type === "context.result" && line.frame.requestId === contextGetK),
    ]);
    expect(initialContextS.frame.context.revision).toBe(0);
    expect(initialContextK.frame.context.finalGoal).toBe("");
    const contextUpdate = randomUUID();
    stephen.send({
      id: contextUpdate,
      type: "context.update",
      projectId: project.id,
      expectedRevision: 0,
      finalGoal: "Complete the private alpha path",
      context: { acceptance: "three-process" },
    });
    const acceptedContext = await waitFor(
      stephen,
      line => line.frame?.type === "context.updated" && line.frame.requestId === contextUpdate,
    );
    expect(acceptedContext.frame.context.revision).toBe(1);
    expect(acceptedContext.frame.context.finalGoal).toBe("Complete the private alpha path");
    await waitFor(kai, line => line.frame?.type === "context.changed"
      && line.frame.context?.revision === 1 && line.frame.context?.finalGoal === "Complete the private alpha path");

    kai.send({ id: randomUUID(), type: "chat.send", projectId: project.id, content: "Kai online" });
    const onlineAtStephen = await waitFor(
      stephen,
      line => line.frame?.type === "chat.event" && line.frame.event?.content === "Kai online",
    );
    const onlineAtKai = await waitFor(
      kai,
      line => line.frame?.type === "chat.event" && line.frame.event?.content === "Kai online",
    );
    expect(onlineAtKai.frame.event.sequence).toBe(onlineAtStephen.frame.event.sequence);

    kai.send({
      id: "task-stephen",
      type: "agent.request",
      projectId: project.id,
      agentId: "stephen-agent",
      prompt: "inspect Stephen workspace",
    });
    const stephenApproval = await waitFor(
      stephen,
      line => line.source === "agent-approval" && line.approvalState === "pending"
        && line.task?.agentId === "stephen-agent",
    );
    stephen.send({ id: randomUUID(), type: "agent.approval", taskId: stephenApproval.task.id, approved: true });
    await waitFor(stephen, line => line.source === "local-usage" && line.deviceId === stephenDevice.id);
    await waitFor(kai, line => line.frame?.type === "agent.result" && line.frame.final === true
      && line.frame.event?.content?.includes("stephen-account"));
    traceCheckpoint("Stephen agent completed");
    expect(existsSync(join(stephenWorkspace, "stephen-account-execution.json"))).toBeTrue();
    expect(existsSync(join(kaiWorkspace, "stephen-account-execution.json"))).toBeFalse();

    stephen.send({
      id: "task-kai",
      type: "agent.request",
      projectId: project.id,
      agentId: "kai-agent",
      prompt: "inspect Kai workspace",
    });
    const kaiApproval = await waitFor(
      kai,
      line => line.source === "agent-approval" && line.approvalState === "pending"
        && line.task?.agentId === "kai-agent",
    );
    kai.send({ id: randomUUID(), type: "agent.approval", taskId: kaiApproval.task.id, approved: true });
    await waitFor(kai, line => line.source === "local-usage" && line.deviceId === kaiDevice.id);
    await waitFor(stephen, line => line.frame?.type === "agent.result" && line.frame.final === true
      && line.frame.event?.content?.includes("kai-account"));
    traceCheckpoint("Kai agent completed");
    expect(existsSync(join(kaiWorkspace, "kai-account-execution.json"))).toBeTrue();

    const keyInitialize = randomUUID();
    stephen.send({
      id: keyInitialize,
      type: "project.key.initialize",
      projectId: project.id,
      keyEpoch: 1,
      recipients: [
        { deviceId: stephenDevice.id, projectWrapPublicKeyPem: stephenDeviceCard.projectWrapPublicKeyPem },
        { deviceId: kaiDevice.id, projectWrapPublicKeyPem: kaiDeviceCard.projectWrapPublicKeyPem },
      ],
    });
    await waitFor(stephen, line => line.source === "control" && line.id === keyInitialize
      && line.ok === true && line.sharedRecipients === 2);
    const keyGet = randomUUID();
    kai.send({ id: keyGet, type: "project.key.get", projectId: project.id });
    await waitFor(kai, line => line.source === "control" && line.id === keyGet && line.ok === true);
    await waitFor(kai, line => line.source === "project-encryption"
      && line.state === "key-available" && line.projectId === project.id);

    // Re-subscribe after project-key enrollment so both clients receive the
    // encrypted chat stream used for encrypted agent results.
    const encryptedChatSubS = randomUUID();
    const encryptedChatSubK = randomUUID();
    stephen.send({ id: encryptedChatSubS, type: "chat.subscribe", projectId: project.id });
    kai.send({ id: encryptedChatSubK, type: "chat.subscribe", projectId: project.id });
    await Promise.all([
      waitFor(stephen, line => line.frame?.type === "chat.snapshot" && line.frame.requestId === encryptedChatSubS),
      waitFor(kai, line => line.frame?.type === "chat.snapshot" && line.frame.requestId === encryptedChatSubK),
    ]);

    const encryptedStephenPrompt = "encrypted Stephen prompt never stored in server plaintext";
    const encryptedStephenRequest = randomUUID();
    kai.send({
      id: encryptedStephenRequest,
      type: "agent.request",
      projectId: project.id,
      agentId: "stephen-agent",
      prompt: encryptedStephenPrompt,
    });
    const encryptedStephenControl = await waitFor(kai, line => line.source === "control"
      && line.id === encryptedStephenRequest && line.ok === true && line.encrypted === true);
    const encryptedStephenApproval = await waitFor(stephen, line => line.source === "agent-approval"
      && line.approvalState === "pending" && line.task?.id === encryptedStephenControl.taskId);
    stephen.send({ id: randomUUID(), type: "agent.approval", taskId: encryptedStephenApproval.task.id, approved: true });
    await waitFor(kai, line => line.frame?.type === "agent.result" && line.frame.taskId === encryptedStephenControl.taskId
      && line.frame.final === true && line.frame.event?.content?.includes(encryptedStephenPrompt));
    expect(readFileSync(join(stephenWorkspace, "stephen-account-execution.json"), "utf8")).toContain(encryptedStephenPrompt);

    const encryptedKaiPrompt = "encrypted Kai prompt never stored in server plaintext";
    const encryptedKaiRequest = randomUUID();
    stephen.send({
      id: encryptedKaiRequest,
      type: "agent.request",
      projectId: project.id,
      agentId: "kai-agent",
      prompt: encryptedKaiPrompt,
    });
    const encryptedKaiControl = await waitFor(stephen, line => line.source === "control"
      && line.id === encryptedKaiRequest && line.ok === true && line.encrypted === true);
    const encryptedKaiApproval = await waitFor(kai, line => line.source === "agent-approval"
      && line.approvalState === "pending" && line.task?.id === encryptedKaiControl.taskId);
    kai.send({ id: randomUUID(), type: "agent.approval", taskId: encryptedKaiApproval.task.id, approved: true });
    await waitFor(stephen, line => line.frame?.type === "agent.result" && line.frame.taskId === encryptedKaiControl.taskId
      && line.frame.final === true && line.frame.event?.content?.includes(encryptedKaiPrompt));
    expect(readFileSync(join(kaiWorkspace, "kai-account-execution.json"), "utf8")).toContain(encryptedKaiPrompt);
    traceCheckpoint("encrypted agents completed");

    const usageGetS = randomUUID();
    const usageGetK = randomUUID();
    stephen.send({ id: usageGetS, type: "usage.get", projectId: project.id });
    kai.send({ id: usageGetK, type: "usage.get", projectId: project.id });
    const [usageS, usageK] = await Promise.all([
      waitFor(stephen, line => line.frame?.type === "usage.result" && line.frame.requestId === usageGetS),
      waitFor(kai, line => line.frame?.type === "usage.result" && line.frame.requestId === usageGetK),
    ]);
    const usageReportsS = usageS.frame.reports as any[];
    const usageReportsK = usageK.frame.reports as any[];
    expect(usageReportsS).toEqual(expect.arrayContaining([
      expect.objectContaining({ deviceId: stephenDevice.id, report: expect.objectContaining({ requests: 2 }) }),
      expect.objectContaining({ deviceId: kaiDevice.id, report: expect.objectContaining({ requests: 2 }) }),
    ]));
    expect(usageReportsK).toEqual(expect.arrayContaining([
      expect.objectContaining({ deviceId: stephenDevice.id, report: expect.objectContaining({ inputTokens: expect.any(Number) }) }),
      expect.objectContaining({ deviceId: kaiDevice.id, report: expect.objectContaining({ outputTokens: expect.any(Number) }) }),
    ]));

    const privateCanary = "PRIVATE-CANARY-7cLw9";
    kai.send({
      id: randomUUID(),
      type: "private.send",
      recipientDeviceId: stephenDevice.id,
      recipientKeyCertificate: stephenKeyCertificate,
      text: privateCanary,
    });
    await waitFor(stephen, line => line.source === "private" && line.message?.text === privateCanary);
    traceCheckpoint("private message decrypted");

    traceCheckpoint("stopping first server");
    server.process.kill();
    await server.process.exited;
    traceCheckpoint("first server stopped");
    residents.splice(residents.indexOf(server), 1);
    await Promise.all([
      waitFor(stephen, line => line.source === "session" && line.state === "disconnected"),
      waitFor(kai, line => line.source === "session" && line.state === "disconnected"),
    ]);
    const offlineS = randomUUID();
    const offlineK = randomUUID();
    stephen.send({ id: offlineS, type: "chat.send", projectId: project.id, content: "Stephen offline queued" });
    kai.send({ id: offlineK, type: "chat.send", projectId: project.id, content: "Kai offline queued" });
    const offlinePrivateS = "Kai private while the server is offline";
    const offlinePrivateK = "Stephen private while the server is offline";
    const offlinePrivateRequestS = randomUUID();
    const offlinePrivateRequestK = randomUUID();
    kai.send({
      id: offlinePrivateRequestS,
      type: "private.send",
      recipientDeviceId: stephenDevice.id,
      recipientKeyCertificate: stephenKeyCertificate,
      text: offlinePrivateS,
    });
    stephen.send({
      id: offlinePrivateRequestK,
      type: "private.send",
      recipientDeviceId: kaiDevice.id,
      recipientKeyCertificate: kaiKeyCertificate,
      text: offlinePrivateK,
    });
    await Promise.all([
      waitFor(stephen, line => line.source === "control" && line.id === offlineS && line.queued === true),
      waitFor(kai, line => line.source === "control" && line.id === offlineK && line.queued === true),
      waitFor(kai, line => line.source === "control" && line.id === offlinePrivateRequestS && line.queued === true),
      waitFor(stephen, line => line.source === "control" && line.id === offlinePrivateRequestK && line.queued === true),
    ]);

    traceCheckpoint("offline queues accepted");
    server = startServer();
    await waitFor(server, line => line.ready === true);
    await Promise.all([
      waitFor(stephen, line => line.source === "session" && line.state === "connected" && line.flushedEvents >= 1),
      waitFor(kai, line => line.source === "session" && line.state === "connected" && line.flushedEvents >= 1),
    ]);
    await Promise.all([
      waitFor(stephen, line => line.source === "private" && line.message?.text === offlinePrivateS),
      waitFor(kai, line => line.source === "private" && line.message?.text === offlinePrivateK),
    ]);
    const [stephenPrivateMailbox, kaiPrivateMailbox] = await Promise.all([
      waitForMailbox(join(stephenRoot, "private-mailbox.json"), 3),
      waitForMailbox(join(kaiRoot, "private-mailbox.json"), 3),
    ]);
    expect(stephenPrivateMailbox.cursor).toBe(kaiPrivateMailbox.cursor);
    expect(stephenPrivateMailbox.receipts.length).toBeGreaterThanOrEqual(3);
    expect(kaiPrivateMailbox.receipts.length).toBeGreaterThanOrEqual(3);
    expect(stephen.process.pid).toBe(stephenPid);
    expect(kai.process.pid).toBe(kaiPid);
    traceCheckpoint("clients reconnected");
    const recoveryCheckpointS = stephen.lines.length;
    const recoveryCheckpointK = kai.lines.length;
    const recoveredChatSubS = randomUUID();
    const recoveredChatSubK = randomUUID();
    stephen.send({ id: recoveredChatSubS, type: "chat.subscribe", projectId: project.id, afterSequence: 0 });
    kai.send({ id: recoveredChatSubK, type: "chat.subscribe", projectId: project.id, afterSequence: 0 });
    await Promise.all([
      waitFor(stephen, line => line.frame?.type === "chat.snapshot" && line.frame.requestId === recoveredChatSubS
        && line.frame.events?.some((item: any) => item.content === "Kai offline queued")),
      waitFor(kai, line => line.frame?.type === "chat.snapshot" && line.frame.requestId === recoveredChatSubK
        && line.frame.events?.some((item: any) => item.content === "Stephen offline queued")),
    ]);
    await Promise.all([
      waitForAfter(stephen, recoveryCheckpointS, line => line.frame?.type === "agent.result"
        && line.frame.taskId === encryptedKaiControl.taskId && line.frame.final === true
        && line.frame.event?.content?.includes(encryptedKaiPrompt)),
      waitForAfter(kai, recoveryCheckpointK, line => line.frame?.type === "agent.result"
        && line.frame.taskId === encryptedStephenControl.taskId && line.frame.final === true
        && line.frame.event?.content?.includes(encryptedStephenPrompt)),
    ]);

    const recoveredContextRequest = randomUUID();
    kai.send({ id: recoveredContextRequest, type: "context.get", projectId: project.id });
    const recoveredContext = await waitFor(
      kai,
      line => line.frame?.type === "context.result" && line.frame.requestId === recoveredContextRequest,
    );
    expect(recoveredContext.frame.context).toMatchObject({
      revision: 1,
      finalGoal: "Complete the private alpha path",
      context: { acceptance: "three-process" },
    });
    const recoveredUsageRequest = randomUUID();
    kai.send({ id: recoveredUsageRequest, type: "usage.get", projectId: project.id });
    const recoveredUsage = await waitFor(
      kai,
      line => line.frame?.type === "usage.result" && line.frame.requestId === recoveredUsageRequest,
    );
    expect(recoveredUsage.frame.reports).toEqual(expect.arrayContaining([
      expect.objectContaining({ deviceId: stephenDevice.id, report: expect.objectContaining({ requests: 2 }) }),
      expect.objectContaining({ deviceId: kaiDevice.id, report: expect.objectContaining({ requests: 2 }) }),
    ]));

    traceCheckpoint("recovered snapshots received");
    stephen.send({ id: "stop-s", type: "shutdown" });
    kai.send({ id: "stop-k", type: "shutdown" });
    await Promise.all([stephen.process.exited, kai.process.exited]);
    traceCheckpoint("clients stopped");
    residents.splice(residents.indexOf(stephen), 1);
    residents.splice(residents.indexOf(kai), 1);
    server.process.kill();
    await server.process.exited;
    residents.splice(residents.indexOf(server), 1);

    const db = new Database(join(serverRoot, "server.sqlite3"), { readonly: true });
    const ciphertext = db.query("SELECT ciphertext FROM private_messages").get() as { ciphertext: string };
    const encryptedTasks = db.query(`
      SELECT id, prompt, prompt_envelope_json AS promptEnvelopeJson
      FROM agent_tasks WHERE id IN (?, ?)
      ORDER BY id
    `).all(encryptedStephenControl.taskId, encryptedKaiControl.taskId) as Array<{
      id: string; prompt: string; promptEnvelopeJson: string;
    }>;
    const encryptedResults = db.query(`
      SELECT task_id AS taskId, envelope_json AS envelopeJson
      FROM project_chat_events WHERE task_id IN (?, ?)
      ORDER BY task_id, sequence
    `).all(encryptedStephenControl.taskId, encryptedKaiControl.taskId) as Array<{
      taskId: string; envelopeJson: string;
    }>;
    const duplicateCounts = db.query(`
      SELECT COUNT(*) AS total, COUNT(DISTINCT event_id) AS uniqueIds FROM chat_events
    `).get() as { total: number; uniqueIds: number };
    db.close();
    expect(ciphertext.ciphertext).not.toContain(privateCanary);
    expect(readFileSync(join(serverRoot, "server.sqlite3")).includes(Buffer.from(privateCanary))).toBeFalse();
    expect(duplicateCounts.total).toBe(duplicateCounts.uniqueIds);
    expect(readFileSync(join(stephenWorkspace, "stephen-account-execution.json"), "utf8")).not.toContain(privateCanary);
    expect(readFileSync(join(kaiWorkspace, "kai-account-execution.json"), "utf8")).not.toContain(privateCanary);
    expect(encryptedTasks).toHaveLength(2);
    for (const task of encryptedTasks) {
      expect(task.prompt).toBe("[encrypted]");
      expect(task.promptEnvelopeJson).not.toContain(encryptedStephenPrompt);
      expect(task.promptEnvelopeJson).not.toContain(encryptedKaiPrompt);
      expect(task.promptEnvelopeJson).toContain("ciphertext");
    }
    expect(encryptedResults.length).toBeGreaterThanOrEqual(2);
    for (const result of encryptedResults) {
      expect(result.envelopeJson).not.toContain(encryptedStephenPrompt);
      expect(result.envelopeJson).not.toContain(encryptedKaiPrompt);
      expect(result.envelopeJson).toContain("ciphertext");
    }
  }, 120_000);
});
