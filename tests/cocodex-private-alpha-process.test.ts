import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  if (process.platform === "win32") await Bun.sleep(1_000);
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
  if (process.platform === "win32") await Bun.sleep(100);
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

async function waitForMailbox(
  path: string,
  expectedMinimumReceipts: number,
  expectedRemoteReceipt?: { messageId: string; receipt: "delivered" | "read" },
): Promise<{
  cursor: number;
  receipts: Array<{ messageId: string; sequence: number }>;
  receiptCursor?: number;
  remoteReceipts?: Array<{ messageId: string; receipt: "delivered" | "read"; sequence: number }>;
}> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (existsSync(path)) {
      const mailbox = JSON.parse(readFileSync(path, "utf8")) as {
        cursor: number;
        receipts: Array<{ messageId: string; sequence: number }>;
        receiptCursor?: number;
        remoteReceipts?: Array<{ messageId: string; receipt: "delivered" | "read"; sequence: number }>;
      };
      if (mailbox.receipts.length >= expectedMinimumReceipts
        && (!expectedRemoteReceipt || mailbox.remoteReceipts?.some(receipt =>
          receipt.messageId === expectedRemoteReceipt.messageId && receipt.receipt === expectedRemoteReceipt.receipt))) return mailbox;
    }
    await Bun.sleep(25);
  }
  throw new Error(`Timed out waiting for mailbox ${path}`);
}

async function waitForPath(path: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(path)) return;
    await Bun.sleep(25);
  }
  throw new Error(`Timed out waiting for ${path}`);
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
    const angelaWorkspace = join(temp, "angela-workspace");
    const kaiWorkspace = join(temp, "kai-workspace");
    const executionBarrier = join(temp, "execution-barrier");
    const fixtureExe = join(temp, "codex-runtime-fixture.exe");
    const serverExe = join(temp, "cocodex-server.exe");
    const clientExe = join(temp, "cocodex-client.exe");
    const port = 25000 + Math.floor(Math.random() * 10000);
    const lucasAgentId = randomUUID();
    const angelaAgentId = randomUUID();
    const sueAgentId = randomUUID();
    mkdirSync(stephenWorkspace, { recursive: true });
    mkdirSync(angelaWorkspace, { recursive: true });
    mkdirSync(kaiWorkspace, { recursive: true });
    mkdirSync(executionBarrier, { recursive: true });
    await buildArtifacts(serverExe, clientExe, fixtureExe);
    if (process.platform === "win32") await Bun.sleep(500);
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
    let stephen = startResident(clientExe, ["connect", "--json-lines", "--state-root", stephenRoot], {
      CODEX_CLI_PATH: fixtureExe,
      COCODEX_ACCOUNT_FIXTURE: "stephen-account",
      CODEX_RUNTIME_MARKER: JSON.stringify({ barrierDirectory: executionBarrier }),
    });
    let kai = startResident(clientExe, ["connect", "--json-lines", "--state-root", kaiRoot], {
      CODEX_CLI_PATH: fixtureExe,
      COCODEX_ACCOUNT_FIXTURE: "kai-account",
      CODEX_RUNTIME_MARKER: JSON.stringify({ allowFullComputer: true }),
    });
    await Promise.all([
      waitFor(stephen, line => line.source === "session" && line.state === "connected"),
      waitFor(kai, line => line.source === "session" && line.state === "connected"),
    ]);
    const [stephenContacts, kaiContacts] = await Promise.all([
      waitFor(stephen, line => line.source === "private-contacts"
        && line.contacts?.some((contact: any) => contact.deviceId === kaiDevice.id)),
      waitFor(kai, line => line.source === "private-contacts"
        && line.contacts?.some((contact: any) => contact.deviceId === stephenDevice.id)),
    ]);
    expect(stephenContacts.contacts).toContainEqual(expect.objectContaining({
      deviceId: kaiDevice.id,
      displayName: "Kai",
      fingerprint: kaiDevice.fingerprint,
    }));
    expect(kaiContacts.contacts).toContainEqual(expect.objectContaining({
      deviceId: stephenDevice.id,
      displayName: "Stephen",
      fingerprint: stephenDevice.fingerprint,
    }));
    expect(JSON.stringify([stephenContacts, kaiContacts])).not.toContain("deviceKeyCertificate");
    const mismatchedTrustRequest = randomUUID();
    kai.send({
      id: mismatchedTrustRequest,
      type: "device.trust",
      deviceId: stephenDevice.id,
      fingerprint: kaiDevice.fingerprint,
    });
    const mismatchedTrust = await waitFor(kai, line =>
      line.source === "control" && line.id === mismatchedTrustRequest);
    expect(mismatchedTrust.ok).toBeFalse();
    expect(mismatchedTrust.error).toContain("current approved directory");
    const trustStephen = randomUUID();
    const trustKai = randomUUID();
    kai.send({
      id: trustStephen,
      type: "device.trust",
      deviceId: stephenDevice.id,
      fingerprint: stephenDevice.fingerprint,
    });
    stephen.send({
      id: trustKai,
      type: "device.trust",
      deviceId: kaiDevice.id,
      fingerprint: kaiDevice.fingerprint,
    });
    await Promise.all([
      waitFor(kai, line => line.source === "control" && line.id === trustStephen && line.ok === true),
      waitFor(stephen, line => line.source === "control" && line.id === trustKai && line.ok === true),
    ]);
    const project = { id: randomUUID(), name: "Nocturne Launcher", role: "owner" };
    const createProjectRequest = randomUUID();
    stephen.send({
      id: createProjectRequest,
      type: "project.create",
      projectId: project.id,
      name: project.name,
      memberDeviceIds: [],
    });
    await waitFor(stephen, line => line.source === "control" && line.id === createProjectRequest
      && line.ok === true && line.projectId === project.id && line.created === true);
    const beforeInvitationList = randomUUID();
    kai.send({ id: beforeInvitationList, type: "project.list" });
    const unauthorizedProjectList = await waitFor(kai, line =>
      line.frame?.type === "project.list.result" && line.frame.requestId === beforeInvitationList);
    expect(unauthorizedProjectList.frame.projects).toEqual([]);
    const serverDatabaseBeforeAcceptance = new Database(join(serverRoot, "server.sqlite3"), { readonly: true });
    expect(serverDatabaseBeforeAcceptance.query(`
      SELECT COUNT(*) AS count FROM project_members WHERE project_id = ?
    `).get(project.id)).toEqual({ count: 1 });
    serverDatabaseBeforeAcceptance.close();

    const inviteProjectRequest = randomUUID();
    stephen.send({
      id: inviteProjectRequest,
      type: "project.invite.create",
      projectId: project.id,
      recipientDeviceId: kaiDevice.id,
    });
    const incomingInvitation = await waitFor(kai, line =>
      line.source === "project-invitations"
      && line.invitations?.some((invitation: any) =>
        invitation.projectId === project.id
        && invitation.direction === "incoming"
        && invitation.status === "pending"
        && invitation.actionable === true));
    const invitation = incomingInvitation.invitations.find((candidate: any) =>
      candidate.projectId === project.id);
    expect(await waitFor(stephen, line => line.source === "control"
      && line.id === inviteProjectRequest && line.ok === true)).toMatchObject({
      projectId: project.id,
      invitationId: invitation.invitationId,
      status: "pending",
    });
    expect(JSON.stringify(incomingInvitation)).not.toContain("sealedProjectKey");
    expect(JSON.stringify(incomingInvitation)).not.toContain("ownerDeviceKeyCertificate");

    const acceptInvitationRequest = randomUUID();
    kai.send({
      id: acceptInvitationRequest,
      type: "project.invite.respond",
      invitationId: invitation.invitationId,
      decision: "accept",
    });
    await Promise.all([
      waitFor(kai, line => line.source === "control" && line.id === acceptInvitationRequest
        && line.ok === true && line.projectId === project.id && line.status === "accepted"),
      waitFor(kai, line => line.frame?.type === "project.changed"
        && line.frame.project?.id === project.id && line.frame.project?.role === "member"),
      waitFor(kai, line => line.source === "project-encryption"
        && line.state === "key-available" && line.projectId === project.id),
    ]);
    expect(JSON.stringify([...stephen.lines, ...kai.lines])).not.toContain("sealedProjectKey");
    const configureResidentAgent = async (
      resident: Resident,
      command: Record<string, unknown>,
    ) => {
      const id = randomUUID();
      resident.send({ id, type: "agent.configure", ...command });
      const configured = await waitFor(resident, line => line.source === "agent-configuration"
        && line.id === id && line.configured === true && line.created === true);
      await waitFor(resident, line => line.frame?.type === "agent.ready.accepted"
        && line.frame.agentId === command.agentId);
      return configured;
    };
    await configureResidentAgent(stephen, {
      projectId: project.id,
      agentId: lucasAgentId,
      name: "Lucas",
      workspaceRoot: stephenWorkspace,
      workspaceMode: "shared",
      primaryModel: "gpt-5.6-sol",
      primaryEffort: "medium",
      coAgentModel: "gpt-5.6-luna",
      coAgentEffort: "medium",
      maxConcurrentCoAgents: 3,
      approvalMode: "always",
      trustedRequesterDeviceId: kaiDevice.id,
      trustedRequesterFingerprint: kaiDevice.fingerprint,
    });
    await configureResidentAgent(stephen, {
      projectId: project.id,
      agentId: angelaAgentId,
      name: "Angela",
      workspaceRoot: angelaWorkspace,
      workspaceMode: "shared",
      primaryModel: "gpt-5.6-sol",
      primaryEffort: "xhigh",
      coAgentModel: null,
      coAgentEffort: null,
      maxConcurrentCoAgents: 0,
      approvalMode: "always",
      trustedRequesterDeviceId: kaiDevice.id,
      trustedRequesterFingerprint: kaiDevice.fingerprint,
    });
    await configureResidentAgent(kai, {
      projectId: project.id,
      agentId: sueAgentId,
      name: "Sue",
      workspaceRoot: kaiWorkspace,
      workspaceMode: "shared",
      primaryModel: "gpt-5.6-sol",
      primaryEffort: "high",
      coAgentModel: null,
      coAgentEffort: null,
      maxConcurrentCoAgents: 0,
      accessProfile: "full-computer",
      fullComputerOptIn: true,
      approvalMode: "always",
      trustedRequesterDeviceId: stephenDevice.id,
      trustedRequesterFingerprint: stephenDevice.fingerprint,
    });
    const enableSueFullComputer = randomUUID();
    kai.send({
      id: enableSueFullComputer,
      type: "agent.full-computer.enable",
      agentId: sueAgentId,
      confirm: true,
    });
    await waitFor(kai, line => line.source === "control" && line.id === enableSueFullComputer
      && line.ok === true && line.agentId === sueAgentId && line.fullComputerEnabled === true);
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
    const rosterRequest = randomUUID();
    stephen.send({ id: rosterRequest, type: "agent.list", projectId: project.id });
    const roster = await waitFor(stephen, line => line.frame?.type === "agent.list.result"
      && line.frame.requestId === rosterRequest);
    expect(roster.frame.agents).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: lucasAgentId,
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "medium",
        coAgentModel: "gpt-5.6-luna",
        coAgentEffort: "medium",
        maxConcurrentCoAgents: 3,
      }),
      expect.objectContaining({
        id: angelaAgentId,
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "xhigh",
        coAgentModel: null,
        coAgentEffort: null,
        maxConcurrentCoAgents: 0,
      }),
      expect.objectContaining({
        id: sueAgentId,
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "high",
        coAgentModel: null,
        coAgentEffort: null,
        maxConcurrentCoAgents: 0,
      }),
    ]));
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
      id: "task-lucas",
      type: "agent.request",
      projectId: project.id,
      agentId: lucasAgentId,
      prompt: "inspect Lucas workspace",
    });
    kai.send({
      id: "task-angela",
      type: "agent.request",
      projectId: project.id,
      agentId: angelaAgentId,
      prompt: "inspect Angela workspace",
    });
    const lucasApproval = await waitFor(
      stephen,
      line => line.source === "agent-approval" && line.approvalState === "pending"
        && line.task?.agentId === lucasAgentId,
    );
    const angelaApproval = await waitFor(
      stephen,
      line => line.source === "agent-approval" && line.approvalState === "pending"
        && line.task?.agentId === angelaAgentId,
    );
    const resultCheckpoint = kai.lines.length;
    stephen.send({ id: randomUUID(), type: "agent.approval", taskId: lucasApproval.task.id, approved: true });
    stephen.send({ id: randomUUID(), type: "agent.approval", taskId: angelaApproval.task.id, approved: true });
    const lucasMarker = join(stephenWorkspace, "stephen-account-execution.json");
    const angelaMarker = join(angelaWorkspace, "stephen-account-execution.json");
    await Promise.all([waitForPath(lucasMarker), waitForPath(angelaMarker)]);
    expect(kai.lines.slice(resultCheckpoint).some(line => line.frame?.type === "agent.result" && line.frame.final === true)).toBeFalse();
    writeFileSync(join(executionBarrier, "release"), "release\n", "utf8");
    await Promise.all([
      waitForAfter(kai, resultCheckpoint, line => line.frame?.type === "agent.result"
        && line.frame.taskId === lucasApproval.task.id && line.frame.final === true),
      waitForAfter(kai, resultCheckpoint, line => line.frame?.type === "agent.result"
        && line.frame.taskId === angelaApproval.task.id && line.frame.final === true),
    ]);
    await waitFor(stephen, line => line.source === "local-usage" && line.deviceId === stephenDevice.id);
    traceCheckpoint("Lucas and Angela completed concurrently");
    expect(existsSync(lucasMarker)).toBeTrue();
    expect(existsSync(angelaMarker)).toBeTrue();
    const lucasRuntime = JSON.parse(readFileSync(lucasMarker, "utf8")) as { prompt: string; args: string[] };
    const angelaRuntime = JSON.parse(readFileSync(angelaMarker, "utf8")) as { prompt: string; args: string[] };
    expect(lucasRuntime.args).toEqual(expect.arrayContaining([
      "--model", "gpt-5.6-sol",
      "model_reasoning_effort=\"medium\"",
      "features.multi_agent_v2.enabled=true",
      "features.multi_agent_v2.max_concurrent_threads_per_session=4",
    ]));
    expect(lucasRuntime.prompt).toContain("at most 3 co-agents concurrently");
    expect(lucasRuntime.prompt).toContain("gpt-5.6-luna");
    expect(angelaRuntime.args).toEqual(expect.arrayContaining([
      "--model", "gpt-5.6-sol",
      "model_reasoning_effort=\"xhigh\"",
      "features.multi_agent_v2.enabled=true",
      "features.multi_agent_v2.max_concurrent_threads_per_session=1",
    ]));
    expect(angelaRuntime.prompt).toContain("Do not spawn co-agents");
    expect(existsSync(join(kaiWorkspace, "stephen-account-execution.json"))).toBeFalse();

    stephen.send({
      id: "task-kai",
      type: "agent.request",
      projectId: project.id,
      agentId: sueAgentId,
      prompt: "inspect Kai workspace",
    });
    await waitFor(
      stephen,
      line => line.source === "control" && line.id === "task-kai"
        && line.ok === true && line.taskId,
    );
    const kaiApproval = await waitFor(
      kai,
      line => line.source === "agent-approval" && line.approvalState === "pending"
        && line.task?.agentId === sueAgentId,
    );
    kai.send({ id: randomUUID(), type: "agent.approval", taskId: kaiApproval.task.id, approved: true });
    await waitFor(kai, line => line.source === "local-usage" && line.deviceId === kaiDevice.id);
    await waitFor(stephen, line => line.frame?.type === "agent.result" && line.frame.final === true
      && line.frame.event?.content?.includes("kai-account"));
    traceCheckpoint("Kai agent completed");
    expect(existsSync(join(kaiWorkspace, "kai-account-execution.json"))).toBeTrue();
    const initialSueRuntime = JSON.parse(readFileSync(
      join(kaiWorkspace, "kai-account-execution.json"),
      "utf8",
    )) as { args: string[]; sandbox: string };
    expect(initialSueRuntime.args).toEqual(expect.arrayContaining([
      "--model", "gpt-5.6-sol",
      "model_reasoning_effort=\"high\"",
      "features.multi_agent_v2.enabled=true",
      "features.multi_agent_v2.max_concurrent_threads_per_session=1",
      "danger-full-access",
    ]));
    expect(initialSueRuntime.sandbox).toBe("danger-full-access");

    const privateCanary = "PRIVATE-CANARY-7cLw9";
    kai.send({
      id: randomUUID(),
      type: "private.send",
      recipientDeviceId: stephenDevice.id,
      text: privateCanary,
    });
    const privateDelivery = await waitFor(stephen, line => line.source === "private" && line.message?.text === privateCanary);
    const privateMessageId = String(privateDelivery.message.messageId);
    await waitFor(kai, line => line.source === "private-receipt"
      && line.receipt?.messageId === privateMessageId && line.receipt?.receipt === "delivered");
    const privateReadRequest = randomUUID();
    stephen.send({ id: privateReadRequest, type: "private.read", messageId: privateMessageId });
    await waitFor(stephen, line => line.source === "control" && line.id === privateReadRequest
      && line.ok === true && line.receipt === "read");
    await waitFor(kai, line => line.source === "private-receipt"
      && line.receipt?.messageId === privateMessageId && line.receipt?.receipt === "read");
    traceCheckpoint("private message decrypted");

    const keyGet = randomUUID();
    kai.send({ id: keyGet, type: "project.key.get", projectId: project.id });
    await waitFor(kai, line => line.source === "control" && line.id === keyGet && line.ok === true);
    await waitFor(kai, line => line.source === "project-encryption"
      && line.state === "key-available" && line.projectId === project.id);

    // Re-subscribe explicitly to prove both clients recover the already keyed
    // project stream used for encrypted agent results.
    const encryptedChatSubS = randomUUID();
    const encryptedChatSubK = randomUUID();
    stephen.send({ id: encryptedChatSubS, type: "chat.subscribe", projectId: project.id });
    kai.send({ id: encryptedChatSubK, type: "chat.subscribe", projectId: project.id });
    await Promise.all([
      waitFor(stephen, line => line.frame?.type === "chat.snapshot" && line.frame.requestId === encryptedChatSubS),
      waitFor(kai, line => line.frame?.type === "chat.snapshot" && line.frame.requestId === encryptedChatSubK),
    ]);

    const sharedPrivateRequest = randomUUID();
    stephen.send({
      id: sharedPrivateRequest,
      type: "private.share",
      projectId: project.id,
      agentId: lucasAgentId,
      messageId: privateMessageId,
    });
    const sharedPrivateControl = await waitFor(stephen, line => line.source === "control"
      && line.id === sharedPrivateRequest && line.ok === true && line.encrypted === true
      && line.sharedPrivateMessageId === privateMessageId);
    const sharedPrivateApproval = await waitFor(stephen, line => line.source === "agent-approval"
      && line.approvalState === "pending" && line.task?.id === sharedPrivateControl.taskId);
    stephen.send({ id: randomUUID(), type: "agent.approval", taskId: sharedPrivateApproval.task.id, approved: true });
    await waitFor(kai, line => line.frame?.type === "agent.result" && line.frame.taskId === sharedPrivateControl.taskId
      && line.frame.final === true && line.frame.event?.content?.includes(privateCanary));
    expect(readFileSync(join(stephenWorkspace, "stephen-account-execution.json"), "utf8")).toContain(privateCanary);
    traceCheckpoint("private message explicitly shared with agent");

    const artifactCanary = "ARTIFACT-HANDOFF-CANARY-4pV7s";
    const artifactId = randomUUID();
    const artifactPublish = randomUUID();
    kai.send({
      id: artifactPublish,
      type: "artifact.publish",
      artifactId,
      projectId: project.id,
      taskId: null,
      artifactType: "handoff",
      title: "Kai handoff",
      summary: "Explicit input for Stephen's agent",
      content: artifactCanary,
      status: "ready",
    });
    await waitFor(kai, line => line.frame?.type === "artifact.accepted"
      && line.frame.requestId === artifactPublish && line.frame.artifact?.id === artifactId);

    const encryptedStephenPrompt = "encrypted Stephen prompt never stored in server plaintext";
    const encryptedStephenRequest = randomUUID();
    kai.send({
      id: encryptedStephenRequest,
      type: "agent.request",
      projectId: project.id,
      agentId: lucasAgentId,
      prompt: encryptedStephenPrompt,
      inputArtifactIds: [artifactId],
    });
    const encryptedStephenControl = await waitFor(kai, line => line.source === "control"
      && line.id === encryptedStephenRequest && line.ok === true && line.encrypted === true);
    const encryptedStephenApproval = await waitFor(stephen, line => line.source === "agent-approval"
      && line.approvalState === "pending" && line.task?.id === encryptedStephenControl.taskId);
    stephen.send({ id: randomUUID(), type: "agent.approval", taskId: encryptedStephenApproval.task.id, approved: true });
    await waitFor(kai, line => line.frame?.type === "agent.result" && line.frame.taskId === encryptedStephenControl.taskId
      && line.frame.final === true && line.frame.event?.content?.includes(artifactCanary));
    const stephenExecution = readFileSync(join(stephenWorkspace, "stephen-account-execution.json"), "utf8");
    expect(stephenExecution).toContain(encryptedStephenPrompt);
    expect(stephenExecution).toContain(artifactCanary);
    traceCheckpoint("encrypted artifact consumed by Stephen agent");

    const encryptedKaiPrompt = "encrypted Kai prompt never stored in server plaintext";
    const encryptedKaiRequest = randomUUID();
    stephen.send({
      id: encryptedKaiRequest,
      type: "agent.request",
      projectId: project.id,
      agentId: sueAgentId,
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

    // Exercise the complete authoritative handoff chain with real resident
    // workers: Lucas findings -> Angela review -> Sue integration.
    rmSync(join(executionBarrier, "release"), { force: true });
    rmSync(lucasMarker, { force: true });
    const lucasChainPrompt = "Lucas: investigate the authentication failure and report a focused finding.";
    const lucasChainRequest = randomUUID();
    kai.send({
      id: lucasChainRequest,
      type: "agent.request",
      projectId: project.id,
      agentId: lucasAgentId,
      prompt: lucasChainPrompt,
    });
    const lucasChainControl = await waitFor(kai, line => line.source === "control"
      && line.id === lucasChainRequest && line.ok === true && line.encrypted === true);
    const lucasChainApproval = await waitFor(stephen, line => line.source === "agent-approval"
      && line.approvalState === "pending" && line.task?.id === lucasChainControl.taskId);
    stephen.send({ id: randomUUID(), type: "agent.approval", taskId: lucasChainControl.taskId, approved: true });
    await waitForPath(lucasMarker);

    const lucasFinding = "LUCAS-FINDING-refresh-token-persistence";
    const lucasArtifactId = randomUUID();
    const lucasArtifactPublish = randomUUID();
    stephen.send({
      id: lucasArtifactPublish,
      type: "artifact.publish",
      artifactId: lucasArtifactId,
      projectId: project.id,
      taskId: lucasChainControl.taskId,
      artifactType: "finding",
      title: "Lucas authentication finding",
      summary: "Focused finding for Angela",
      content: lucasFinding,
      status: "ready",
    });
    await waitFor(stephen, line => line.frame?.type === "artifact.accepted"
      && line.frame.requestId === lucasArtifactPublish && line.frame.artifact?.id === lucasArtifactId);
    await waitFor(kai, line => line.frame?.type === "artifact.published"
      && line.frame.artifact?.id === lucasArtifactId);

    const angelaChainPrompt = "Angela: verify Lucas's finding and prepare a tested handoff for Sue.";
    const angelaChainRequest = randomUUID();
    kai.send({
      id: angelaChainRequest,
      type: "agent.request",
      projectId: project.id,
      agentId: angelaAgentId,
      prompt: angelaChainPrompt,
      dependencies: [lucasChainControl.taskId],
      inputArtifactIds: [lucasArtifactId],
    });
    const angelaChainControl = await waitFor(kai, line => line.source === "control"
      && line.id === angelaChainRequest && line.ok === true && line.encrypted === true);
    expect(stephen.lines.some(line => line.source === "agent-approval"
      && line.task?.id === angelaChainControl.taskId)).toBeFalse();
    writeFileSync(join(executionBarrier, "release"), "release\n", "utf8");
    await waitFor(kai, line => line.frame?.type === "agent.result"
      && line.frame.taskId === lucasChainControl.taskId && line.frame.final === true);
    const angelaChainApproval = await waitFor(stephen, line => line.source === "agent-approval"
      && line.approvalState === "pending" && line.task?.id === angelaChainControl.taskId);
    rmSync(join(executionBarrier, "release"), { force: true });
    rmSync(angelaMarker, { force: true });
    stephen.send({ id: randomUUID(), type: "agent.approval", taskId: angelaChainControl.taskId, approved: true });
    await waitForPath(angelaMarker);
    expect(readFileSync(angelaMarker, "utf8")).toContain(lucasFinding);

    const angelaHandoff = "ANGELA-HANDOFF-refresh-token-tests-passed";
    const angelaArtifactId = randomUUID();
    const angelaArtifactPublish = randomUUID();
    stephen.send({
      id: angelaArtifactPublish,
      type: "artifact.publish",
      artifactId: angelaArtifactId,
      projectId: project.id,
      taskId: angelaChainControl.taskId,
      artifactType: "test-result",
      title: "Angela verified handoff",
      summary: "Verified implementation evidence for Sue",
      content: angelaHandoff,
      status: "accepted",
    });
    await waitFor(stephen, line => line.frame?.type === "artifact.accepted"
      && line.frame.requestId === angelaArtifactPublish && line.frame.artifact?.id === angelaArtifactId);

    const sueChainPrompt = "Sue: integrate the verified Lucas and Angela handoffs using the locally enabled full-computer profile.";
    const sueChainRequest = randomUUID();
    stephen.send({
      id: sueChainRequest,
      type: "agent.request",
      projectId: project.id,
      agentId: sueAgentId,
      prompt: sueChainPrompt,
      dependencies: [lucasChainControl.taskId, angelaChainControl.taskId],
      inputArtifactIds: [lucasArtifactId, angelaArtifactId],
    });
    const sueChainControl = await waitFor(stephen, line => line.source === "control"
      && line.id === sueChainRequest && line.ok === true && line.encrypted === true);
    expect(kai.lines.some(line => line.source === "agent-approval"
      && line.task?.id === sueChainControl.taskId)).toBeFalse();
    writeFileSync(join(executionBarrier, "release"), "release\n", "utf8");
    await waitFor(kai, line => line.frame?.type === "agent.result"
      && line.frame.taskId === angelaChainControl.taskId && line.frame.final === true
      && line.frame.event?.content?.includes(lucasFinding));
    const sueChainApproval = await waitFor(kai, line => line.source === "agent-approval"
      && line.approvalState === "pending" && line.task?.id === sueChainControl.taskId);
    kai.send({ id: randomUUID(), type: "agent.approval", taskId: sueChainControl.taskId, approved: true });
    await waitFor(stephen, line => line.frame?.type === "agent.result"
      && line.frame.taskId === sueChainControl.taskId && line.frame.final === true
      && line.frame.event?.content?.includes(angelaHandoff));
    const sueExecution = JSON.parse(readFileSync(join(kaiWorkspace, "kai-account-execution.json"), "utf8")) as {
      prompt: string;
      args: string[];
      sandbox: string;
    };
    expect(sueExecution.prompt).toContain(lucasFinding);
    expect(sueExecution.prompt).toContain(angelaHandoff);
    expect(sueExecution.args).toEqual(expect.arrayContaining([
      "--model", "gpt-5.6-sol", "danger-full-access",
    ]));
    expect(sueExecution.sandbox).toBe("danger-full-access");

    const sueArtifactId = randomUUID();
    const sueArtifactPublish = randomUUID();
    const sueIntegrated = "SUE-INTEGRATED-private-alpha-chain";
    kai.send({
      id: sueArtifactPublish,
      type: "artifact.publish",
      artifactId: sueArtifactId,
      projectId: project.id,
      taskId: sueChainControl.taskId,
      artifactType: "code-change",
      title: "Sue integrated result",
      summary: "Lucas and Angela handoffs integrated by Sue",
      content: sueIntegrated,
      status: "integrated",
    });
    await waitFor(kai, line => line.frame?.type === "artifact.accepted"
      && line.frame.requestId === sueArtifactPublish && line.frame.artifact?.id === sueArtifactId);
    traceCheckpoint("Lucas to Angela to Sue artifact chain completed");

    const taskEvidenceRequest = randomUUID();
    stephen.send({ id: taskEvidenceRequest, type: "agent.task.list", projectId: project.id });
    const taskEvidence = await waitFor(stephen, line => line.frame?.type === "agent.task.list.result"
      && line.frame.requestId === taskEvidenceRequest);
    expect(taskEvidence.frame.tasks).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: encryptedStephenControl.taskId,
        workspaceMode: "shared",
        workspaceRef: "configured-workspace",
        branch: null,
        baseCommit: null,
        mergeTarget: null,
        startedAt: expect.any(String),
      }),
      expect.objectContaining({
        id: encryptedKaiControl.taskId,
        workspaceMode: "shared",
        workspaceRef: "configured-workspace",
        startedAt: expect.any(String),
      }),
      expect.objectContaining({
        id: angelaChainControl.taskId,
        dependencies: [lucasChainControl.taskId],
        inputArtifactIds: [lucasArtifactId],
        status: "completed",
      }),
      expect.objectContaining({
        id: sueChainControl.taskId,
        dependencies: [lucasChainControl.taskId, angelaChainControl.taskId],
        inputArtifactIds: [lucasArtifactId, angelaArtifactId],
        status: "completed",
      }),
    ]));

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
      expect.objectContaining({ deviceId: stephenDevice.id, report: expect.objectContaining({ requests: 6 }) }),
      expect.objectContaining({ deviceId: kaiDevice.id, report: expect.objectContaining({ requests: 3 }) }),
    ]));
    expect(usageReportsK).toEqual(expect.arrayContaining([
      expect.objectContaining({ deviceId: stephenDevice.id, report: expect.objectContaining({ inputTokens: expect.any(Number) }) }),
      expect.objectContaining({ deviceId: kaiDevice.id, report: expect.objectContaining({ outputTokens: expect.any(Number) }) }),
    ]));

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
      text: offlinePrivateS,
    });
    stephen.send({
      id: offlinePrivateRequestK,
      type: "private.send",
      recipientDeviceId: kaiDevice.id,
      text: offlinePrivateK,
    });
    await Promise.all([
      waitFor(stephen, line => line.source === "control" && line.id === offlineS && line.queued === true),
      waitFor(kai, line => line.source === "control" && line.id === offlineK && line.queued === true),
      waitFor(kai, line => line.source === "control" && line.id === offlinePrivateRequestS && line.queued === true),
      waitFor(stephen, line => line.source === "control" && line.id === offlinePrivateRequestK && line.queued === true),
    ]);

    traceCheckpoint("offline queues accepted");
    const workerReconnectCheckpointS = stephen.lines.length;
    const workerReconnectCheckpointK = kai.lines.length;
    server = startServer();
    await waitFor(server, line => line.ready === true);
    await Promise.all([
      waitFor(stephen, line => line.source === "session" && line.state === "connected" && line.flushedEvents >= 1),
      waitFor(kai, line => line.source === "session" && line.state === "connected" && line.flushedEvents >= 1),
    ]);
    await Promise.all([
      waitForAfter(stephen, workerReconnectCheckpointS,
        line => line.frame?.type === "agent.ready.accepted" && line.frame.agentId === lucasAgentId),
      waitForAfter(stephen, workerReconnectCheckpointS,
        line => line.frame?.type === "agent.ready.accepted" && line.frame.agentId === angelaAgentId),
      waitForAfter(kai, workerReconnectCheckpointK,
        line => line.frame?.type === "agent.ready.accepted" && line.frame.agentId === sueAgentId),
    ]);
    await Promise.all([
      waitFor(stephen, line => line.source === "private" && line.message?.text === offlinePrivateS),
      waitFor(kai, line => line.source === "private" && line.message?.text === offlinePrivateK),
    ]);
    const [stephenPrivateMailbox, kaiPrivateMailbox] = await Promise.all([
      waitForMailbox(join(stephenRoot, "private-mailbox.json"), 3),
      waitForMailbox(join(kaiRoot, "private-mailbox.json"), 3, { messageId: privateMessageId, receipt: "read" }),
    ]);
    expect(stephenPrivateMailbox.cursor).toBe(kaiPrivateMailbox.cursor);
    expect(stephenPrivateMailbox.receipts.length).toBeGreaterThanOrEqual(3);
    expect(kaiPrivateMailbox.receipts.length).toBeGreaterThanOrEqual(3);
    expect(kaiPrivateMailbox.remoteReceipts?.some(receipt => receipt.messageId === privateMessageId && receipt.receipt === "read")).toBeTrue();
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
      expect.objectContaining({ deviceId: stephenDevice.id, report: expect.objectContaining({ requests: 6 }) }),
      expect.objectContaining({ deviceId: kaiDevice.id, report: expect.objectContaining({ requests: 3 }) }),
    ]));

    traceCheckpoint("restarting Stephen client for private history");
    stephen.send({ id: "restart-stephen", type: "shutdown" });
    await stephen.process.exited;
    residents.splice(residents.indexOf(stephen), 1);
    stephen = startResident(clientExe, ["connect", "--json-lines", "--state-root", stephenRoot], {
      CODEX_CLI_PATH: fixtureExe,
      COCODEX_ACCOUNT_FIXTURE: "stephen-account",
      CODEX_RUNTIME_MARKER: JSON.stringify({ barrierDirectory: executionBarrier }),
    });
    const [restoredInbound, restoredOutbound] = await Promise.all([
      waitFor(stephen, line => line.source === "private"
        && line.message?.text === privateCanary
        && line.message?.direction === "received"
        && line.message?.restored === true),
      waitFor(stephen, line => line.source === "private"
        && line.message?.text === offlinePrivateK
        && line.message?.direction === "sent"
        && line.message?.restored === true),
    ]);
    expect(restoredInbound.message.messageId).toBe(privateMessageId);
    expect(restoredOutbound.message.senderDeviceId).toBe(stephenDevice.id);
    await waitFor(stephen, line => line.source === "session" && line.state === "connected");
    const privateHistoryRaw = readFileSync(join(stephenRoot, "private-history.json"), "utf8");
    expect(privateHistoryRaw).not.toContain(privateCanary);
    expect(privateHistoryRaw).not.toContain(offlinePrivateK);
    expect(privateHistoryRaw).toContain("localCiphertext");

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

    traceCheckpoint("restarting Kai offline for private history and receipts");
    kai = startResident(clientExe, ["connect", "--json-lines", "--state-root", kaiRoot], {
      CODEX_CLI_PATH: fixtureExe,
      COCODEX_ACCOUNT_FIXTURE: "kai-account",
      CODEX_RUNTIME_MARKER: JSON.stringify({ barrierDirectory: executionBarrier }),
    });
    const [offlineRestoredMessage, offlineRestoredRead, offlineRestoredContacts] = await Promise.all([
      waitFor(kai, line => line.source === "private"
        && line.message?.messageId === privateMessageId
        && line.message?.text === privateCanary
        && line.message?.direction === "sent"
        && line.message?.restored === true),
      waitFor(kai, line => line.source === "private-receipt"
        && line.receipt?.messageId === privateMessageId
        && line.receipt?.receipt === "read"),
      waitFor(kai, line => line.source === "private-contacts"
        && line.contacts?.some((contact: any) =>
          contact.deviceId === stephenDevice.id && contact.trusted === true)),
    ]);
    expect(offlineRestoredMessage.message.serverSequence).toBeGreaterThan(0);
    expect(offlineRestoredRead.receipt.senderDeviceId).toBe(kaiDevice.id);
    expect(JSON.stringify(offlineRestoredContacts)).not.toContain("deviceKeyCertificate");
    const cachedContactCanary = "private send from cached contact while server is down";
    const cachedContactRequest = randomUUID();
    kai.send({
      id: cachedContactRequest,
      type: "private.send",
      recipientDeviceId: stephenDevice.id,
      text: cachedContactCanary,
    });
    const cachedQueued = await waitFor(kai, line => line.source === "control"
      && line.id === cachedContactRequest
      && line.ok === true
      && line.queued === true);
    const afterRevocationChat = "later work drains after cached recipient revocation";
    const afterRevocationChatRequest = randomUUID();
    kai.send({
      id: afterRevocationChatRequest,
      type: "chat.send",
      projectId: project.id,
      content: afterRevocationChat,
    });
    await waitFor(kai, line => line.source === "control"
      && line.id === afterRevocationChatRequest
      && line.ok === true
      && line.queued === true);
    const cachedContactOutbox = readFileSync(join(kaiRoot, "outbox.json"), "utf8");
    expect(cachedContactOutbox).not.toContain(cachedContactCanary);
    expect(cachedContactOutbox).toContain("\"type\": \"private.send\"");
    kai.send({ id: "stop-offline-k", type: "shutdown" });
    await kai.process.exited;
    residents.splice(residents.indexOf(kai), 1);

    await run(serverExe, [
      "revoke", "--fingerprint", stephenDevice.fingerprint, "--state-root", serverRoot,
    ]);
    server = startServer();
    await waitFor(server, line => line.ready === true);
    kai = startResident(clientExe, ["connect", "--json-lines", "--state-root", kaiRoot], {
      CODEX_CLI_PATH: fixtureExe,
      COCODEX_ACCOUNT_FIXTURE: "kai-account",
      CODEX_RUNTIME_MARKER: JSON.stringify({ barrierDirectory: executionBarrier }),
    });
    const rejectedCachedSend = await waitFor(kai, line => line.source === "private"
      && line.message?.messageId === cachedQueued.messageId
      && line.message?.deliveryState === "rejected");
    expect(rejectedCachedSend.message.rejectionReason).toContain("not approved");
    await waitFor(kai, line => line.source === "session"
      && line.state === "connected"
      && line.flushedEvents >= 1);
    const afterRevocationSubscribe = randomUUID();
    kai.send({
      id: afterRevocationSubscribe,
      type: "chat.subscribe",
      projectId: project.id,
      afterSequence: 0,
    });
    await waitFor(kai, line => line.frame?.type === "chat.snapshot"
      && line.frame.requestId === afterRevocationSubscribe
      && line.frame.events?.some((event: any) => event.content === afterRevocationChat));
    expect(readFileSync(join(kaiRoot, "outbox.json"), "utf8")).not.toContain(cachedQueued.messageId);
    kai.send({ id: "stop-revocation-k", type: "shutdown" });
    await kai.process.exited;
    residents.splice(residents.indexOf(kai), 1);
    server.process.kill();
    await server.process.exited;
    residents.splice(residents.indexOf(server), 1);

    const db = new Database(join(serverRoot, "server.sqlite3"), { readonly: true });
    const ciphertext = db.query("SELECT ciphertext FROM private_messages").get() as { ciphertext: string };
    const encryptedTasks = db.query(`
      SELECT id, prompt, prompt_envelope_json AS promptEnvelopeJson
      FROM agent_tasks WHERE id IN (?, ?, ?, ?, ?, ?)
      ORDER BY id
    `).all(
      sharedPrivateControl.taskId,
      encryptedStephenControl.taskId,
      encryptedKaiControl.taskId,
      lucasChainControl.taskId,
      angelaChainControl.taskId,
      sueChainControl.taskId,
    ) as Array<{
      id: string; prompt: string; promptEnvelopeJson: string;
    }>;
    const encryptedResults = db.query(`
      SELECT task_id AS taskId, envelope_json AS envelopeJson
      FROM project_chat_events WHERE task_id IN (?, ?, ?, ?, ?, ?)
      ORDER BY task_id, sequence
    `).all(
      sharedPrivateControl.taskId,
      encryptedStephenControl.taskId,
      encryptedKaiControl.taskId,
      lucasChainControl.taskId,
      angelaChainControl.taskId,
      sueChainControl.taskId,
    ) as Array<{
      taskId: string; envelopeJson: string;
    }>;
    const duplicateCounts = db.query(`
      SELECT COUNT(*) AS total, COUNT(DISTINCT event_id) AS uniqueIds FROM chat_events
    `).get() as { total: number; uniqueIds: number };
    db.close();
    expect(ciphertext.ciphertext).not.toContain(privateCanary);
    const serverDatabaseBytes = readFileSync(join(serverRoot, "server.sqlite3"));
    for (const secret of [
      privateCanary,
      encryptedStephenPrompt,
      encryptedKaiPrompt,
      lucasChainPrompt,
      lucasFinding,
      angelaChainPrompt,
      angelaHandoff,
      sueChainPrompt,
      sueIntegrated,
    ]) {
      expect(serverDatabaseBytes.includes(Buffer.from(secret))).toBeFalse();
    }
    expect(duplicateCounts.total).toBe(duplicateCounts.uniqueIds);
    expect(readFileSync(join(kaiWorkspace, "kai-account-execution.json"), "utf8")).not.toContain(privateCanary);
    expect(encryptedTasks).toHaveLength(6);
    for (const task of encryptedTasks) {
      expect(task.prompt).toBe("[encrypted]");
      for (const secret of [
        encryptedStephenPrompt, encryptedKaiPrompt, privateCanary,
        lucasChainPrompt, lucasFinding, angelaChainPrompt, angelaHandoff,
        sueChainPrompt, sueIntegrated,
      ]) expect(task.promptEnvelopeJson).not.toContain(secret);
      expect(task.promptEnvelopeJson).toContain("ciphertext");
    }
    expect(encryptedResults.length).toBeGreaterThanOrEqual(6);
    for (const result of encryptedResults) {
      for (const secret of [
        encryptedStephenPrompt, encryptedKaiPrompt, privateCanary,
        lucasChainPrompt, lucasFinding, angelaChainPrompt, angelaHandoff,
        sueChainPrompt, sueIntegrated,
      ]) expect(result.envelopeJson).not.toContain(secret);
      expect(result.envelopeJson).toContain("ciphertext");
    }
  }, 120_000);
});
