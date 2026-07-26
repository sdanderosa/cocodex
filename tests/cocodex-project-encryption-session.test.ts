import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { PassThrough } from "node:stream";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Database } from "bun:sqlite";
import * as Y from "yjs";
import { publicKeyFingerprint } from "@cocodex/protocol";
import { createDefaultConfig } from "../apps/cocodex-server/src/config";
import { openDatabase } from "../apps/cocodex-server/src/database";
import { approveDevice } from "../apps/cocodex-server/src/enrollment";
import { createServerIdentity } from "../apps/cocodex-server/src/identity";
import { createInvitation } from "../apps/cocodex-server/src/invitations";
import { serverPaths } from "../apps/cocodex-server/src/paths";
import { addProjectMember, createProject } from "../apps/cocodex-server/src/shared-state";
import { startCoCodexServer } from "../apps/cocodex-server/src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../apps/cocodex-server/src/tls";
import { enrollClient } from "../src/cocodex/client";
import { loadOrCreateClientIdentity } from "../src/cocodex/identity";
import { clientPaths } from "../src/cocodex/paths";
import { runJsonLineSession } from "../src/cocodex/session";
import { loadLocalAgentPolicies, loadLocalAgentPolicy } from "../src/cocodex/agent-policy";
import { trustDevice } from "../src/cocodex/trusted-devices";

const roots: string[] = [];
const servers: Array<{ stop(force?: boolean): Promise<void> }> = [];
const databases: Database[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => server.stop(true)));
  for (const database of databases.splice(0)) database.close();
  Bun.gc(true);
  for (const root of roots.splice(0)) {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        rmSync(root, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 99) throw error;
        await Bun.sleep(50);
      }
    }
  }
});

class JsonSessionHarness {
  readonly input = new PassThrough();
  readonly output = new PassThrough();
  readonly errors = new PassThrough();
  private readonly events: Record<string, unknown>[] = [];
  private readonly waiters: Array<{
    predicate: (event: Record<string, unknown>) => boolean;
    resolve: (event: Record<string, unknown>) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  constructor() {
    for (const stream of [this.output, this.errors]) {
      stream.setEncoding("utf8");
      stream.on("data", chunk => {
        for (const line of String(chunk).split("\n")) {
          if (!line.trim()) continue;
          let value: Record<string, unknown>;
          try { value = JSON.parse(line) as Record<string, unknown>; }
          catch { continue; }
          this.events.push(value);
          for (let index = this.waiters.length - 1; index >= 0; index -= 1) {
            const waiter = this.waiters[index];
            if (!waiter.predicate(value)) continue;
            clearTimeout(waiter.timer);
            this.waiters.splice(index, 1);
            waiter.resolve(value);
          }
        }
      });
    }
  }

  send(command: Record<string, unknown>): void {
    this.input.write(`${JSON.stringify(command)}\n`);
  }

  waitFor(predicate: (event: Record<string, unknown>) => boolean, timeoutMs = 15_000): Promise<Record<string, unknown>> {
    const existing = this.events.find(predicate);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.waiters.findIndex(waiter => waiter.timer === timer);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error(`Timed out waiting for CoCodex session event; recent=${JSON.stringify(this.events.slice(-8))}`));
      }, timeoutMs);
      this.waiters.push({ predicate, resolve, reject, timer });
    });
  }

  close(): void {
    this.send({ type: "shutdown" });
    this.input.end();
    this.errors.end();
  }
}

async function waitUntilConnectedViaProjectList(session: JsonSessionHarness): Promise<void> {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const id = crypto.randomUUID();
    session.send({ id, type: "project.list" });
    try {
      const result = await session.waitFor(event =>
        (event.source === "server" && (event.frame as Record<string, unknown> | undefined)?.requestId === id)
        || (event.source === "control" && event.id === id), 750);
      if (result.source === "server") return;
    } catch {
      // The resident session may still be between reconnect attempts.
    }
    await Bun.sleep(250);
  }
  throw new Error("CoCodex session did not reconnect before the recovery deadline");
}

describe("CoCodex encrypted project context session", () => {
  test("initializes a project key, encrypts context on the wire, and decrypts it on another client", async () => {
    const serverRoot = mkdtempSync(join(tmpdir(), "cocodex-project-session-server-"));
    const stephenRoot = mkdtempSync(join(tmpdir(), "cocodex-project-session-stephen-"));
    const kaiRoot = mkdtempSync(join(tmpdir(), "cocodex-project-session-kai-"));
    roots.push(serverRoot, stephenRoot, kaiRoot);

    const paths = serverPaths(serverRoot);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths, "127.0.0.1");
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);

    const stephenConnection = await enrollClient(createInvitation(db, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint,
    }), "Stephen", clientPaths(stephenRoot));
    const stephenRow = db.query("SELECT fingerprint FROM devices WHERE id = ?")
      .get(stephenConnection.deviceId) as { fingerprint: string };
    expect(approveDevice(db, stephenRow.fingerprint)).toBeTrue();

    const kaiConnection = await enrollClient(createInvitation(db, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint,
    }), "Kai", clientPaths(kaiRoot));
    const kaiRow = db.query("SELECT fingerprint FROM devices WHERE id = ?")
      .get(kaiConnection.deviceId) as { fingerprint: string };
    expect(approveDevice(db, kaiRow.fingerprint)).toBeTrue();

    const project = createProject(db, "Encrypted session project", stephenConnection.deviceId);
    addProjectMember(db, project.id, stephenConnection.deviceId, kaiConnection.deviceId);
    const stephenPaths = clientPaths(stephenRoot);
    const kaiPaths = clientPaths(kaiRoot);
    const stephenIdentity = loadOrCreateClientIdentity(stephenPaths);
    const kaiIdentity = loadOrCreateClientIdentity(kaiPaths);
    trustDevice(kaiPaths.trustedDevices, stephenConnection.deviceId, publicKeyFingerprint(stephenIdentity.publicKeyPem));
    trustDevice(stephenPaths.trustedDevices, kaiConnection.deviceId, publicKeyFingerprint(kaiIdentity.publicKeyPem));

    const stephen = new JsonSessionHarness();
    const kai = new JsonSessionHarness();
    const stephenRun = runJsonLineSession(stephenPaths, { input: stephen.input, output: stephen.output, errorOutput: stephen.errors });
    const kaiRun = runJsonLineSession(kaiPaths, { input: kai.input, output: kai.output, errorOutput: kai.errors });
    await Promise.all([
      stephen.waitFor(event => event.source === "session" && event.state === "connected"),
      kai.waitFor(event => event.source === "session" && event.state === "connected"),
    ]);

    stephen.send({
      id: crypto.randomUUID(),
      type: "project.key.initialize",
      projectId: project.id,
      keyEpoch: 1,
      recipients: [
        { deviceId: stephenConnection.deviceId, projectWrapPublicKeyPem: stephenIdentity.projectWrapPublicKeyPem },
        { deviceId: kaiConnection.deviceId, projectWrapPublicKeyPem: kaiIdentity.projectWrapPublicKeyPem },
      ],
    });
    await stephen.waitFor(event => event.source === "control" && event.ok === true && event.sharedRecipients === 2);
    await new Promise(resolve => setTimeout(resolve, 50));

    kai.send({ id: crypto.randomUUID(), type: "project.key.get", projectId: project.id });
    await kai.waitFor(event => event.source === "project-encryption" && event.state === "key-available" && event.projectId === project.id);

    stephen.send({ id: crypto.randomUUID(), type: "chat.subscribe", projectId: project.id });
    kai.send({ id: crypto.randomUUID(), type: "chat.subscribe", projectId: project.id });
    await Promise.all([
      stephen.waitFor(event => event.source === "server" && (event.frame as Record<string, unknown> | undefined)?.type === "chat.snapshot"),
      kai.waitFor(event => event.source === "server" && (event.frame as Record<string, unknown> | undefined)?.type === "chat.snapshot"),
    ]);
    const plaintextChat = "This encrypted chat payload stays off the server";
    stephen.send({ id: crypto.randomUUID(), type: "chat.send", projectId: project.id, content: plaintextChat });
    const [stephenChat, kaiChat] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "chat.event"
        && ((event.frame as Record<string, unknown>).event as Record<string, unknown> | undefined)?.content === plaintextChat),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "chat.event"
        && ((event.frame as Record<string, unknown>).event as Record<string, unknown> | undefined)?.content === plaintextChat),
    ]);
    expect(stephenChat.frame).toMatchObject({ type: "chat.event", projectId: project.id });
    expect(kaiChat.frame).toMatchObject({ type: "chat.event", projectId: project.id });
    const encryptedChat = db.query("SELECT envelope_json AS envelopeJson FROM project_chat_events WHERE project_id = ?")
      .get(project.id) as { envelopeJson: string };
    expect(encryptedChat.envelopeJson).not.toContain(plaintextChat);
    expect(encryptedChat.envelopeJson).toContain("ciphertext");

    stephen.send({ id: crypto.randomUUID(), type: "prompt.subscribe", projectId: project.id });
    kai.send({ id: crypto.randomUUID(), type: "prompt.subscribe", projectId: project.id });
    await Promise.all([
      stephen.waitFor(event => event.source === "server" && (event.frame as Record<string, unknown> | undefined)?.type === "prompt.snapshot"),
      kai.waitFor(event => event.source === "server" && (event.frame as Record<string, unknown> | undefined)?.type === "prompt.snapshot"),
    ]);
    const promptDocument = new Y.Doc();
    const promptText = "Encrypted shared prompt text";
    promptDocument.getText("prompt").insert(0, promptText);
    const promptUpdate = Buffer.from(Y.encodeStateAsUpdate(promptDocument)).toString("base64");
    stephen.send({ id: crypto.randomUUID(), type: "prompt.update", projectId: project.id, update: promptUpdate });
    const [promptRecovered] = await Promise.all([
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "prompt.update"
        && ((event.frame as Record<string, unknown>).update as string | undefined) === promptUpdate),
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "prompt.update"
        && ((event.frame as Record<string, unknown>).update as string | undefined) === promptUpdate),
    ]);
    expect(promptRecovered.frame).toMatchObject({ type: "prompt.update", projectId: project.id, update: promptUpdate });
    const recoveredPromptDocument = new Y.Doc();
    Y.applyUpdate(recoveredPromptDocument, Buffer.from(promptUpdate, "base64"));
    expect(recoveredPromptDocument.getText("prompt").toString()).toBe(promptText);
    const encryptedPrompt = db.query("SELECT envelope_json AS envelopeJson FROM project_prompt_updates WHERE project_id = ?")
      .get(project.id) as { envelopeJson: string };
    expect(encryptedPrompt.envelopeJson).not.toContain(promptUpdate);
    expect(encryptedPrompt.envelopeJson).not.toContain(promptText);
    expect(encryptedPrompt.envelopeJson).toContain("ciphertext");

    const plaintextGoal = "This goal must never be stored by the collaboration server";
    stephen.send({
      id: crypto.randomUUID(),
      type: "project.context.update",
      projectId: project.id,
      expectedRevision: 0,
      finalGoal: plaintextGoal,
      context: { acceptance: ["opaque storage", "local decryption"] },
    });
    const updated = await stephen.waitFor(event => event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "context.updated"
      && ((event.frame as Record<string, unknown>).context as Record<string, unknown> | undefined)?.finalGoal === plaintextGoal);
    expect(updated.frame).toMatchObject({ type: "context.updated", projectId: project.id });

    kai.send({ id: crypto.randomUUID(), type: "project.context.get", projectId: project.id });
    const recovered = await kai.waitFor(event => event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "context.result"
      && ((event.frame as Record<string, unknown>).context as Record<string, unknown> | undefined)?.finalGoal === plaintextGoal);
    expect(recovered.frame).toMatchObject({ type: "context.result", projectId: project.id });

    const stored = db.query("SELECT envelope_json AS envelopeJson FROM encrypted_project_context WHERE project_id = ?")
      .get(project.id) as { envelopeJson: string };
    expect(stored.envelopeJson).not.toContain(plaintextGoal);
    expect(stored.envelopeJson).toContain("ciphertext");

    const artifactSubscribeStephen = crypto.randomUUID();
    const artifactSubscribeKai = crypto.randomUUID();
    stephen.send({ id: artifactSubscribeStephen, type: "artifact.list", projectId: project.id });
    kai.send({ id: artifactSubscribeKai, type: "artifact.list", projectId: project.id });
    await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "artifact.list.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === artifactSubscribeStephen),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "artifact.list.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === artifactSubscribeKai),
    ]);

    const artifactId = crypto.randomUUID();
    const artifactTitle = "Encrypted handoff finding";
    const artifactContent = "The artifact body is decrypted only by enrolled project members.";
    stephen.send({
      id: crypto.randomUUID(),
      type: "artifact.publish",
      projectId: project.id,
      artifactId,
      taskId: null,
      artifactType: "finding",
      title: artifactTitle,
      summary: "Opaque artifact summary",
      content: artifactContent,
      status: "ready",
    });
    const [artifactAtStephen, artifactAtKai] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "artifact.accepted"
        && ((event.frame as Record<string, unknown>).artifact as Record<string, unknown> | undefined)?.id === artifactId),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "artifact.published"
        && ((event.frame as Record<string, unknown>).artifact as Record<string, unknown> | undefined)?.id === artifactId),
    ]);
    expect(artifactAtStephen.frame).toMatchObject({ type: "artifact.accepted", projectId: project.id });
    expect(artifactAtKai.frame).toMatchObject({ type: "artifact.published", projectId: project.id });
    expect((artifactAtKai.frame as Record<string, any>).artifact).toMatchObject({
      id: artifactId,
      title: artifactTitle,
      content: artifactContent,
      status: "ready",
    });
    const storedArtifact = db.query("SELECT envelope_json AS envelopeJson FROM project_artifacts WHERE id = ?")
      .get(artifactId) as { envelopeJson: string };
    expect(storedArtifact.envelopeJson).not.toContain(artifactTitle);
    expect(storedArtifact.envelopeJson).not.toContain(artifactContent);
    expect(storedArtifact.envelopeJson).toContain("ciphertext");

    const stephenDisconnected = stephen.waitFor(event => event.source === "session" && event.state === "disconnected");
    const kaiDisconnected = kai.waitFor(event => event.source === "session" && event.state === "disconnected");
    const serverIndex = servers.indexOf(server);
    if (serverIndex >= 0) servers.splice(serverIndex, 1);
    await server.stop(true);
    await Promise.all([stephenDisconnected, kaiDisconnected]);
    const restarted = startCoCodexServer({ ...config, port: server.port }, db, identity);
    servers.push(restarted);
    await Promise.all([
      waitUntilConnectedViaProjectList(stephen),
      waitUntilConnectedViaProjectList(kai),
    ]);

    const recoveredChatStephen = crypto.randomUUID();
    const recoveredChatKai = crypto.randomUUID();
    stephen.send({ id: recoveredChatStephen, type: "chat.subscribe", projectId: project.id, afterSequence: 0 });
    kai.send({ id: recoveredChatKai, type: "chat.subscribe", projectId: project.id, afterSequence: 0 });
    const [chatSnapshotStephen, chatSnapshotKai] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "chat.snapshot"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === recoveredChatStephen),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "chat.snapshot"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === recoveredChatKai),
    ]);
    expect((chatSnapshotStephen.frame as Record<string, unknown>).events).toEqual(expect.arrayContaining([
      expect.objectContaining({ content: plaintextChat }),
    ]));
    expect((chatSnapshotKai.frame as Record<string, unknown>).events).toEqual(expect.arrayContaining([
      expect.objectContaining({ content: plaintextChat }),
    ]));

    const recoveredPromptStephen = crypto.randomUUID();
    const recoveredPromptKai = crypto.randomUUID();
    stephen.send({ id: recoveredPromptStephen, type: "prompt.subscribe", projectId: project.id, afterSequence: 0 });
    kai.send({ id: recoveredPromptKai, type: "prompt.subscribe", projectId: project.id, afterSequence: 0 });
    const [promptSnapshotStephen, promptSnapshotKai] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "prompt.snapshot"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === recoveredPromptStephen),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "prompt.snapshot"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === recoveredPromptKai),
    ]);
    for (const snapshot of [promptSnapshotStephen, promptSnapshotKai]) {
      expect((snapshot.frame as Record<string, unknown>).updates).toEqual(expect.arrayContaining([
        expect.objectContaining({ update: promptUpdate }),
      ]));
    }

    const recoveredContextStephen = crypto.randomUUID();
    const recoveredContextKai = crypto.randomUUID();
    stephen.send({ id: recoveredContextStephen, type: "project.context.get", projectId: project.id });
    kai.send({ id: recoveredContextKai, type: "project.context.get", projectId: project.id });
    const [contextSnapshotStephen, contextSnapshotKai] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "context.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === recoveredContextStephen),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "context.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === recoveredContextKai),
    ]);
    expect((contextSnapshotStephen.frame as Record<string, unknown>).context).toMatchObject({ finalGoal: plaintextGoal });
    expect((contextSnapshotKai.frame as Record<string, unknown>).context).toMatchObject({ finalGoal: plaintextGoal });

    const artifactListStephen = crypto.randomUUID();
    const artifactListKai = crypto.randomUUID();
    stephen.send({ id: artifactListStephen, type: "artifact.list", projectId: project.id });
    kai.send({ id: artifactListKai, type: "artifact.list", projectId: project.id });
    const [artifactSnapshotStephen, artifactSnapshotKai] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "artifact.list.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === artifactListStephen),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "artifact.list.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === artifactListKai),
    ]);
    for (const snapshot of [artifactSnapshotStephen, artifactSnapshotKai]) {
      expect((snapshot.frame as Record<string, unknown>).artifacts).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: artifactId, content: artifactContent }),
      ]));
    }

    stephen.close();
    kai.close();
    await Promise.all([stephenRun, kaiRun]);
  }, 30_000);

  test("configures two signed self-hosted agents with independent ready workers", async () => {
    const serverRoot = mkdtempSync(join(tmpdir(), "cocodex-agent-setup-server-"));
    const stephenRoot = mkdtempSync(join(tmpdir(), "cocodex-agent-setup-client-"));
    const kaiRoot = mkdtempSync(join(tmpdir(), "cocodex-agent-setup-trusted-"));
    const repository = join(stephenRoot, "repository");
    roots.push(serverRoot, stephenRoot, kaiRoot);
    expect(Bun.spawnSync(["git", "init", "-b", "main", repository], {
      stdout: "ignore",
      stderr: "ignore",
    }).exitCode).toBe(0);

    const paths = serverPaths(serverRoot);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths, "127.0.0.1");
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);

    const stephenPaths = clientPaths(stephenRoot);
    const stephenConnection = await enrollClient(createInvitation(db, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint,
    }), "Stephen", stephenPaths);
    const stephenRow = db.query("SELECT fingerprint FROM devices WHERE id = ?")
      .get(stephenConnection.deviceId) as { fingerprint: string };
    expect(approveDevice(db, stephenRow.fingerprint)).toBeTrue();

    const kaiPaths = clientPaths(kaiRoot);
    const kaiConnection = await enrollClient(createInvitation(db, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint,
    }), "Kai", kaiPaths);
    const kaiRow = db.query("SELECT fingerprint FROM devices WHERE id = ?")
      .get(kaiConnection.deviceId) as { fingerprint: string };
    expect(approveDevice(db, kaiRow.fingerprint)).toBeTrue();
    const project = createProject(db, "Agent setup project", stephenConnection.deviceId);
    addProjectMember(db, project.id, stephenConnection.deviceId, kaiConnection.deviceId);
    const kaiIdentity = loadOrCreateClientIdentity(kaiPaths);

    const stephen = new JsonSessionHarness();
    const stephenRun = runJsonLineSession(stephenPaths, {
      input: stephen.input,
      output: stephen.output,
      errorOutput: stephen.errors,
    });
    await stephen.waitFor(event => event.source === "session" && event.state === "connected", 25_000);
    const configureId = crypto.randomUUID();
    stephen.send({
      id: configureId,
      type: "agent.configure",
      projectId: project.id,
      name: "Lucas",
      workspaceRoot: repository,
      workspaceMode: "git-worktree",
      trustedRequesterDeviceId: kaiConnection.deviceId,
      trustedRequesterFingerprint: publicKeyFingerprint(kaiIdentity.publicKeyPem),
    });
    const configured = await stephen.waitFor(event =>
      event.source === "agent-configuration" && event.id === configureId && event.configured === true, 25_000);
    expect(configured).toMatchObject({ projectId: project.id, created: true });
    const policy = loadLocalAgentPolicy(stephenPaths.agentPolicy);
    expect(policy).toMatchObject({
      projectId: project.id,
      agentId: configured.agentId,
      workspaceRoot: repository,
      workspaceMode: "git-worktree",
      accessProfile: "project-only",
    });
    await stephen.waitFor(event => event.source === "agent-worker"
      && event.agentId === configured.agentId
      && (event.frame as Record<string, unknown> | undefined)?.type === "agent.ready.accepted", 25_000);
    const angelaConfigureId = crypto.randomUUID();
    stephen.send({
      id: angelaConfigureId,
      type: "agent.configure",
      projectId: project.id,
      name: "Angela",
      workspaceRoot: repository,
      workspaceMode: "git-worktree",
      trustedRequesterDeviceId: kaiConnection.deviceId,
      trustedRequesterFingerprint: publicKeyFingerprint(kaiIdentity.publicKeyPem),
    });
    const angelaConfigured = await stephen.waitFor(event =>
      event.source === "agent-configuration" && event.id === angelaConfigureId && event.configured === true, 25_000);
    await stephen.waitFor(event => event.source === "agent-worker"
      && event.agentId === angelaConfigured.agentId
      && (event.frame as Record<string, unknown> | undefined)?.type === "agent.ready.accepted", 25_000);
    expect(loadLocalAgentPolicies(stephenPaths.agentPolicy).map(item => item.agentId)).toEqual([
      configured.agentId,
      angelaConfigured.agentId,
    ]);
    const rosterRequest = crypto.randomUUID();
    stephen.send({ id: rosterRequest, type: "agent.list", projectId: project.id });
    const roster = await stephen.waitFor(event => event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "agent.list.result"
      && (event.frame as Record<string, unknown> | undefined)?.requestId === rosterRequest);
    const rosterAgents = (roster.frame as Record<string, unknown>).agents as unknown[];
    expect(rosterAgents).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: configured.agentId,
        name: "Lucas",
        hostDeviceId: stephenConnection.deviceId,
        status: "available",
      }),
      expect.objectContaining({
        id: angelaConfigured.agentId,
        name: "Angela",
        hostDeviceId: stephenConnection.deviceId,
        status: "available",
      }),
    ]));
    expect(rosterAgents).toHaveLength(2);
    expect(db.query("SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'agent.created'").get())
      .toEqual({ count: 2 });

    stephen.close();
    await stephenRun;
  }, 45_000);
});
