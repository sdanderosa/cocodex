import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
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
import { loadPendingProjectCreations, loadProjectKeyState } from "../src/cocodex/project-key-store";
import { queuedEvents } from "../src/cocodex/outbox";
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
}, 15_000);

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

  serializedEvents(): string {
    return JSON.stringify(this.events);
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
  test("creates owner-only, then requires the verified recipient to accept a project invitation", async () => {
    const serverRoot = mkdtempSync(join(tmpdir(), "cocodex-project-create-server-"));
    const stephenRoot = mkdtempSync(join(tmpdir(), "cocodex-project-create-stephen-"));
    const kaiRoot = mkdtempSync(join(tmpdir(), "cocodex-project-create-kai-"));
    roots.push(serverRoot, stephenRoot, kaiRoot);

    const paths = serverPaths(serverRoot);
    const serverIdentity = createServerIdentity(paths);
    await createTlsIdentity(paths, "127.0.0.1");
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, serverIdentity);
    servers.push(server);

    const stephenPaths = clientPaths(stephenRoot);
    const kaiPaths = clientPaths(kaiRoot);
    const stephenConnection = await enrollClient(createInvitation(db, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint,
    }), "Stephen", stephenPaths);
    const kaiConnection = await enrollClient(createInvitation(db, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint,
    }), "Kai", kaiPaths);
    for (const deviceId of [stephenConnection.deviceId, kaiConnection.deviceId]) {
      const row = db.query("SELECT fingerprint FROM devices WHERE id = ?").get(deviceId) as { fingerprint: string };
      expect(approveDevice(db, row.fingerprint)).toBeTrue();
    }
    const stephenIdentity = loadOrCreateClientIdentity(stephenPaths);
    const kaiIdentity = loadOrCreateClientIdentity(kaiPaths);
    trustDevice(stephenPaths.trustedDevices, kaiConnection.deviceId, publicKeyFingerprint(kaiIdentity.publicKeyPem));
    trustDevice(kaiPaths.trustedDevices, stephenConnection.deviceId, publicKeyFingerprint(stephenIdentity.publicKeyPem));

    const stephen = new JsonSessionHarness();
    const kai = new JsonSessionHarness();
    const stephenRun = runJsonLineSession(stephenPaths, {
      input: stephen.input, output: stephen.output, errorOutput: stephen.errors,
    });
    const kaiRun = runJsonLineSession(kaiPaths, {
      input: kai.input, output: kai.output, errorOutput: kai.errors,
    });
    await Promise.all([
      stephen.waitFor(event => event.source === "private-contacts"
        && Array.isArray(event.contacts)
        && (event.contacts as Array<Record<string, unknown>>)
          .some(contact => contact.deviceId === kaiConnection.deviceId && contact.trusted === true)),
      kai.waitFor(event => event.source === "session" && event.state === "connected"),
    ]);

    const projectId = randomUUID();
    const requestId = randomUUID();
    stephen.send({
      id: requestId,
      type: "project.create",
      projectId,
      name: "Nocturne Launcher",
      memberDeviceIds: [],
    });
    await stephen.waitFor(event => event.source === "control" && event.id === requestId
      && event.ok === true && event.projectId === projectId);
    const beforeInviteListId = randomUUID();
    kai.send({ id: beforeInviteListId, type: "project.list" });
    const beforeInvite = await kai.waitFor(event => event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "project.list.result"
      && (event.frame as Record<string, unknown> | undefined)?.requestId === beforeInviteListId);
    expect((beforeInvite.frame as Record<string, unknown>).projects).toEqual([]);
    expect(db.query("SELECT COUNT(*) AS count FROM project_members WHERE project_id = ?").get(projectId))
      .toEqual({ count: 1 });
    expect(loadProjectKeyState(kaiPaths.projectKeys, projectId)).toBeUndefined();

    const inviteRequestId = randomUUID();
    stephen.send({
      id: inviteRequestId,
      type: "project.invite.create",
      projectId,
      recipientDeviceId: kaiConnection.deviceId,
    });
    const incomingInvitation = await kai.waitFor(event =>
      event.source === "project-invitations"
      && Array.isArray(event.invitations)
      && (event.invitations as Array<Record<string, unknown>>).some(invitation =>
        invitation.projectId === projectId
        && invitation.direction === "incoming"
        && invitation.status === "pending"
        && invitation.actionable === true));
    const invitation = (incomingInvitation.invitations as Array<Record<string, unknown>>)
      .find(candidate => candidate.projectId === projectId)!;
    expect(await stephen.waitFor(event => event.source === "control"
      && event.id === inviteRequestId && event.ok === true)).toMatchObject({
      projectId,
      invitationId: invitation.invitationId,
      status: "pending",
    });
    expect(kai.serializedEvents()).not.toContain("sealedProjectKey");
    expect(kai.serializedEvents()).not.toContain("ownerDeviceKeyCertificate");

    const acceptRequestId = randomUUID();
    kai.send({
      id: acceptRequestId,
      type: "project.invite.respond",
      invitationId: invitation.invitationId,
      decision: "accept",
    });
    await Promise.all([
      kai.waitFor(event => event.source === "control" && event.id === acceptRequestId
        && event.ok === true && event.projectId === projectId && event.status === "accepted"),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "project.changed"
        && ((event.frame as Record<string, unknown>).project as Record<string, unknown> | undefined)?.id === projectId),
      kai.waitFor(event => event.source === "project-encryption"
        && event.state === "key-available" && event.projectId === projectId),
    ]);

    stephen.send({ id: randomUUID(), type: "project.list" });
    kai.send({ id: randomUUID(), type: "project.list" });
    const [stephenProjects, kaiProjects] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "project.list.result"
        && ((event.frame as Record<string, unknown>).projects as Array<Record<string, unknown>> | undefined)
          ?.some(project => project.id === projectId && project.role === "owner") === true),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "project.list.result"
        && ((event.frame as Record<string, unknown>).projects as Array<Record<string, unknown>> | undefined)
          ?.some(project => project.id === projectId && project.role === "member") === true),
    ]);
    expect(stephenProjects.frame).toBeDefined();
    expect(kaiProjects.frame).toBeDefined();
    expect(db.query("SELECT COUNT(*) AS count FROM project_members WHERE project_id = ?").get(projectId))
      .toEqual({ count: 2 });
    expect(db.query("SELECT current_epoch AS currentEpoch FROM project_key_epochs WHERE project_id = ?").get(projectId))
      .toEqual({ currentEpoch: 1 });
    expect(db.query("SELECT COUNT(*) AS count FROM project_key_envelopes WHERE project_id = ?").get(projectId))
      .toEqual({ count: 2 });
    expect(stephen.serializedEvents()).not.toContain("sealedProjectKey");
    expect(kai.serializedEvents()).not.toContain("sealedProjectKey");
    expect(loadProjectKeyState(stephenPaths.projectKeys, projectId)?.currentEpoch).toBe(1);
    expect(loadProjectKeyState(kaiPaths.projectKeys, projectId)?.currentEpoch).toBe(1);
    expect(stephenIdentity.projectWrapPublicKeyPem).not.toBe(kaiIdentity.projectWrapPublicKeyPem);

    // Consume the remaining creation allowance, then prove a transient limit
    // preserves the exact durable intent and its epoch-one key. Restarting the
    // Server clears only its in-memory limiter; the resident must replay and
    // complete the same signed request without user intervention.
    for (let index = 0; index < 11; index += 1) {
      const fillerRequestId = randomUUID();
      stephen.send({
        id: fillerRequestId,
        type: "project.create",
        projectId: randomUUID(),
        name: `Recovery allowance ${index + 1}`,
        memberDeviceIds: [],
      });
      await stephen.waitFor(event => event.source === "control"
        && event.id === fillerRequestId && event.ok === true);
    }
    const retryProjectId = randomUUID();
    const retryRequestId = randomUUID();
    stephen.send({
      id: retryRequestId,
      type: "project.create",
      projectId: retryProjectId,
      name: "Durable retry project",
      memberDeviceIds: [],
    });
    expect(await stephen.waitFor(event => event.source === "control"
      && event.id === retryRequestId && event.retryable === true)).toMatchObject({
      ok: false,
      projectId: retryProjectId,
      error: "Project creation rate limit exceeded",
    });
    expect(loadPendingProjectCreations(stephenPaths.projectKeys)
      .some(pending => pending.requestId === retryRequestId && pending.projectId === retryProjectId)).toBeTrue();
    expect(loadProjectKeyState(stephenPaths.projectKeys, retryProjectId)?.currentEpoch).toBe(1);

    const restartPort = server.port;
    await server.stop(true);
    servers.splice(servers.indexOf(server), 1);
    await Bun.sleep(500);
    config.port = restartPort;
    const restartedServer = startCoCodexServer(config, db, serverIdentity);
    servers.push(restartedServer);
    expect(await stephen.waitFor(event => event.source === "control"
      && event.id === retryRequestId && event.ok === true, 15_000)).toMatchObject({
      projectId: retryProjectId,
      created: true,
    });
    expect(loadPendingProjectCreations(stephenPaths.projectKeys)
      .some(pending => pending.requestId === retryRequestId)).toBeFalse();
    expect(loadProjectKeyState(stephenPaths.projectKeys, retryProjectId)?.currentEpoch).toBe(1);

    stephen.close();
    kai.close();
    await Promise.all([stephenRun, kaiRun]);
    await restartedServer.stop(true);
    await Bun.sleep(1_500);
    servers.splice(servers.indexOf(restartedServer), 1);
    db.close();
    databases.splice(databases.indexOf(db), 1);
  }, 45_000);

  test("initializes a project key, encrypts context on the wire, and decrypts it on another client", async () => {
    const serverRoot = mkdtempSync(join(tmpdir(), "cocodex-project-session-server-"));
    const stephenRoot = mkdtempSync(join(tmpdir(), "cocodex-project-session-stephen-"));
    const kaiRoot = mkdtempSync(join(tmpdir(), "cocodex-project-session-kai-"));
    const angelaRoot = mkdtempSync(join(tmpdir(), "cocodex-project-session-angela-"));
    roots.push(serverRoot, stephenRoot, kaiRoot, angelaRoot);

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

    const angelaConnection = await enrollClient(createInvitation(db, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint,
    }), "Angela", clientPaths(angelaRoot));
    const angelaRow = db.query("SELECT fingerprint FROM devices WHERE id = ?")
      .get(angelaConnection.deviceId) as { fingerprint: string };
    expect(approveDevice(db, angelaRow.fingerprint)).toBeTrue();

    const project = createProject(db, "Encrypted session project", stephenConnection.deviceId);
    addProjectMember(db, project.id, stephenConnection.deviceId, kaiConnection.deviceId);
    addProjectMember(db, project.id, stephenConnection.deviceId, angelaConnection.deviceId);
    const stephenPaths = clientPaths(stephenRoot);
    const kaiPaths = clientPaths(kaiRoot);
    const angelaPaths = clientPaths(angelaRoot);
    const stephenIdentity = loadOrCreateClientIdentity(stephenPaths);
    const kaiIdentity = loadOrCreateClientIdentity(kaiPaths);
    const angelaIdentity = loadOrCreateClientIdentity(angelaPaths);
    trustDevice(kaiPaths.trustedDevices, stephenConnection.deviceId, publicKeyFingerprint(stephenIdentity.publicKeyPem));
    trustDevice(stephenPaths.trustedDevices, kaiConnection.deviceId, publicKeyFingerprint(kaiIdentity.publicKeyPem));
    trustDevice(stephenPaths.trustedDevices, angelaConnection.deviceId, publicKeyFingerprint(angelaIdentity.publicKeyPem));
    trustDevice(angelaPaths.trustedDevices, stephenConnection.deviceId, publicKeyFingerprint(stephenIdentity.publicKeyPem));

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
        { deviceId: angelaConnection.deviceId, projectWrapPublicKeyPem: angelaIdentity.projectWrapPublicKeyPem },
      ],
    });
    await stephen.waitFor(event => event.source === "control" && event.ok === true && event.sharedRecipients === 3);
    await new Promise(resolve => setTimeout(resolve, 50));

    kai.send({ id: crypto.randomUUID(), type: "project.key.get", projectId: project.id });
    await kai.waitFor(event => event.source === "project-encryption" && event.state === "key-available" && event.projectId === project.id);
    expect(stephen.serializedEvents()).not.toContain("project.key.initialized");
    expect(kai.serializedEvents()).not.toContain("project.key.result");
    expect(stephen.serializedEvents()).not.toContain("sealedProjectKey");
    expect(kai.serializedEvents()).not.toContain("sealedProjectKey");

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

    const referenceListStephen = crypto.randomUUID();
    const referenceListKai = crypto.randomUUID();
    stephen.send({ id: referenceListStephen, type: "project.file-reference.list", projectId: project.id });
    kai.send({ id: referenceListKai, type: "project.file-reference.list", projectId: project.id });
    await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "file-reference.list.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === referenceListStephen),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "file-reference.list.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === referenceListKai),
    ]);
    const workspaceRoot = join(stephenRoot, "workspace");
    const privateRelativePath = "reports/private-result.txt";
    const privateFileBytes = "FILE_BYTES_CANARY_does_not_leave_Stephen";
    mkdirSync(join(workspaceRoot, "reports"), { recursive: true });
    writeFileSync(join(workspaceRoot, ...privateRelativePath.split("/")), privateFileBytes, "utf8");
    const referenceId = crypto.randomUUID();
    stephen.send({
      id: crypto.randomUUID(),
      type: "project.file-reference.publish",
      projectId: project.id,
      referenceId,
      artifactId,
      workspaceRoot,
      path: privateRelativePath,
      workspaceMode: "shared",
      workspaceRef: "main",
      mediaType: "text/plain",
    });
    const [referenceAtStephen, referenceAtKai] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "file-reference.accepted"
        && ((event.frame as Record<string, any>).reference as Record<string, unknown> | undefined)?.referenceId === referenceId),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "file-reference.published"
        && ((event.frame as Record<string, any>).reference as Record<string, unknown> | undefined)?.referenceId === referenceId),
    ]);
    for (const event of [referenceAtStephen, referenceAtKai]) {
      expect((event.frame as Record<string, any>).reference).toMatchObject({
        referenceId,
        projectId: project.id,
        artifactId,
        hostDeviceId: stephenConnection.deviceId,
        relativePath: privateRelativePath,
        sizeBytes: Buffer.byteLength(privateFileBytes),
        mediaType: "text/plain",
      });
    }
    const storedReference = db.query(
      "SELECT envelope_json AS envelopeJson FROM project_file_references WHERE id = ?",
    ).get(referenceId) as { envelopeJson: string };
    expect(storedReference.envelopeJson).not.toContain(workspaceRoot);
    expect(storedReference.envelopeJson).not.toContain(privateRelativePath);
    expect(storedReference.envelopeJson).not.toContain(privateFileBytes);
    expect(storedReference.envelopeJson).toContain("ciphertext");

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

    const recoveredReferenceStephen = crypto.randomUUID();
    const recoveredReferenceKai = crypto.randomUUID();
    stephen.send({ id: recoveredReferenceStephen, type: "project.file-reference.list", projectId: project.id });
    kai.send({ id: recoveredReferenceKai, type: "project.file-reference.list", projectId: project.id });
    const [referenceSnapshotStephen, referenceSnapshotKai] = await Promise.all([
      stephen.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "file-reference.list.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === recoveredReferenceStephen),
      kai.waitFor(event => event.source === "server"
        && (event.frame as Record<string, unknown> | undefined)?.type === "file-reference.list.result"
        && (event.frame as Record<string, unknown> | undefined)?.requestId === recoveredReferenceKai),
    ]);
    for (const snapshot of [referenceSnapshotStephen, referenceSnapshotKai]) {
      expect((snapshot.frame as Record<string, unknown>).references).toEqual(expect.arrayContaining([
        expect.objectContaining({ referenceId, relativePath: privateRelativePath, artifactId }),
      ]));
    }

    const angela = new JsonSessionHarness();
    const angelaRun = runJsonLineSession(angelaPaths, {
      input: angela.input,
      output: angela.output,
      errorOutput: angela.errors,
    });
    await angela.waitFor(event => event.source === "session" && event.state === "connected");
    angela.send({ id: crypto.randomUUID(), type: "project.key.get", projectId: project.id });
    await angela.waitFor(event => event.source === "project-encryption"
      && event.state === "key-available" && event.projectId === project.id && event.keyEpoch === 1);

    const memberListRequest = crypto.randomUUID();
    stephen.send({ id: memberListRequest, type: "project.member.list", projectId: project.id });
    const memberList = await stephen.waitFor(event => event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "project.member.list.result"
      && (event.frame as Record<string, unknown> | undefined)?.requestId === memberListRequest);
    expect((memberList.frame as Record<string, any>).members).toEqual(expect.arrayContaining([
      expect.objectContaining({ deviceId: stephenConnection.deviceId, role: "owner" }),
      expect.objectContaining({ deviceId: kaiConnection.deviceId, role: "member" }),
      expect.objectContaining({ deviceId: angelaConnection.deviceId, role: "member", trusted: true }),
    ]));
    expect(JSON.stringify(memberList)).not.toContain("projectWrapPublicKeyPem");

    const removalRequest = crypto.randomUUID();
    stephen.send({
      id: removalRequest,
      type: "project.member.remove-and-rotate",
      projectId: project.id,
      deviceId: kaiConnection.deviceId,
    });
    await Promise.all([
      stephen.waitFor(event => event.source === "control" && event.id === removalRequest && event.ok === true),
      stephen.waitFor(event => event.source === "project-encryption"
        && event.state === "key-available" && event.projectId === project.id && event.keyEpoch === 2),
      kai.waitFor(event => event.source === "project-encryption"
        && event.state === "revoked" && event.projectId === project.id),
      angela.waitFor(event => event.source === "project-encryption"
        && event.state === "key-available" && event.projectId === project.id && event.keyEpoch === 2),
    ]);
    expect(loadProjectKeyState(stephenPaths.projectKeys, project.id)).toMatchObject({ currentEpoch: 2, revoked: false });
    expect(loadProjectKeyState(kaiPaths.projectKeys, project.id)).toMatchObject({ revoked: true });
    expect(loadProjectKeyState(angelaPaths.projectKeys, project.id)).toMatchObject({ currentEpoch: 2, revoked: false });
    expect(db.query("SELECT role FROM project_members WHERE project_id = ? AND device_id = ?")
      .get(project.id, kaiConnection.deviceId)).toBeNull();
    expect(db.query(`
      SELECT recipient_device_id AS recipientDeviceId
      FROM project_key_envelopes WHERE project_id = ? AND key_epoch = 2
    `).all(project.id)).toEqual(
      [angelaConnection.deviceId, stephenConnection.deviceId]
        .sort()
        .map(recipientDeviceId => ({ recipientDeviceId })),
    );

    const postRevocationSubscribe = crypto.randomUUID();
    angela.send({ id: postRevocationSubscribe, type: "chat.subscribe", projectId: project.id });
    await angela.waitFor(event => event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "chat.snapshot"
      && (event.frame as Record<string, unknown> | undefined)?.requestId === postRevocationSubscribe);
    const survivorMessage = "Angela continues securely after Kai is revoked";
    angela.send({ id: crypto.randomUUID(), type: "chat.send", projectId: project.id, content: survivorMessage });
    await stephen.waitFor(event => event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "chat.event"
      && ((event.frame as Record<string, unknown>).event as Record<string, unknown> | undefined)?.content === survivorMessage);
    expect(db.query(`
      SELECT json_extract(envelope_json, '$.keyEpoch') AS keyEpoch,
        json_extract(envelope_json, '$.senderDeviceId') AS senderDeviceId
      FROM project_chat_events
      WHERE project_id = ?
      ORDER BY sequence DESC
      LIMIT 1
    `).get(project.id)).toEqual({
      keyEpoch: 2,
      senderDeviceId: angelaConnection.deviceId,
    });

    const offlineProject = createProject(db, "Offline atomic replay", stephenConnection.deviceId);
    addProjectMember(db, offlineProject.id, stephenConnection.deviceId, kaiConnection.deviceId);
    const offlineInitializeId = crypto.randomUUID();
    stephen.send({
      id: offlineInitializeId,
      type: "project.key.initialize",
      projectId: offlineProject.id,
      keyEpoch: 1,
      recipients: [
        { deviceId: stephenConnection.deviceId, projectWrapPublicKeyPem: stephenIdentity.projectWrapPublicKeyPem },
        { deviceId: kaiConnection.deviceId, projectWrapPublicKeyPem: kaiIdentity.projectWrapPublicKeyPem },
      ],
    });
    await stephen.waitFor(event => event.source === "control"
      && event.id === offlineInitializeId && event.ok === true && event.sharedRecipients === 2);
    kai.send({ id: crypto.randomUUID(), type: "project.key.get", projectId: offlineProject.id });
    await kai.waitFor(event => event.source === "project-encryption"
      && event.state === "key-available" && event.projectId === offlineProject.id && event.keyEpoch === 1);
    const offlineRosterId = crypto.randomUUID();
    stephen.send({ id: offlineRosterId, type: "project.member.list", projectId: offlineProject.id });
    const offlineRoster = await stephen.waitFor(event => event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "project.member.list.result"
      && (event.frame as Record<string, unknown> | undefined)?.requestId === offlineRosterId);
    expect((offlineRoster.frame as Record<string, any>).members).toEqual(expect.arrayContaining([
      expect.objectContaining({ deviceId: stephenConnection.deviceId, trusted: true }),
      expect.objectContaining({ deviceId: kaiConnection.deviceId, trusted: true }),
    ]));

    const offlineStephenDisconnected = stephen.waitFor(event => event.source === "session" && event.state === "disconnected");
    const offlineKaiDisconnected = kai.waitFor(event => event.source === "session" && event.state === "disconnected");
    const offlineAngelaDisconnected = angela.waitFor(event => event.source === "session" && event.state === "disconnected");
    const restartedIndex = servers.indexOf(restarted);
    if (restartedIndex >= 0) servers.splice(restartedIndex, 1);
    await restarted.stop(true);
    await Promise.all([offlineStephenDisconnected, offlineKaiDisconnected, offlineAngelaDisconnected]);

    const offlineRemovalId = crypto.randomUUID();
    stephen.send({
      id: offlineRemovalId,
      type: "project.member.remove-and-rotate",
      projectId: offlineProject.id,
      deviceId: kaiConnection.deviceId,
    });
    await stephen.waitFor(event => event.source === "control"
      && event.id === offlineRemovalId && event.ok === true && event.queued === true);
    expect(queuedEvents(stephenPaths)).toEqual([
      expect.objectContaining({
        requestId: offlineRemovalId,
        type: "project.member.remove-and-rotate",
        projectId: offlineProject.id,
      }),
    ]);

    stephen.close();
    await stephenRun;
    const recoveredStephen = new JsonSessionHarness();
    const recoveredStephenRun = runJsonLineSession(stephenPaths, {
      input: recoveredStephen.input,
      output: recoveredStephen.output,
      errorOutput: recoveredStephen.errors,
    });
    await recoveredStephen.waitFor(event => event.source === "session"
      && (event.state === "retrying" || event.state === "disconnected"));
    const recoveredServer = startCoCodexServer({ ...config, port: server.port }, db, identity);
    servers.push(recoveredServer);
    await Promise.all([
      waitUntilConnectedViaProjectList(recoveredStephen),
      waitUntilConnectedViaProjectList(kai),
      waitUntilConnectedViaProjectList(angela),
      recoveredStephen.waitFor(event => event.source === "project-encryption"
        && event.state === "key-available" && event.projectId === offlineProject.id && event.keyEpoch === 2),
      kai.waitFor(event => event.source === "project-encryption"
        && event.state === "revoked" && event.projectId === offlineProject.id),
    ]);
    expect(queuedEvents(stephenPaths)).toEqual([]);
    expect(db.query("SELECT role FROM project_members WHERE project_id = ? AND device_id = ?")
      .get(offlineProject.id, kaiConnection.deviceId)).toBeNull();
    expect(db.query(`
      SELECT key_epoch AS keyEpoch FROM project_member_removal_rotations
      WHERE rotation_id = ?
    `).get(offlineRemovalId)).toEqual({ keyEpoch: 2 });

    recoveredStephen.close();
    kai.close();
    angela.close();
    await Promise.all([recoveredStephenRun, kaiRun, angelaRun]);
  }, 45_000);

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
