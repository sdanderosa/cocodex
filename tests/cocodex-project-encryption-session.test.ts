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
    this.output.setEncoding("utf8");
    this.output.on("data", chunk => {
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
        reject(new Error("Timed out waiting for CoCodex session event"));
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

    stephen.close();
    kai.close();
    await Promise.all([stephenRun, kaiRun]);
  }, 30_000);
});
