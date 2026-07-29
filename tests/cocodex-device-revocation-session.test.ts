import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import type { Database } from "bun:sqlite";
import { publicKeyFingerprint } from "@cocodex/protocol";
import { createDefaultConfig } from "../apps/cocodex-server/src/config";
import { openDatabase } from "../apps/cocodex-server/src/database";
import { revokeDevice } from "../apps/cocodex-server/src/enrollment";
import { approvePendingDeviceForTest } from "../apps/cocodex-server/tests/device-approval-fixture";
import { createServerIdentity } from "../apps/cocodex-server/src/identity";
import { createInvitation } from "../apps/cocodex-server/src/invitations";
import { serverPaths } from "../apps/cocodex-server/src/paths";
import { startCoCodexServer } from "../apps/cocodex-server/src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../apps/cocodex-server/src/tls";
import { enrollClient } from "../src/cocodex/client";
import { loadOrCreateClientIdentity } from "../src/cocodex/identity";
import { clientPaths } from "../src/cocodex/paths";
import { loadProjectKeyState } from "../src/cocodex/project-key-store";
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
    for (let attempt = 0; attempt < 300; attempt += 1) {
      try {
        rmSync(root, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 299) throw error;
        await Bun.sleep(100);
      }
    }
  }
}, 60_000);

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
          try {
            value = JSON.parse(line) as Record<string, unknown>;
          } catch {
            continue;
          }
          this.events.push(value);
          for (let index = this.waiters.length - 1; index >= 0; index -= 1) {
            const waiter = this.waiters[index]!;
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

  waitFor(
    predicate: (event: Record<string, unknown>) => boolean,
    // The complete repository gate schedules many process/TLS suites together.
    // Keep the semantic assertion exact while allowing bounded scheduler delay;
    // the isolated path normally completes in about five seconds.
    timeoutMs = 45_000,
  ): Promise<Record<string, unknown>> {
    const existing = this.events.find(predicate);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.waiters.findIndex(waiter => waiter.timer === timer);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error(
          `Timed out waiting for CoCodex session event; recent=${JSON.stringify(this.events.slice(-10))}`,
        ));
      }, timeoutMs);
      this.waiters.push({ predicate, resolve, reject, timer });
    });
  }

  count(predicate: (event: Record<string, unknown>) => boolean): number {
    return this.events.filter(predicate).length;
  }

  close(): void {
    this.send({ type: "shutdown" });
    this.input.end();
    this.errors.end();
  }
}

async function waitUntilConnectedViaProjectList(session: JsonSessionHarness): Promise<void> {
  // The all-repository gate can delay resident reconnect work behind hundreds
  // of process/TLS fixtures. Keep the 120-second test ceiling and every
  // post-reconnect assertion, but allow a bounded forty probe attempts here.
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const requestId = randomUUID();
    session.send({ id: requestId, type: "project.list" });
    try {
      const result = await session.waitFor(event =>
        (event.source === "server"
          && (event.frame as Record<string, unknown> | undefined)?.requestId === requestId)
        || (event.source === "control" && event.id === requestId), 750);
      if (result.source === "server") return;
    } catch {
      // The resident reconnect supervisor may still be between attempts.
    }
    await Bun.sleep(250);
  }
  throw new Error("CoCodex resident session did not reconnect before the recovery deadline");
}

describe("CoCodex device-revocation incident recovery", () => {
  test("quarantines an owner revocation until the promoted survivor removes and rotates", async () => {
    const serverRoot = mkdtempSync(join(tmpdir(), "cocodex-revocation-server-"));
    const stephenRoot = mkdtempSync(join(tmpdir(), "cocodex-revocation-stephen-"));
    const kaiRoot = mkdtempSync(join(tmpdir(), "cocodex-revocation-kai-"));
    roots.push(serverRoot, stephenRoot, kaiRoot);

    const paths = serverPaths(serverRoot);
    const serverIdentity = createServerIdentity(paths);
    await createTlsIdentity(paths, "127.0.0.1");
    const serverFingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
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
      serverFingerprint,
    }), "Stephen", stephenPaths);
    const stephenIdentity = loadOrCreateClientIdentity(stephenPaths);
    const stephenRow = db.query("SELECT fingerprint FROM devices WHERE id = ?")
      .get(stephenConnection.deviceId) as { fingerprint: string };
    approvePendingDeviceForTest(
      db,
      { id: stephenConnection.deviceId, fingerprint: stephenRow.fingerprint },
      stephenIdentity.privateKeyPem,
      serverFingerprint,
    );
    const kaiConnection = await enrollClient(createInvitation(db, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint,
    }), "Kai", kaiPaths);
    const kaiIdentity = loadOrCreateClientIdentity(kaiPaths);
    const kaiRow = db.query("SELECT fingerprint FROM devices WHERE id = ?")
      .get(kaiConnection.deviceId) as { fingerprint: string };
    approvePendingDeviceForTest(
      db,
      { id: kaiConnection.deviceId, fingerprint: kaiRow.fingerprint },
      kaiIdentity.privateKeyPem,
      serverFingerprint,
    );
    trustDevice(
      stephenPaths.trustedDevices,
      kaiConnection.deviceId,
      publicKeyFingerprint(kaiIdentity.publicKeyPem),
    );
    trustDevice(
      kaiPaths.trustedDevices,
      stephenConnection.deviceId,
      publicKeyFingerprint(stephenIdentity.publicKeyPem),
    );

    const stephen = new JsonSessionHarness();
    const kai = new JsonSessionHarness();
    const stephenRun = runJsonLineSession(stephenPaths, {
      input: stephen.input,
      output: stephen.output,
      errorOutput: stephen.errors,
    });
    const kaiRun = runJsonLineSession(kaiPaths, {
      input: kai.input,
      output: kai.output,
      errorOutput: kai.errors,
    });
    await Promise.all([
      stephen.waitFor(event => event.source === "private-contacts"
        && Array.isArray(event.contacts)
        && (event.contacts as Array<Record<string, unknown>>).some(contact =>
          contact.deviceId === kaiConnection.deviceId && contact.trusted === true)),
      kai.waitFor(event => event.source === "private-contacts"
        && Array.isArray(event.contacts)
        && (event.contacts as Array<Record<string, unknown>>).some(contact =>
          contact.deviceId === stephenConnection.deviceId && contact.trusted === true)),
    ]);

    const projectId = randomUUID();
    const createRequestId = randomUUID();
    stephen.send({
      id: createRequestId,
      type: "project.create",
      projectId,
      name: "Revocation recovery",
      memberDeviceIds: [],
    });
    await stephen.waitFor(event =>
      event.source === "control"
      && event.id === createRequestId
      && event.ok === true
      && event.projectId === projectId);

    const inviteRequestId = randomUUID();
    stephen.send({
      id: inviteRequestId,
      type: "project.invite.create",
      projectId,
      recipientDeviceId: kaiConnection.deviceId,
    });
    const invitationEvent = await kai.waitFor(event =>
      event.source === "project-invitations"
      && Array.isArray(event.invitations)
      && (event.invitations as Array<Record<string, unknown>>).some(invitation =>
        invitation.projectId === projectId
        && invitation.status === "pending"
        && invitation.actionable === true));
    const invitation = (invitationEvent.invitations as Array<Record<string, unknown>>)
      .find(candidate => candidate.projectId === projectId)!;
    await stephen.waitFor(event =>
      event.source === "control"
      && event.id === inviteRequestId
      && event.ok === true);

    const acceptRequestId = randomUUID();
    kai.send({
      id: acceptRequestId,
      type: "project.invite.respond",
      invitationId: invitation.invitationId,
      decision: "accept",
    });
    await Promise.all([
      kai.waitFor(event =>
        event.source === "control"
        && event.id === acceptRequestId
        && event.ok === true
        && event.status === "accepted"),
      kai.waitFor(event =>
        event.source === "project-encryption"
        && event.state === "key-available"
        && event.projectId === projectId
        && event.keyEpoch === 1),
    ]);
    expect(loadProjectKeyState(stephenPaths.projectKeys, projectId)).toMatchObject({
      currentEpoch: 1,
      rotationRequired: false,
      revoked: false,
    });
    expect(loadProjectKeyState(kaiPaths.projectKeys, projectId)).toMatchObject({
      currentEpoch: 1,
      rotationRequired: false,
      revoked: false,
    });

    const stephenDisconnected = stephen.waitFor(event =>
      event.source === "session" && event.state === "disconnected");
    expect(revokeDevice(db, stephenRow.fingerprint)).toBeTrue();
    const [incident] = await Promise.all([
      kai.waitFor(event =>
        event.source === "project-security"
        && event.state === "device-revoked"
        && event.projectId === projectId
        && event.revokedDeviceId === stephenConnection.deviceId),
      stephenDisconnected,
    ]);
    expect(incident).toMatchObject({
      promotedOwnerDeviceId: kaiConnection.deviceId,
      localDeviceRevoked: false,
      keyRotationRequired: true,
    });
    expect(loadProjectKeyState(kaiPaths.projectKeys, projectId)).toMatchObject({
      currentEpoch: 1,
      rotationRequired: true,
      revoked: false,
    });
    expect(db.query(`
      SELECT incident_id AS incidentId, status, current_epoch AS currentEpoch,
        recovery_owner_device_id AS recoveryOwnerDeviceId
      FROM device_revocation_project_incidents
      WHERE project_id = ? AND revoked_device_id = ?
    `).get(projectId, stephenConnection.deviceId)).toEqual({
      incidentId: incident.incidentId,
      status: "unresolved",
      currentEpoch: 1,
      recoveryOwnerDeviceId: kaiConnection.deviceId,
    });

    const rosterRequestId = randomUUID();
    kai.send({ id: rosterRequestId, type: "project.member.list", projectId });
    const roster = await kai.waitFor(event =>
      event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "project.member.list.result"
      && (event.frame as Record<string, unknown> | undefined)?.requestId === rosterRequestId);
    expect((roster.frame as Record<string, any>).members).toEqual(expect.arrayContaining([
      expect.objectContaining({
        deviceId: kaiConnection.deviceId,
        role: "owner",
        status: "approved",
      }),
      expect.objectContaining({
        deviceId: stephenConnection.deviceId,
        role: "member",
        status: "revoked",
      }),
    ]));
    expect(JSON.stringify(roster)).not.toContain("projectWrapPublicKeyPem");
    expect(db.query(`
      SELECT pm.device_id AS deviceId, pm.role, d.status
      FROM project_members pm
      JOIN devices d ON d.id = pm.device_id
      WHERE pm.project_id = ?
      ORDER BY pm.device_id ASC
    `).all(projectId)).toEqual(expect.arrayContaining([
      {
        deviceId: kaiConnection.deviceId,
        role: "owner",
        status: "approved",
      },
      {
        deviceId: stephenConnection.deviceId,
        role: "member",
        status: "revoked",
      },
    ]));

    const chatCountBeforeBlockedWrite = db.query(
      "SELECT COUNT(*) AS count FROM project_chat_events WHERE project_id = ?",
    ).get(projectId) as { count: number };
    const blockedWriteRequestId = randomUUID();
    kai.send({
      id: blockedWriteRequestId,
      type: "chat.send",
      projectId,
      content: "This stale epoch write must not be accepted",
    });
    expect(await kai.waitFor(event =>
      event.source === "control"
      && event.id === blockedWriteRequestId
      && event.ok === false)).toMatchObject({
      error: `Project ${projectId} requires encrypted content frames`,
    });
    expect(db.query(
      "SELECT COUNT(*) AS count FROM project_chat_events WHERE project_id = ?",
    ).get(projectId)).toEqual(chatCountBeforeBlockedWrite);

    const removalRequestId = randomUUID();
    kai.send({
      id: removalRequestId,
      type: "project.member.remove-and-rotate",
      projectId,
      deviceId: stephenConnection.deviceId,
    });
    await Promise.all([
      kai.waitFor(event =>
        event.source === "control"
        && event.id === removalRequestId
        && event.ok === true
        && event.keyEpoch === 2),
      kai.waitFor(event =>
        event.source === "project-encryption"
        && event.state === "key-available"
        && event.projectId === projectId
        && event.keyEpoch === 2),
    ]);
    expect(loadProjectKeyState(kaiPaths.projectKeys, projectId)).toMatchObject({
      currentEpoch: 2,
      rotationRequired: false,
      revoked: false,
    });
    expect(db.query(`
      SELECT status, resolution_rotation_id AS resolutionRotationId
      FROM device_revocation_project_incidents
      WHERE project_id = ? AND revoked_device_id = ?
    `).get(projectId, stephenConnection.deviceId)).toMatchObject({
      status: "resolved",
      resolutionRotationId: removalRequestId,
    });
    expect(db.query(
      "SELECT role FROM project_members WHERE project_id = ? AND device_id = ?",
    ).get(projectId, stephenConnection.deviceId)).toBeNull();

    const epochTwoMessage = "Kai writes with the recovered epoch";
    const epochTwoRequestId = randomUUID();
    kai.send({
      id: epochTwoRequestId,
      type: "chat.send",
      projectId,
      content: epochTwoMessage,
    });
    const epochTwoAccepted = await kai.waitFor(event =>
      event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "chat.accepted"
      && (event.frame as Record<string, unknown> | undefined)?.requestId === epochTwoRequestId);
    expect(((epochTwoAccepted.frame as Record<string, any>).event as Record<string, unknown>).content)
      .toBe(epochTwoMessage);
    expect(db.query(`
      SELECT json_extract(envelope_json, '$.keyEpoch') AS keyEpoch
      FROM project_chat_events
      WHERE project_id = ?
      ORDER BY sequence DESC
      LIMIT 1
    `).get(projectId)).toEqual({ keyEpoch: 2 });

    stephen.close();
    await stephenRun;

    const incidentPredicate = (event: Record<string, unknown>) =>
      event.source === "project-security"
      && event.state === "device-revoked"
      && event.projectId === projectId;
    const incidentCountBeforeRestart = kai.count(incidentPredicate);
    expect(incidentCountBeforeRestart).toBe(1);
    const kaiDisconnected = kai.waitFor(event =>
      event.source === "session" && event.state === "disconnected");
    servers.splice(servers.indexOf(server), 1);
    await server.stop(true);
    await kaiDisconnected;

    const restarted = startCoCodexServer({ ...config, port: server.port }, db, serverIdentity);
    servers.push(restarted);
    await waitUntilConnectedViaProjectList(kai);
    await Bun.sleep(1_250);
    expect(kai.count(incidentPredicate)).toBe(incidentCountBeforeRestart);

    const afterRestartMessage = "Resolved incident stays resolved after restart";
    const afterRestartRequestId = randomUUID();
    kai.send({
      id: afterRestartRequestId,
      type: "chat.send",
      projectId,
      content: afterRestartMessage,
    });
    const afterRestartAccepted = await kai.waitFor(event =>
      event.source === "server"
      && (event.frame as Record<string, unknown> | undefined)?.type === "chat.accepted"
      && (event.frame as Record<string, unknown> | undefined)?.requestId === afterRestartRequestId);
    expect(((afterRestartAccepted.frame as Record<string, any>).event as Record<string, unknown>).content)
      .toBe(afterRestartMessage);

    kai.close();
    await kaiRun;
  }, 120_000);
});
