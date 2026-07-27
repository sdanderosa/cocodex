import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { databaseAdminSummary } from "../src/admin-status";
import { openDatabase } from "../src/database";

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

async function readReadyLine(child: Bun.Subprocess<"ignore", "pipe", "pipe">): Promise<Record<string, unknown>> {
  const reader = child.stdout.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    const result = await Promise.race([
      reader.read(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Server readiness timed out")), remaining)),
    ]);
    if (result.done) throw new Error(`Server exited before readiness with code ${await child.exited}`);
    buffered += decoder.decode(result.value, { stream: true });
    const newline = buffered.indexOf("\n");
    if (newline >= 0) return JSON.parse(buffered.slice(0, newline));
  }
  throw new Error("Server readiness timed out");
}

describe("standalone CoCodex Server process", () => {
  test("initializes, runs independently, serves TLS health, and shuts down", async () => {
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
    const initialized = JSON.parse(await new Response(init.stdout).text()) as {
      adminToken: string;
    };
    expect(initialized.adminToken.length).toBeGreaterThanOrEqual(32);

    const child = Bun.spawn([
      process.execPath,
      cli,
      "start",
      "--state-root",
      root,
    ], { stdout: "pipe", stderr: "pipe" });
    children.push(child);
    const ready = await readReadyLine(child);
    expect(ready.ready).toBeTrue();
    expect(ready.port).toBe(port);

    const health = await fetch(`https://127.0.0.1:${port}/healthz`, {
      tls: { rejectUnauthorized: false },
    });
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true, service: "cocodex-server", protocol: 1 });

    const unauthorized = await fetch(`https://127.0.0.1:${port}/v1/admin/status`, {
      tls: { rejectUnauthorized: false },
    });
    expect(unauthorized.status).toBe(401);
    const status = await fetch(`https://127.0.0.1:${port}/v1/admin/status`, {
      headers: { authorization: `Bearer ${initialized.adminToken}` },
      tls: { rejectUnauthorized: false },
    });
    expect(status.status).toBe(200);
    const admin = await status.json() as Record<string, any>;
    expect(admin).toMatchObject({
      service: "cocodex-server",
      protocol: 1,
      status: "running",
      authority: { state: "active", epoch: 1 },
      endpoint: {
        bindHostname: "0.0.0.0",
        listeningPort: port,
        publicHost: "127.0.0.1",
        publicPort: port,
        transport: "TLS/WSS",
      },
      tls: { validNow: true },
      connections: {
        authenticatedSockets: 0,
        uniqueDevices: 0,
        agentWorkerSockets: 0,
        unauthenticatedSockets: 0,
      },
      activePresenceProjects: 0,
      database: {
        health: "ok",
        quickCheck: "ok",
        foreignKeyViolations: 0,
        counts: {
          devices: { pending: 0, approved: 0, revoked: 0 },
          projects: 0,
          memberships: 0,
          agents: 0,
          tasks: { queued: 0, running: 0, completed: 0, failed: 0 },
          privateCiphertexts: 0,
          projectCiphertextRecords: 0,
          auditEvents: 0,
        },
      },
    });
    expect(admin.uptimeSeconds).toBeGreaterThanOrEqual(0);
    expect(admin.database.schemaVersion).toBeGreaterThan(0);
    expect(admin.database.logicalBytes).toBeGreaterThan(0);
    expect(JSON.stringify(admin)).not.toContain(initialized.adminToken);
    expect(JSON.stringify(admin)).not.toContain(root);

    child.kill();
    expect(await child.exited).toBe(143);
  }, 20_000);

  test("reports bounded aggregate database health without exposing stored content", () => {
    const db = openDatabase(":memory:");
    const now = "2030-01-01T00:00:00.000Z";
    try {
      for (const [index, status] of ["pending", "approved", "revoked"].entries()) {
        db.query(`INSERT INTO invitations
          (id, token_hash, expires_at, consumed_at, created_at)
          VALUES (?, ?, ?, NULL, ?)`)
          .run(`invite-${index}`, `token-${index}`, "2031-01-01T00:00:00.000Z", now);
        db.query(`INSERT INTO devices (
          id, public_key_pem, fingerprint, display_name, status,
          invitation_id, enrolled_at, approved_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
          `device-${index}`,
          `public-key-${index}`,
          `fingerprint-${index}`,
          `SECRET-DISPLAY-NAME-${index}`,
          status,
          `invite-${index}`,
          now,
          status === "approved" ? now : null,
          status === "revoked" ? now : null,
        );
      }
      db.query(`INSERT INTO projects (id, name, created_by_device_id, created_at)
        VALUES ('project-1', 'SECRET-PROJECT-NAME', 'device-1', ?)`).run(now);
      db.query(`INSERT INTO project_members (project_id, device_id, role, joined_at)
        VALUES ('project-1', 'device-1', 'owner', ?)`).run(now);
      db.query(`INSERT INTO shared_chats (
        id, project_id, title, created_by_device_id, state, creation_nonce,
        created_at, updated_at
      ) VALUES ('project-1', 'project-1', 'General', 'device-1', 'active', NULL, ?, ?)`).run(now, now);
      db.query(`INSERT INTO agents
        (id, project_id, host_device_id, name, enabled, created_at)
        VALUES ('agent-1', 'project-1', 'device-1', 'SECRET-AGENT-NAME', 1, ?)`).run(now);
      for (const [index, status] of ["queued", "running", "completed", "failed"].entries()) {
        db.query(`INSERT INTO agent_tasks (
          id, project_id, requester_device_id, target_device_id, agent_id,
          prompt, nonce, issued_at, expires_at, requester_signature,
          server_signature, status, accepted_at, completed_at, chat_id
        ) VALUES (?, 'project-1', 'device-1', 'device-1', 'agent-1',
          'SECRET-PROMPT', ?, ?, ?, 'requester-signature', 'server-signature',
          ?, ?, ?, 'project-1')`).run(
          `task-${index}`,
          `nonce-${index}`,
          now,
          "2031-01-01T00:00:00.000Z",
          status,
          now,
          status === "completed" || status === "failed" ? now : null,
        );
      }
      db.query(`INSERT INTO private_messages (
        message_id, sender_device_id, recipient_device_id, ciphertext,
        client_created_at, accepted_at
      ) VALUES ('private-1', 'device-1', 'device-2', 'SECRET-CIPHERTEXT', ?, ?)`).run(now, now);
      db.query(`INSERT INTO project_chat_events (
        project_id, chat_id, event_id, sender_device_id, envelope_json,
        client_created_at, accepted_at
      ) VALUES ('project-1', 'project-1', 'event-1', 'device-1',
        '{"ciphertext":"SECRET-EVENT"}', ?, ?)`).run(now, now);
      db.query(`INSERT INTO audit_events
        (event_type, actor_device_id, subject_id, occurred_at, details_json)
        VALUES ('test', 'device-1', 'project-1', ?, '{"secret":"SECRET-AUDIT"}')`).run(now);

      const summary = databaseAdminSummary(db);
      expect(summary).toMatchObject({
        health: "ok",
        quickCheck: "ok",
        foreignKeyViolations: 0,
        counts: {
          devices: { pending: 1, approved: 1, revoked: 1 },
          projects: 1,
          memberships: 1,
          agents: 1,
          tasks: { queued: 1, running: 1, completed: 1, failed: 1 },
          privateCiphertexts: 1,
          projectCiphertextRecords: 1,
          auditEvents: 1,
        },
      });
      expect(summary.schemaVersion).toBeGreaterThan(0);
      expect(summary.logicalBytes).toBeGreaterThan(0);
      expect(JSON.stringify(summary)).not.toContain("SECRET-");
    } finally {
      db.close();
    }
  });
});
