import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { openDatabase } from "../src/database";
import { migrations } from "../src/migrations";

describe("CoCodex database migrations", () => {
  test("preserves legacy unsigned agent tables while installing signed task schema", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-migration-"));
    const path = join(root, "server.sqlite3");
    let migrated: Database | undefined;
    try {
      const legacy = new Database(path, { create: true });
      legacy.exec("PRAGMA foreign_keys = ON");
      legacy.exec("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
      legacy.exec(migrations[0]!.sql);
      legacy.exec(`
        CREATE TABLE agent_tasks (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          requester_device_id TEXT NOT NULL,
          target_device_id TEXT NOT NULL,
          agent_id TEXT NOT NULL,
          prompt TEXT NOT NULL,
          status TEXT NOT NULL,
          client_created_at TEXT NOT NULL,
          accepted_at TEXT NOT NULL,
          completed_at TEXT
        );
        CREATE TABLE agent_task_events (
          task_id TEXT NOT NULL,
          chat_sequence INTEGER NOT NULL UNIQUE,
          final INTEGER NOT NULL,
          status TEXT NOT NULL,
          PRIMARY KEY (task_id, chat_sequence)
        );
      `);
      legacy.query("INSERT INTO schema_migrations VALUES (1, ?)").run(new Date().toISOString());
      legacy.close();

      migrated = openDatabase(path);
      expect(migrated.query(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'legacy_agent_tasks_v1'",
      ).get()).not.toBeNull();
      const columns = migrated.query("PRAGMA table_info(agent_tasks)").all() as Array<{ name: string }>;
      expect(columns.map(column => column.name)).toContain("requester_signature");
      expect(columns.map(column => column.name)).toContain("input_artifact_ids_json");
      expect(columns.map(column => column.name)).toEqual(expect.arrayContaining([
        "workspace_mode",
        "workspace_ref",
        "worktree_branch",
        "base_commit",
        "merge_target",
        "execution_started_at",
        "execution_signature",
      ]));
      expect(migrated.query("SELECT version FROM schema_migrations ORDER BY version").all())
        .toEqual([{ version: 1 }, { version: 2 }, { version: 3 }, { version: 4 }, { version: 5 }, { version: 6 }, { version: 7 }, { version: 8 }, { version: 9 }, { version: 10 }, { version: 11 }, { version: 12 }, { version: 13 }, { version: 14 }, { version: 15 }, { version: 16 }, { version: 17 }, { version: 18 }, { version: 19 }, { version: 20 }, { version: 21 }, { version: 22 }, { version: 23 }, { version: 24 }, { version: 25 }]);
      expect(migrated.query(`
        SELECT primary_model AS primaryModel, primary_effort AS primaryEffort,
          coagent_model AS coAgentModel, coagent_effort AS coAgentEffort,
          max_concurrent_coagents AS maxConcurrentCoAgents
        FROM agents LIMIT 1
      `).get()).toBeNull();
      expect((migrated.query("PRAGMA table_info(agents)").all() as Array<{ name: string }>).map(column => column.name))
        .toEqual(expect.arrayContaining([
          "primary_model",
          "primary_effort",
          "coagent_model",
          "coagent_effort",
          "max_concurrent_coagents",
        ]));
      expect(migrated.query(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('project_key_envelopes', 'encrypted_project_context', 'project_key_epochs', 'project_chat_events', 'project_prompt_updates', 'project_artifacts', 'project_file_references') ORDER BY name",
      ).all()).toEqual([{ name: "encrypted_project_context" }, { name: "project_artifacts" }, { name: "project_chat_events" }, { name: "project_file_references" }, { name: "project_key_envelopes" }, { name: "project_key_epochs" }, { name: "project_prompt_updates" }]);
      expect((migrated.query("PRAGMA table_info(agent_tasks)").all() as Array<{ name: string }>).map(column => column.name))
        .toContain("prompt_envelope_json");
      expect((migrated.query("PRAGMA table_info(agent_tasks)").all() as Array<{ name: string }>).map(column => column.name))
        .toContain("private_share_message_id");
      expect((migrated.query("PRAGMA table_info(project_key_epochs)").all() as Array<{ name: string }>).map(column => column.name))
        .toContain("rotation_required");
      expect((migrated.query("PRAGMA table_info(project_chat_events)").all() as Array<{ name: string }>).map(column => column.name))
        .toEqual(expect.arrayContaining(["task_id", "final", "status"]));
      migrated.exec("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;");
      migrated.close();
      migrated = undefined;
    } finally {
      migrated?.close();
      migrated = undefined;
      Bun.gc(true);
      for (let attempt = 0; attempt < 60; attempt += 1) {
        try {
          rmSync(root, { recursive: true, force: true });
          break;
        } catch (error) {
          if (attempt === 59) throw error;
          await Bun.sleep(50);
        }
      }
    }
  });

  test("migrates legacy agent rows to explicit runtime defaults and enforces consistency", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-runtime-migration-"));
    const path = join(root, "server.sqlite3");
    let migrated: Database | undefined;
    try {
      const legacy = new Database(path, { create: true });
      legacy.exec("PRAGMA foreign_keys = ON");
      legacy.exec("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
      const appliedAt = new Date().toISOString();
      for (const migration of migrations.filter(item => item.version <= 21)) {
        legacy.exec(migration.sql);
        legacy.query("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)")
          .run(migration.version, appliedAt);
      }
      const invitationId = randomUUID();
      const deviceId = randomUUID();
      const projectId = randomUUID();
      const agentId = randomUUID();
      const taskId = randomUUID();
      legacy.query(`
        INSERT INTO invitations (id, token_hash, expires_at, consumed_at, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(invitationId, "legacy-token-hash", appliedAt, appliedAt, appliedAt);
      legacy.query(`
        INSERT INTO devices (
          id, public_key_pem, fingerprint, display_name, status, invitation_id,
          enrolled_at, approved_at, messaging_public_key_pem, project_wrap_public_key_pem
        ) VALUES (?, ?, ?, 'Legacy Host', 'approved', ?, ?, ?, ?, ?)
      `).run(deviceId, "legacy-signing-key", "legacy-fingerprint", invitationId,
        appliedAt, appliedAt, "legacy-messaging-key", "legacy-wrap-key");
      legacy.query("INSERT INTO projects (id, name, created_by_device_id, created_at) VALUES (?, 'Legacy', ?, ?)")
        .run(projectId, deviceId, appliedAt);
      legacy.query(`
        INSERT INTO project_members (project_id, device_id, role, joined_at)
        VALUES (?, ?, 'owner', ?)
      `).run(projectId, deviceId, appliedAt);
      legacy.query(`
        INSERT INTO agents (id, project_id, host_device_id, name, enabled, created_at)
        VALUES (?, ?, ?, 'Legacy Agent', 1, ?)
      `).run(agentId, projectId, deviceId, appliedAt);
      const insertLegacyTask = legacy.query(`
        INSERT INTO agent_tasks (
          id, project_id, requester_device_id, target_device_id, agent_id,
          prompt, nonce, issued_at, expires_at, requester_signature,
          server_signature, status, accepted_at
        ) VALUES (?, ?, ?, ?, ?, 'Legacy task', ?, ?, ?, 'request-signature',
          'server-signature', 'completed', ?)
      `);
      insertLegacyTask.run(taskId, projectId, deviceId, deviceId, agentId, randomUUID(),
        appliedAt, new Date(Date.now() + 60_000).toISOString(), appliedAt);
      insertLegacyTask.finalize();
      legacy.close();

      migrated = openDatabase(path);
      expect(migrated.query(`
        SELECT primary_model AS primaryModel, primary_effort AS primaryEffort,
          coagent_model AS coAgentModel, coagent_effort AS coAgentEffort,
          max_concurrent_coagents AS maxConcurrentCoAgents
        FROM agents WHERE id = ?
      `).get(agentId)).toEqual({
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "medium",
        coAgentModel: null,
        coAgentEffort: null,
        maxConcurrentCoAgents: 0,
      });
      expect(() => migrated!.query(`
        UPDATE agents SET coagent_model = 'gpt-5.6-luna',
          coagent_effort = 'medium', max_concurrent_coagents = 0
        WHERE id = ?
      `).run(agentId)).toThrow("inconsistent agent runtime definition");
      expect(migrated.query("SELECT id FROM agent_tasks WHERE id = ?").get(taskId)).toEqual({ id: taskId });
      expect(migrated.query("SELECT id FROM agents WHERE id = ?").get(agentId)).toEqual({ id: agentId });
      expect((migrated.query("PRAGMA foreign_key_list(agents)").all() as Array<{ table: string }>)
        .some(constraint => constraint.table === "project_members")).toBeFalse();
      expect(migrated.query("PRAGMA foreign_key_check").all()).toEqual([]);
      migrated.exec("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;");
      migrated.close();
      migrated = undefined;
    } finally {
      if (migrated) {
        try { migrated.exec("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;"); }
        finally { migrated.close(); }
      }
      Bun.gc(true);
      for (let attempt = 0; attempt < 60; attempt += 1) {
        try {
          rmSync(root, { recursive: true, force: true });
          break;
        } catch (error) {
          if (attempt === 59) throw error;
          await Bun.sleep(50);
        }
      }
    }
  });
});
