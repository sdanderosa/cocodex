import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
      expect(migrated.query("SELECT version FROM schema_migrations ORDER BY version").all())
        .toEqual([{ version: 1 }, { version: 2 }, { version: 3 }, { version: 4 }, { version: 5 }, { version: 6 }, { version: 7 }, { version: 8 }, { version: 9 }, { version: 10 }, { version: 11 }, { version: 12 }, { version: 13 }, { version: 14 }, { version: 15 }]);
      expect(migrated.query(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('project_key_envelopes', 'encrypted_project_context', 'project_key_epochs', 'project_chat_events', 'project_prompt_updates', 'project_artifacts') ORDER BY name",
      ).all()).toEqual([{ name: "encrypted_project_context" }, { name: "project_artifacts" }, { name: "project_chat_events" }, { name: "project_key_envelopes" }, { name: "project_key_epochs" }, { name: "project_prompt_updates" }]);
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
});
