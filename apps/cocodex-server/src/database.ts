import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { hardenSecretDir, hardenSecretPath } from "../../../src/lib/windows-secret-acl";
import { migrations } from "./migrations";

function applyMigrations(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    );
  `);
  const newest = db.query("SELECT MAX(version) AS version FROM schema_migrations").get() as { version: number | null };
  const latestSupported = migrations.at(-1)?.version ?? 0;
  if ((newest.version ?? 0) > latestSupported) {
    throw new Error(`Database schema version ${newest.version} is newer than this server supports`);
  }
  const agentColumns = db.query("PRAGMA table_info(agent_tasks)").all() as Array<{ name: string }>;
  if (
    agentColumns.some(column => column.name === "client_created_at") &&
    !db.query("SELECT 1 FROM schema_migrations WHERE version = 2").get()
  ) {
    db.transaction(() => {
      const hasEvents = db.query(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'agent_task_events'",
      ).get();
      if (hasEvents) db.exec("ALTER TABLE agent_task_events RENAME TO legacy_agent_task_events_v1");
      db.exec("ALTER TABLE agent_tasks RENAME TO legacy_agent_tasks_v1");
    }).immediate();
  }
  const apply = db.transaction((version: number, sql: string) => {
    db.exec(sql);
    db.query("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)")
      .run(version, new Date().toISOString());
  });
  for (const migration of migrations) {
    const present = db.query("SELECT 1 FROM schema_migrations WHERE version = ?").get(migration.version);
    if (!present) apply.immediate(migration.version, migration.sql);
  }
  const invalid = db.query("PRAGMA foreign_key_check").all();
  if (invalid.length > 0) throw new Error("Database foreign-key validation failed after migration");
}

export function openDatabase(path: string): Database {
  if (path !== ":memory:") {
    mkdirSync(dirname(path), { recursive: true });
    hardenSecretDir(dirname(path), { required: true });
  }
  const db = new Database(path, { create: true, strict: true });
  if (path !== ":memory:") hardenSecretPath(path, { required: true });
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA synchronous = FULL;");
  db.exec("PRAGMA busy_timeout = 5000;");
  applyMigrations(db);
  return db;
}
