import type { Database } from "bun:sqlite";
import { PROJECT_CONTEXT_MAX_BYTES } from "../../../packages/cocodex-protocol/src/index.ts";
import { requireProjectMembership } from "./shared-state";

const MAX_GOAL_LENGTH = 32_768;

export interface SharedProjectContext {
  projectId: string;
  finalGoal: string;
  context: Record<string, unknown>;
  revision: number;
  updatedByDeviceId: string | null;
  updatedAt: string | null;
}

function readContext(db: Database, projectId: string): SharedProjectContext {
  const row = db.query(`SELECT project_id AS projectId, final_goal AS finalGoal,
    context_json AS contextJson, revision, updated_by_device_id AS updatedByDeviceId,
    updated_at AS updatedAt FROM shared_project_context WHERE project_id = ?`).get(projectId) as {
      projectId: string; finalGoal: string; contextJson: string; revision: number;
      updatedByDeviceId: string | null; updatedAt: string | null;
    } | null;
  if (!row) return { projectId, finalGoal: "", context: {}, revision: 0, updatedByDeviceId: null, updatedAt: null };
  let context: unknown;
  try { context = JSON.parse(row.contextJson); } catch { throw new Error("Shared project context is corrupted"); }
  if (!context || typeof context !== "object" || Array.isArray(context)) throw new Error("Shared project context is invalid");
  return { projectId: row.projectId, finalGoal: row.finalGoal, context: context as Record<string, unknown>, revision: row.revision, updatedByDeviceId: row.updatedByDeviceId, updatedAt: row.updatedAt };
}

export function getSharedProjectContext(db: Database, projectId: string, deviceId: string): SharedProjectContext {
  requireProjectMembership(db, projectId, deviceId);
  return readContext(db, projectId);
}

export function updateSharedProjectContext(
  db: Database,
  projectId: string,
  deviceId: string,
  expectedRevision: number,
  finalGoal: string,
  context: Record<string, unknown>,
  now = new Date(),
): SharedProjectContext {
  requireProjectMembership(db, projectId, deviceId);
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) throw new Error("Invalid context revision");
  if (typeof finalGoal !== "string") throw new Error("Final Goal must be a string");
  if (!context || typeof context !== "object" || Array.isArray(context)) throw new Error("Shared project context must be an object");
  if (finalGoal.length > MAX_GOAL_LENGTH) throw new Error("Final Goal is too large");
  let contextJson: string;
  try {
    const serialized = JSON.stringify(context);
    if (typeof serialized !== "string") throw new Error("not an object");
    contextJson = serialized;
  } catch {
    throw new Error("Shared project context is not serializable");
  }
  if (Buffer.byteLength(contextJson, "utf8") > PROJECT_CONTEXT_MAX_BYTES) throw new Error("Shared project context is too large");
  return db.transaction(() => {
    const current = readContext(db, projectId);
    if (current.revision !== expectedRevision) throw new Error(`Shared project context revision conflict (expected ${expectedRevision}, current ${current.revision})`);
    const revision = current.revision + 1;
    const updatedAt = now.toISOString();
    db.query(`INSERT INTO shared_project_context
      (project_id, chat_id, final_goal, context_json, revision, updated_by_device_id, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(project_id, chat_id) DO UPDATE SET final_goal = excluded.final_goal,
      context_json = excluded.context_json, revision = excluded.revision,
      updated_by_device_id = excluded.updated_by_device_id, updated_at = excluded.updated_at`)
      .run(projectId, projectId, finalGoal, contextJson, revision, deviceId, updatedAt);
    return { projectId, finalGoal, context, revision, updatedByDeviceId: deviceId, updatedAt };
  }).immediate();
}
