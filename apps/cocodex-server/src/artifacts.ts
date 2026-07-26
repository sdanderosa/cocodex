import type { Database } from "bun:sqlite";
import type { Artifact, ArtifactStatus, ArtifactType } from "@cocodex/protocol";
import { requireProjectMembership } from "./shared-state";

export interface PublishArtifactInput {
  id: string;
  projectId: string;
  taskId: string | null;
  authorDeviceId: string;
  type: ArtifactType;
  title: string;
  summary: string;
  content: string;
  status: ArtifactStatus;
}

export function publishArtifact(db: Database, input: PublishArtifactInput, now = new Date()): { artifact: Artifact; created: boolean } {
  requireProjectMembership(db, input.projectId, input.authorDeviceId);
  if (input.taskId) {
    const task = db.query("SELECT project_id AS projectId, target_device_id AS targetDeviceId FROM agent_tasks WHERE id = ?")
      .get(input.taskId) as { projectId: string; targetDeviceId: string } | null;
    if (!task || task.projectId !== input.projectId) throw new Error("Artifact task is not in this project");
    if (task.targetDeviceId !== input.authorDeviceId) {
      throw new Error("Task-linked artifact must be published by the task target device");
    }
  }
  const existing = db.query(`SELECT id, project_id AS projectId, task_id AS taskId, author_device_id AS authorDeviceId,
    type, title, summary, content, status, created_at AS createdAt, updated_at AS updatedAt
    FROM artifacts WHERE id = ?`).get(input.id) as Artifact | null;
  if (existing) {
    const same = JSON.stringify(existing) === JSON.stringify({ ...input, createdAt: existing.createdAt, updatedAt: existing.updatedAt });
    if (!same) throw new Error("Artifact ID was already used for different content");
    return { artifact: existing, created: false };
  }
  const createdAt = now.toISOString();
  const artifact: Artifact = { ...input, createdAt, updatedAt: createdAt };
  db.query(`INSERT INTO artifacts
    (id, project_id, task_id, author_device_id, type, title, summary, content, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    artifact.id, artifact.projectId, artifact.taskId, artifact.authorDeviceId, artifact.type,
    artifact.title.trim(), artifact.summary.trim(), artifact.content, artifact.status, createdAt, createdAt,
  );
  return { artifact, created: true };
}

export function listArtifacts(db: Database, projectId: string, deviceId: string): Artifact[] {
  requireProjectMembership(db, projectId, deviceId);
  return db.query(`SELECT id, project_id AS projectId, task_id AS taskId, author_device_id AS authorDeviceId,
    type, title, summary, content, status, created_at AS createdAt, updated_at AS updatedAt
    FROM artifacts WHERE project_id = ? ORDER BY created_at, id`).all(projectId) as Artifact[];
}
