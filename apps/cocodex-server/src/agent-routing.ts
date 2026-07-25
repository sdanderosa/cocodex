import type { Database } from "bun:sqlite";
import type { AgentTask, ChatEvent } from "@cocodex/protocol";
import { appendChatEvent, requireProjectMembership } from "./shared-state";

export interface CreateAgentTaskInput {
  id: string;
  projectId: string;
  requesterDeviceId: string;
  targetDeviceId: string;
  agentId: string;
  prompt: string;
  clientCreatedAt: string;
}

export function createAgentTask(db: Database, input: CreateAgentTaskInput, now = new Date()): AgentTask {
  requireProjectMembership(db, input.projectId, input.requesterDeviceId);
  requireProjectMembership(db, input.projectId, input.targetDeviceId);
  if (input.requesterDeviceId === input.targetDeviceId) {
    throw new Error("Remote agent target must be another enrolled device");
  }
  const task: AgentTask = {
    id: input.id,
    projectId: input.projectId,
    requesterDeviceId: input.requesterDeviceId,
    targetDeviceId: input.targetDeviceId,
    agentId: input.agentId.trim(),
    prompt: input.prompt,
    status: "queued",
    clientCreatedAt: input.clientCreatedAt,
    acceptedAt: now.toISOString(),
  };
  db.query(`
    INSERT INTO agent_tasks (
      id, project_id, requester_device_id, target_device_id, agent_id, prompt,
      status, client_created_at, accepted_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)
  `).run(
    task.id,
    task.projectId,
    task.requesterDeviceId,
    task.targetDeviceId,
    task.agentId,
    task.prompt,
    task.clientCreatedAt,
    task.acceptedAt,
  );
  return task;
}

interface TaskRow extends AgentTask {}

export function appendAgentResult(
  db: Database,
  targetDeviceId: string,
  taskId: string,
  eventId: string,
  content: string,
  final: boolean,
  status: "running" | "completed" | "failed",
  now = new Date(),
): { task: AgentTask; event: ChatEvent } {
  return db.transaction(() => {
    const task = db.query(`
      SELECT
        id,
        project_id AS projectId,
        requester_device_id AS requesterDeviceId,
        target_device_id AS targetDeviceId,
        agent_id AS agentId,
        prompt,
        status,
        client_created_at AS clientCreatedAt,
        accepted_at AS acceptedAt
      FROM agent_tasks WHERE id = ?
    `).get(taskId) as TaskRow | null;
    if (!task || task.targetDeviceId !== targetDeviceId) throw new Error("Agent task is not assigned to this device");
    if (task.status === "completed" || task.status === "failed") throw new Error("Agent task is already final");
    if (final !== (status === "completed" || status === "failed")) {
      throw new Error("Agent result final flag and status disagree");
    }
    const event = appendChatEvent(db, {
      projectId: task.projectId,
      eventId,
      senderDeviceId: targetDeviceId,
      content,
      clientCreatedAt: now.toISOString(),
    }, now);
    db.query(`
      INSERT INTO agent_task_events (task_id, chat_sequence, final, status)
      VALUES (?, ?, ?, ?)
    `).run(task.id, event.sequence, final ? 1 : 0, status);
    db.query(`
      UPDATE agent_tasks
      SET status = ?, completed_at = CASE WHEN ? THEN ? ELSE completed_at END
      WHERE id = ?
    `).run(status, final ? 1 : 0, now.toISOString(), task.id);
    return { task: { ...task, status }, event };
  }).immediate();
}
