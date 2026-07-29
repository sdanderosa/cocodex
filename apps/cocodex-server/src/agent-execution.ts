import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  agentExecutionSigningTranscript,
  type AgentExecutionTranscriptInput,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { requireProjectMembership } from "./shared-state";
import { assertProjectUnlocked } from "./project-locks";

const worktreeRefPattern =
  /^worktrees\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/([A-Za-z0-9._-]{1,80})\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;
const branchPattern =
  /^cocodex\/[0-9a-f]{8}\/[A-Za-z0-9._-]{1,80}\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const branchComponentPattern = /[^A-Za-z0-9._-]+/g;

export interface AgentExecutionReport extends AgentExecutionTranscriptInput {
  signature: string;
}

interface TaskRow {
  id: string;
  projectId: string;
  chatId: string;
  agentId: string;
  targetDeviceId: string;
  status: "queued" | "running" | "completed" | "failed";
  acceptedAt: string;
  hostDeviceId: string;
  enabled: number;
  publicKeyPem: string;
  deviceStatus: "pending" | "approved" | "revoked";
  workspaceMode: "shared" | "git-worktree" | null;
  workspaceRef: string | null;
  branch: string | null;
  baseCommit: string | null;
  mergeTarget: string | null;
  startedAt: string | null;
  signature: string | null;
}

function agentBranchComponent(agentId: string): string {
  const component = agentId.trim()
    .replace(branchComponentPattern, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  if (!component || component === "." || component === ".." || component.endsWith(".lock")) {
    throw new Error("Agent ID cannot form a safe Git branch");
  }
  return component;
}

function validateWorkspaceMetadata(input: AgentExecutionReport): void {
  if (input.workspaceMode === "shared") {
    if (input.workspaceRef !== "configured-workspace"
      || input.branch !== null || input.baseCommit !== null || input.mergeTarget !== null) {
      throw new Error("Shared execution workspace metadata is invalid");
    }
    return;
  }
  const ref = worktreeRefPattern.exec(input.workspaceRef);
  const expectedComponent = agentBranchComponent(input.agentId);
  const expectedBranch = ref
    ? `cocodex/${input.projectId.slice(0, 8)}/${expectedComponent}/${input.taskId}`
    : "";
  if (!ref || ref[1]!.toLowerCase() !== input.projectId.toLowerCase()
    || ref[3]!.toLowerCase() !== input.taskId.toLowerCase()
    || ref[2] !== expectedComponent
    || !branchPattern.test(input.branch ?? "")
    || input.branch !== expectedBranch
    || input.baseCommit === null || input.mergeTarget === null) {
    throw new Error("Git worktree execution metadata is invalid");
  }
}

function sameReport(row: TaskRow, input: AgentExecutionReport): boolean {
  return row.workspaceMode === input.workspaceMode
    && row.workspaceRef === input.workspaceRef
    && row.branch === input.branch
    && row.baseCommit === input.baseCommit
    && row.mergeTarget === input.mergeTarget
    && row.startedAt === input.startedAt
    && row.signature === input.signature;
}

export function acceptAgentExecutionReport(
  db: Database,
  actorDeviceId: string,
  input: AgentExecutionReport,
  now = new Date(),
): { taskId: string; startedAt: string; created: boolean } {
  const row = db.query(`
    SELECT t.id, t.project_id AS projectId, t.chat_id AS chatId, t.agent_id AS agentId,
      t.target_device_id AS targetDeviceId, t.status, t.accepted_at AS acceptedAt,
      a.host_device_id AS hostDeviceId, a.enabled,
      d.public_key_pem AS publicKeyPem, d.status AS deviceStatus,
      t.workspace_mode AS workspaceMode, t.workspace_ref AS workspaceRef,
      t.worktree_branch AS branch, t.base_commit AS baseCommit,
      t.merge_target AS mergeTarget, t.execution_started_at AS startedAt,
      t.execution_signature AS signature
    FROM agent_tasks t
    JOIN agents a ON a.id = t.agent_id AND a.project_id = t.project_id
    JOIN devices d ON d.id = t.target_device_id
    WHERE t.id = ?
  `).get(input.taskId) as TaskRow | null;
  if (!row || row.projectId !== input.projectId || row.chatId !== input.chatId
    || row.agentId !== input.agentId) {
    throw new Error("Agent execution report does not match a task");
  }
  assertProjectUnlocked(db, input.projectId);
  if (row.targetDeviceId !== actorDeviceId || row.hostDeviceId !== actorDeviceId
    || row.deviceStatus !== "approved" || row.enabled !== 1) {
    throw new Error("Authenticated device cannot report this agent execution");
  }
  requireProjectMembership(db, input.projectId, actorDeviceId);
  if (row.status !== "queued" && row.status !== "running") {
    throw new Error("Agent execution report cannot update a finished task");
  }
  validateWorkspaceMetadata(input);
  const startedMs = Date.parse(input.startedAt);
  if (!Number.isFinite(startedMs) || startedMs > now.getTime() + 60_000
    || startedMs < Date.parse(row.acceptedAt) - 60_000) {
    throw new Error("Agent execution start time is invalid");
  }
  const publicKey = createPublicKey(row.publicKeyPem);
  if (publicKey.asymmetricKeyType !== "ed25519"
    || !verify(null, agentExecutionSigningTranscript(input), publicKey, Buffer.from(input.signature, "base64url"))) {
    throw new Error("Agent execution report signature is invalid");
  }
  if (row.startedAt !== null) {
    if (!sameReport(row, input)) {
      throw new Error("Agent execution report was reused with different content");
    }
    return { taskId: row.id, startedAt: row.startedAt, created: false };
  }
  db.transaction(() => {
    assertProjectUnlocked(db, input.projectId);
    const result = db.query(`
      UPDATE agent_tasks
      SET status = 'running', workspace_mode = ?, workspace_ref = ?,
        worktree_branch = ?, base_commit = ?, merge_target = ?,
        execution_started_at = ?, execution_signature = ?
      WHERE id = ? AND execution_started_at IS NULL
        AND status IN ('queued', 'running')
    `).run(
      input.workspaceMode,
      input.workspaceRef,
      input.branch,
      input.baseCommit,
      input.mergeTarget,
      input.startedAt,
      input.signature,
      input.taskId,
    );
    if (result.changes !== 1) throw new Error("Agent execution report lost an update race");
    db.query(`
      INSERT INTO audit_events (
        event_type, actor_device_id, subject_id, occurred_at, details_json
      ) VALUES ('agent.execution.started', ?, ?, ?, ?)
    `).run(actorDeviceId, input.taskId, now.toISOString(), JSON.stringify({
      projectId: input.projectId,
      chatId: input.chatId,
      agentId: input.agentId,
      workspaceMode: input.workspaceMode,
      workspaceRef: input.workspaceRef,
      branch: input.branch,
      baseCommit: input.baseCommit,
      mergeTarget: input.mergeTarget,
      startedAt: input.startedAt,
    }));
  }).immediate();
  return { taskId: input.taskId, startedAt: input.startedAt, created: true };
}
