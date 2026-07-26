import { randomUUID } from "node:crypto";
import type { Database } from "bun:sqlite";
import type { ChatEvent, SharedProject } from "../../../packages/cocodex-protocol/src/index.ts";
import type { ProjectMemberView } from "../../../packages/cocodex-protocol/src/index.ts";

interface DeviceStatusRow {
  status: "pending" | "approved" | "revoked";
}

interface MembershipRow {
  role: "owner" | "member";
}

export function createProject(
  db: Database,
  name: string,
  ownerDeviceId: string,
  now = new Date(),
): SharedProject {
  const normalized = name.trim();
  if (normalized.length < 1 || normalized.length > 120) {
    throw new Error("Project name must be 1-120 characters");
  }
  const device = db.query("SELECT status FROM devices WHERE id = ?").get(ownerDeviceId) as DeviceStatusRow | null;
  if (!device || device.status !== "approved") throw new Error("Project owner device is not approved");
  const project: SharedProject = { id: randomUUID(), name: normalized, role: "owner" };
  db.transaction(() => {
    db.query(`
      INSERT INTO projects (id, name, created_by_device_id, created_at)
      VALUES (?, ?, ?, ?)
    `).run(project.id, project.name, ownerDeviceId, now.toISOString());
    db.query(`
      INSERT INTO project_members (project_id, device_id, role, joined_at)
      VALUES (?, ?, 'owner', ?)
    `).run(project.id, ownerDeviceId, now.toISOString());
  }).immediate();
  return project;
}

export function addProjectMember(
  db: Database,
  projectId: string,
  actorDeviceId: string,
  memberDeviceId: string,
  now = new Date(),
): void {
  const actor = db.query(`
    SELECT role FROM project_members WHERE project_id = ? AND device_id = ?
  `).get(projectId, actorDeviceId) as MembershipRow | null;
  if (actor?.role !== "owner") throw new Error("Only a project owner can add members");
  const member = db.query("SELECT status FROM devices WHERE id = ?").get(memberDeviceId) as DeviceStatusRow | null;
  if (!member || member.status !== "approved") throw new Error("Project member device is not approved");
  const existing = db.query(`
    SELECT 1 AS present FROM project_members WHERE project_id = ? AND device_id = ?
  `).get(projectId, memberDeviceId);
  if (existing) return;
  const count = db.query(`
    SELECT COUNT(*) AS count FROM project_members WHERE project_id = ?
  `).get(projectId) as { count: number };
  if (count.count >= 128) throw new Error("Project member limit reached");
  db.query(`
    INSERT INTO project_members (project_id, device_id, role, joined_at)
    VALUES (?, ?, 'member', ?)
    ON CONFLICT(project_id, device_id) DO NOTHING
  `).run(projectId, memberDeviceId, now.toISOString());
}

export function removeProjectMember(
  db: Database,
  projectId: string,
  ownerDeviceId: string,
  memberDeviceId: string,
  now = new Date(),
  afterRemoved?: () => void,
): void {
  const owner = requireProjectMembership(db, projectId, ownerDeviceId);
  if (owner.role !== "owner") throw new Error("Only a project owner can remove members");
  if (ownerDeviceId === memberDeviceId) throw new Error("A project owner cannot remove itself");
  const member = db.query(`
    SELECT role FROM project_members WHERE project_id = ? AND device_id = ?
  `).get(projectId, memberDeviceId) as MembershipRow | null;
  if (!member) throw new Error("Device is not a project member");
  if (member.role === "owner") throw new Error("A project owner cannot be removed");
  db.transaction(() => {
    db.query("DELETE FROM project_members WHERE project_id = ? AND device_id = ?")
      .run(projectId, memberDeviceId);
    db.query(`
      INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
      VALUES ('project.member.removed', ?, ?, ?, ?)
    `).run(ownerDeviceId, memberDeviceId, now.toISOString(), JSON.stringify({ projectId }));
    afterRemoved?.();
  }).immediate();
}

export function listProjects(db: Database, deviceId: string): SharedProject[] {
  return db.query(`
    SELECT p.id, p.name, pm.role
    FROM projects p
    JOIN project_members pm ON pm.project_id = p.id
    JOIN devices d ON d.id = pm.device_id
    WHERE pm.device_id = ? AND d.status = 'approved'
    ORDER BY p.created_at ASC, p.id ASC
  `).all(deviceId) as SharedProject[];
}

export function listProjectMembers(
  db: Database,
  projectId: string,
  deviceId: string,
): ProjectMemberView[] {
  requireProjectMembership(db, projectId, deviceId);
  return db.query(`
    SELECT
      d.id AS deviceId,
      d.display_name AS displayName,
      d.fingerprint,
      pm.role,
      d.device_key_certificate AS deviceKeyCertificate
    FROM project_members pm
    JOIN devices d ON d.id = pm.device_id
    WHERE pm.project_id = ? AND d.status = 'approved'
    ORDER BY CASE pm.role WHEN 'owner' THEN 0 ELSE 1 END, pm.joined_at ASC, d.id ASC
  `).all(projectId) as ProjectMemberView[];
}

export function requireProjectMembership(db: Database, projectId: string, deviceId: string): MembershipRow {
  const membership = db.query(`
    SELECT pm.role
    FROM project_members pm
    JOIN devices d ON d.id = pm.device_id
    WHERE pm.project_id = ? AND pm.device_id = ? AND d.status = 'approved'
  `).get(projectId, deviceId) as MembershipRow | null;
  if (!membership) throw new Error("Device is not an approved project member");
  return membership;
}

export interface AppendChatInput {
  projectId: string;
  eventId: string;
  senderDeviceId: string;
  content: string;
  clientCreatedAt: string;
}

export interface AppendChatResult {
  event: ChatEvent;
  created: boolean;
}

export function appendChatEventResult(
  db: Database,
  input: AppendChatInput,
  now = new Date(),
): AppendChatResult {
  requireProjectMembership(db, input.projectId, input.senderDeviceId);
  if (input.content.length < 1 || input.content.length > 32_768) {
    throw new Error("Chat content must be 1-32768 characters");
  }
  if (!Number.isFinite(new Date(input.clientCreatedAt).getTime())) {
    throw new Error("Invalid client creation time");
  }
  const existing = db.query(`
    SELECT
      sequence,
      project_id AS projectId,
      event_id AS eventId,
      sender_device_id AS senderDeviceId,
      content,
      client_created_at AS clientCreatedAt,
      accepted_at AS acceptedAt
    FROM chat_events WHERE event_id = ?
  `).get(input.eventId) as ChatEvent | null;
  if (existing) {
    if (
      existing.projectId !== input.projectId ||
      existing.senderDeviceId !== input.senderDeviceId ||
      existing.content !== input.content ||
      existing.clientCreatedAt !== input.clientCreatedAt
    ) {
      throw new Error("Event ID was already used with different content");
    }
    return { event: existing, created: false };
  }
  const result = db.query(`
    INSERT INTO chat_events (
      project_id, event_id, sender_device_id, content, client_created_at, accepted_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    input.projectId,
    input.eventId,
    input.senderDeviceId,
    input.content,
    input.clientCreatedAt,
    now.toISOString(),
  );
  const event = db.query(`
    SELECT
      sequence,
      project_id AS projectId,
      event_id AS eventId,
      sender_device_id AS senderDeviceId,
      content,
      client_created_at AS clientCreatedAt,
      accepted_at AS acceptedAt
    FROM chat_events WHERE sequence = ?
  `).get(Number(result.lastInsertRowid)) as ChatEvent;
  return { event, created: true };
}

export function appendChatEvent(db: Database, input: AppendChatInput, now = new Date()): ChatEvent {
  return appendChatEventResult(db, input, now).event;
}

export function chatEventsAfter(
  db: Database,
  projectId: string,
  deviceId: string,
  afterSequence: number,
  limit = 500,
): ChatEvent[] {
  requireProjectMembership(db, projectId, deviceId);
  const boundedLimit = Math.max(1, Math.min(500, Math.trunc(limit)));
  return db.query(`
    SELECT
      sequence,
      project_id AS projectId,
      event_id AS eventId,
      sender_device_id AS senderDeviceId,
      content,
      client_created_at AS clientCreatedAt,
      accepted_at AS acceptedAt
    FROM chat_events
    WHERE project_id = ? AND sequence > ?
    ORDER BY sequence ASC
    LIMIT ?
  `).all(projectId, afterSequence, boundedLimit) as ChatEvent[];
}
