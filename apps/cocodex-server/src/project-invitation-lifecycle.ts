import type { Database } from "bun:sqlite";

export function expirePendingProjectInvitationsForProject(
  db: Database,
  projectId: string,
  reason: "key-rotation-required" | "project-locked" | "member-leave-pending",
  now = new Date(),
): void {
  const expired = db.query(`
    SELECT invitation_id AS invitationId
    FROM project_invitations
    WHERE project_id = ? AND status = 'pending'
  `).all(projectId) as Array<{ invitationId: string }>;
  if (expired.length === 0) return;
  db.query(`
    UPDATE project_invitations
    SET status = 'expired', updated_at = ?
    WHERE project_id = ? AND status = 'pending'
  `).run(now.toISOString(), projectId);
  const audit = db.query(`
    INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
    VALUES ('project.invite.expired', NULL, ?, ?, ?)
  `);
  for (const invitation of expired) {
    audit.run(
      invitation.invitationId,
      now.toISOString(),
      JSON.stringify({ projectId, reason }),
    );
  }
}
