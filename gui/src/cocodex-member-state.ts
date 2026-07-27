import type { TFn } from "./i18n";

export interface Project {
  id: string;
  name: string;
  role: "owner" | "member";
  lock?: {
    state: "active" | "locked";
    revision: number;
    lockedAt: string | null;
    lockedByDeviceId: string | null;
    reason: string | null;
  };
}

export interface ProjectMember {
  deviceId: string;
  displayName: string;
  fingerprint: string;
  role: "owner" | "member";
  trusted: boolean;
  /** Server-authoritative membership status. Older clients omit this field. */
  status?: "approved" | "revoked";
}

export interface ProjectSecurityIncident {
  state: "rotation-required" | "device-revoked";
  revokedDeviceId?: string;
  promotedOwnerDeviceId?: string | null;
  currentEpoch?: number;
  incidentId?: string;
  localDeviceRevoked?: boolean;
  /** Internal renderer acknowledgement that the owner removed the target. */
  memberRemoved?: boolean;
}

export function isRevokedProjectMember(member: ProjectMember): boolean {
  return member.status === "revoked";
}

export function markProjectMemberRevoked(
  members: ProjectMember[],
  revokedDeviceId: string,
): ProjectMember[] {
  return members.map(member => member.deviceId === revokedDeviceId
    ? { ...member, status: "revoked" as const }
    : member);
}

export function clearRecoveredProjectSecurity(
  incident: ProjectSecurityIncident | undefined,
  removedDeviceId: string,
  keyEpoch: number,
): ProjectSecurityIncident | undefined {
  if (!incident || incident.state !== "device-revoked"
    || incident.revokedDeviceId !== removedDeviceId
    || !incident.memberRemoved
    || typeof incident.currentEpoch !== "number"
    || keyEpoch <= incident.currentEpoch) {
    return incident;
  }
  return undefined;
}

export function reconcileRevokedProject(
  projects: Project[],
  selectedProjectId: string,
  revokedProjectId: string,
): { projects: Project[]; selectedProjectId: string; clearedSelection: boolean } {
  const remaining = projects.filter(project => project.id !== revokedProjectId);
  const clearedSelection = selectedProjectId === revokedProjectId;
  return {
    projects: remaining,
    selectedProjectId: clearedSelection ? remaining[0]?.id ?? "" : selectedProjectId,
    clearedSelection,
  };
}

export function projectMemberRemovalCommand(projectId: string, member: ProjectMember) {
  return {
    type: "project.member.remove-and-rotate",
    projectId,
    deviceId: member.deviceId,
  } as const;
}

export function confirmProjectMemberRemoval(
  t: TFn,
  member: ProjectMember,
  confirmAction: (message: string) => boolean,
): boolean {
  return confirmAction(t("cocodex.members.removeConfirm", {
    name: member.displayName,
    fingerprint: member.fingerprint.slice(-12),
  }));
}
