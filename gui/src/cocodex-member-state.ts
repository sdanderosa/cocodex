import type { TFn } from "./i18n";

export interface Project {
  id: string;
  name: string;
  role: "owner" | "member";
}

export interface ProjectMember {
  deviceId: string;
  displayName: string;
  fingerprint: string;
  role: "owner" | "member";
  trusted: boolean;
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
