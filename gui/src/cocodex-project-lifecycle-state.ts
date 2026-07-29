import type { Project } from "./cocodex-member-state";

export type ProjectLifecycleAction = "rename" | "archive" | "restore" | "delete";

export function projectLifecycleCommand(
  project: Project,
  action: ProjectLifecycleAction,
  value?: string,
) {
  const expectedRevision = project.lifecycleRevision ?? 0;
  if (project.role !== "owner") throw new Error("Only the project owner can change project lifecycle state");
  if (action === "rename") {
    const name = value?.trim() ?? "";
    if (!name || name.length > 120) throw new Error("Project name must be 1-120 characters");
    return { type: "project.lifecycle.update", projectId: project.id, action, expectedRevision, name } as const;
  }
  if (action === "delete") {
    if (value !== project.name) throw new Error("Project deletion confirmation must exactly match its name");
    return {
      type: "project.lifecycle.update",
      projectId: project.id,
      action,
      expectedRevision,
      confirmationName: value,
    } as const;
  }
  return { type: "project.lifecycle.update", projectId: project.id, action, expectedRevision } as const;
}

export function projectLeaveCommand(project: Project) {
  if (project.role !== "member") throw new Error("Only a non-owner project member can leave");
  return { type: "project.member.leave", projectId: project.id } as const;
}

export function reconcileDeletedProject(
  projects: Project[],
  selectedProjectId: string,
  deletedProjectId: string,
): { projects: Project[]; selectedProjectId: string } {
  const remaining = projects.filter(project => project.id !== deletedProjectId);
  return {
    projects: remaining,
    selectedProjectId: selectedProjectId === deletedProjectId
      ? remaining.find(project => (project.state ?? "active") === "active")?.id ?? remaining[0]?.id ?? ""
      : selectedProjectId,
  };
}

export function orderedProjects(projects: Project[]): Project[] {
  return [...projects].sort((left, right) => {
    const leftArchived = (left.state ?? "active") === "archived" ? 1 : 0;
    const rightArchived = (right.state ?? "active") === "archived" ? 1 : 0;
    return leftArchived - rightArchived || left.name.localeCompare(right.name) || left.id.localeCompare(right.id);
  });
}
