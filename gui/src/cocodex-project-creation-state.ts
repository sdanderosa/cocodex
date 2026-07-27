import type { Project } from "./cocodex-member-state";

/** Parse only the safe resident control result; key-envelope acknowledgements stay resident-only. */
export function projectCreatedFromControl(value: unknown): Project | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const event = value as Record<string, unknown>;
  if (event.source !== "control" || event.ok !== true
    || !event.project || typeof event.project !== "object" || Array.isArray(event.project)) {
    return undefined;
  }
  const project = event.project as Record<string, unknown>;
  if (typeof project.id !== "string" || typeof project.name !== "string"
    || (project.role !== "owner" && project.role !== "member")) {
    return undefined;
  }
  return { id: project.id, name: project.name, role: project.role };
}
