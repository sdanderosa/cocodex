import { describe, expect, test } from "bun:test";
import {
  orderedProjects,
  projectLifecycleCommand,
  projectLeaveCommand,
  reconcileDeletedProject,
} from "../src/cocodex-project-lifecycle-state";
import type { Project } from "../src/cocodex-member-state";

const lock = { state: "locked" as const, revision: 2, lockedAt: "2030-01-01T00:00:00.000Z", lockedByDeviceId: crypto.randomUUID(), reason: "Owner review" };
const owner: Project = { id: crypto.randomUUID(), name: "Nocturne", role: "owner", state: "archived", lifecycleRevision: 4, lock };

describe("CoCodex project lifecycle UI state", () => {
  test("builds minimal owner commands and keeps exact deletion confirmation", () => {
    expect(projectLifecycleCommand(owner, "restore")).toEqual({
      type: "project.lifecycle.update", projectId: owner.id, action: "restore", expectedRevision: 4,
    });
    expect(projectLifecycleCommand(owner, "delete", "Nocturne")).toEqual({
      type: "project.lifecycle.update", projectId: owner.id, action: "delete", expectedRevision: 4,
      confirmationName: "Nocturne",
    });
    expect(() => projectLifecycleCommand(owner, "delete", "nocturne")).toThrow("exactly match");
    expect(projectLifecycleCommand({ ...owner, state: "active" }, "rename", "  Nocturne Next  "))
      .toMatchObject({ action: "rename", name: "Nocturne Next", expectedRevision: 4 });
    expect(() => projectLifecycleCommand({ ...owner, role: "member" }, "restore")).toThrow("owner");
    const member = { ...owner, role: "member" as const };
    expect(projectLeaveCommand(member)).toEqual({
      type: "project.member.leave", projectId: member.id,
    });
    expect(() => projectLeaveCommand(owner)).toThrow("non-owner");
  });

  test("orders archived projects last and selects another active project after deletion", () => {
    const active: Project = { ...owner, id: crypto.randomUUID(), name: "Active", state: "active" };
    const archived: Project = { ...owner, id: crypto.randomUUID(), name: "Archived" };
    expect(orderedProjects([archived, active]).map(project => project.id)).toEqual([active.id, archived.id]);
    expect(reconcileDeletedProject([archived, active], archived.id, archived.id)).toEqual({
      projects: [active], selectedProjectId: active.id,
    });
  });
});
