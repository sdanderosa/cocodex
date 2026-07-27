import { describe, expect, test } from "bun:test";
import { projectCreatedFromControl } from "../src/cocodex-project-creation-state";

describe("CoCodex project creation UI state", () => {
  test("accepts the resident safe control result without requiring the withheld envelope frame", () => {
    expect(projectCreatedFromControl({
      source: "control",
      id: "create-1",
      ok: true,
      projectId: "project-1",
      project: { id: "project-1", name: "Nocturne Launcher", role: "owner" },
      created: true,
    })).toEqual({ id: "project-1", name: "Nocturne Launcher", role: "owner" });
    expect(projectCreatedFromControl({
      source: "server",
      frame: { type: "project.created", envelopes: [{ sealedProjectKey: "secret" }] },
    })).toBeUndefined();
    expect(projectCreatedFromControl({
      source: "control",
      ok: false,
      project: { id: "project-1", name: "Nocturne Launcher", role: "owner" },
    })).toBeUndefined();
  });
});
