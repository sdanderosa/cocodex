import { describe, expect, test } from "bun:test";
import { buildTaskDependencyGraph } from "../src/cocodex-task-graph";

const task = (id: string, agentName: string, status: "queued" | "running" | "completed" | "failed", dependencies: string[] = [], inputArtifactIds: string[] = []) => ({
  id,
  agentName,
  status,
  dependencies,
  inputArtifactIds,
  acceptedAt: `2026-07-28T10:00:0${id.length}.000Z`,
});

describe("CoCodex task dependency graph", () => {
  test("derives ready, waiting, failed, missing, and artifact handoff state", () => {
    const graph = buildTaskDependencyGraph([
      task("lucas", "Lucas", "completed"),
      task("angela", "Angela", "queued", ["lucas"], ["lucas-plan"]),
      task("sue", "Sue", "queued", ["angela"]),
      task("review", "Review", "queued", ["unknown"]),
      task("failed", "Failed", "failed"),
      task("integration", "Integration", "queued", ["failed"]),
    ], [{
      id: "lucas-plan",
      taskId: "lucas",
      title: "Lucas plan",
      status: "accepted",
    }]);

    const byId = new Map(graph.map(node => [node.task.id, node]));
    expect(byId.get("lucas")).toMatchObject({ state: "completed", layer: 0 });
    expect(byId.get("angela")).toMatchObject({
      state: "ready",
      layer: 1,
      artifactInputs: [{ title: "Lucas plan", status: "accepted", sourceTaskId: "lucas" }],
    });
    expect(byId.get("sue")).toMatchObject({ state: "blocked-waiting", layer: 2 });
    expect(byId.get("review")).toMatchObject({ state: "blocked-missing" });
    expect(byId.get("integration")).toMatchObject({ state: "blocked-failed" });
  });

  test("bounds cyclic dependency rendering without recursion", () => {
    const graph = buildTaskDependencyGraph([
      task("a", "A", "queued", ["b"]),
      task("b", "B", "queued", ["a"]),
    ], []);

    expect(graph.map(node => node.state)).toEqual(["blocked-cycle", "blocked-cycle"]);
    expect(graph.every(node => node.layer === 0)).toBeTrue();
  });
});
