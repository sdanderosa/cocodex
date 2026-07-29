export type TaskDependencyStatus = "queued" | "running" | "completed" | "failed";

export interface DependencyGraphTask {
  id: string;
  agentName: string;
  status: TaskDependencyStatus;
  dependencies: string[];
  inputArtifactIds: string[];
  acceptedAt: string;
}

export interface DependencyGraphArtifact {
  id: string;
  taskId: string | null;
  title: string;
  status: string;
}

export type TaskGraphState =
  | "ready"
  | "running"
  | "completed"
  | "failed"
  | "blocked-waiting"
  | "blocked-failed"
  | "blocked-missing"
  | "blocked-cycle";

export interface TaskGraphDependency {
  id: string;
  agentName: string | null;
  state: TaskGraphState | "missing";
}

export interface TaskGraphArtifactInput {
  id: string;
  title: string | null;
  status: string | null;
  sourceTaskId: string | null;
}

export interface TaskGraphNode<T extends DependencyGraphTask = DependencyGraphTask> {
  task: T;
  state: TaskGraphState;
  layer: number;
  dependencies: TaskGraphDependency[];
  artifactInputs: TaskGraphArtifactInput[];
}

export function buildTaskDependencyGraph<T extends DependencyGraphTask>(
  tasks: readonly T[],
  artifacts: readonly DependencyGraphArtifact[],
): TaskGraphNode<T>[] {
  const byId = new Map(tasks.map(task => [task.id, task]));
  const artifactsById = new Map(artifacts.map(artifact => [artifact.id, artifact]));
  const cycles = new Set<string>();
  const visited = new Set<string>();
  const stack: string[] = [];

  const findCycles = (id: string) => {
    const cycleStart = stack.indexOf(id);
    if (cycleStart >= 0) {
      for (const cycleId of stack.slice(cycleStart)) cycles.add(cycleId);
      return;
    }
    if (visited.has(id)) return;
    const task = byId.get(id);
    if (!task) return;
    stack.push(id);
    for (const dependencyId of task.dependencies) findCycles(dependencyId);
    stack.pop();
    visited.add(id);
  };
  for (const task of tasks) findCycles(task.id);

  const stateMemo = new Map<string, TaskGraphState>();
  const stateFor = (task: T): TaskGraphState => {
    const existing = stateMemo.get(task.id);
    if (existing) return existing;
    if (task.status === "running" || task.status === "completed" || task.status === "failed") {
      stateMemo.set(task.id, task.status);
      return task.status;
    }
    if (cycles.has(task.id)) {
      stateMemo.set(task.id, "blocked-cycle");
      return "blocked-cycle";
    }
    const dependencies = task.dependencies.map(id => byId.get(id));
    let state: TaskGraphState;
    if (dependencies.some(dependency => !dependency)) {
      state = "blocked-missing";
    } else {
      const dependencyStates = dependencies.map(dependency => stateFor(dependency!));
      if (dependencyStates.some(value => value === "failed" || value === "blocked-failed")) {
        state = "blocked-failed";
      } else if (dependencyStates.some(value => value === "blocked-cycle")) {
        state = "blocked-cycle";
      } else if (dependencyStates.some(value => value !== "completed")) {
        state = "blocked-waiting";
      } else {
        state = "ready";
      }
    }
    stateMemo.set(task.id, state);
    return state;
  };

  const layerMemo = new Map<string, number>();
  const layerFor = (task: T, trail = new Set<string>()): number => {
    const existing = layerMemo.get(task.id);
    if (existing !== undefined) return existing;
    if (trail.has(task.id) || cycles.has(task.id)) return 0;
    const nextTrail = new Set(trail);
    nextTrail.add(task.id);
    const present = task.dependencies.map(id => byId.get(id)).filter((value): value is T => Boolean(value));
    const layer = present.length ? Math.max(...present.map(dependency => layerFor(dependency, nextTrail))) + 1 : 0;
    layerMemo.set(task.id, layer);
    return layer;
  };

  return tasks.map(task => ({
    task,
    state: stateFor(task),
    layer: layerFor(task),
    dependencies: task.dependencies.map((id): TaskGraphDependency => {
      const dependency = byId.get(id);
      return {
        id,
        agentName: dependency?.agentName ?? null,
        state: dependency ? stateFor(dependency) : "missing",
      };
    }),
    artifactInputs: task.inputArtifactIds.map(id => {
      const artifact = artifactsById.get(id);
      return {
        id,
        title: artifact?.title ?? null,
        status: artifact?.status ?? null,
        sourceTaskId: artifact?.taskId ?? null,
      };
    }),
  })).sort((left, right) =>
    left.layer - right.layer
    || Date.parse(left.task.acceptedAt) - Date.parse(right.task.acceptedAt)
    || left.task.id.localeCompare(right.task.id));
}
