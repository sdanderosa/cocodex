import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";
import { projectContentEnvelopeSchema, type ProjectContentEnvelope } from "@cocodex/protocol";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

const resultSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.result"),
  requestId: z.uuid(),
  taskId: z.uuid(),
  eventId: z.uuid(),
  content: z.string().min(1).max(32_768),
  final: z.boolean(),
  status: z.enum(["running", "completed", "failed"]),
  projectEnvelope: projectContentEnvelopeSchema.optional(),
}).strict();
export type DurableAgentResult = z.infer<typeof resultSchema> & { projectEnvelope?: ProjectContentEnvelope };

const taskRecordSchema = z.object({
  taskId: z.uuid(),
  state: z.enum(["started", "finished"]),
  results: z.array(resultSchema),
}).strict();
const journalSchema = z.object({
  version: z.literal(1),
  tasks: z.record(z.uuid(), taskRecordSchema),
}).strict();
type Journal = z.infer<typeof journalSchema>;

function load(path: string): Journal {
  if (!existsSync(path)) return { version: 1, tasks: {} };
  hardenSecretPath(path, { required: true });
  return journalSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

function save(path: string, journal: Journal): void {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true });
  hardenSecretDir(directory, { required: true });
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(journal, null, 2)}\n`, {
    encoding: "utf8", mode: 0o600, flag: "wx",
  });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

export function beginAgentTask(path: string, taskId: string): "new" | "started" | "finished" {
  const journal = load(path);
  const existing = journal.tasks[taskId];
  if (existing) return existing.state;
  journal.tasks[taskId] = { taskId, state: "started", results: [] };
  save(path, journal);
  return "new";
}

export function appendAgentResult(path: string, taskId: string, result: DurableAgentResult): void {
  const journal = load(path);
  const task = journal.tasks[taskId];
  if (!task) throw new Error("Agent task was not journaled before execution");
  if (!task.results.some(item => item.eventId === result.eventId)) task.results.push(result);
  if (result.final) task.state = "finished";
  save(path, journal);
}

export function pendingAgentResults(path: string, taskId: string): DurableAgentResult[] {
  return [...(load(path).tasks[taskId]?.results ?? [])];
}

export function acknowledgeAgentResult(path: string, taskId: string, eventId: string): void {
  const journal = load(path);
  const task = journal.tasks[taskId];
  if (!task) return;
  task.results = task.results.filter(result => result.eventId !== eventId);
  save(path, journal);
}
