import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

const sessionRecordSchema = z.object({
  scopeFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  threadId: z.uuid(),
  turns: z.number().int().nonnegative().max(10_000),
  lastInputTokens: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
}).strict();

const sessionStoreSchema = z.object({
  version: z.literal(1),
  sessions: z.array(sessionRecordSchema).max(64),
}).strict();

export type CodexSessionRecord = z.infer<typeof sessionRecordSchema>;

function load(path: string): z.infer<typeof sessionStoreSchema> {
  if (!existsSync(path)) return { version: 1, sessions: [] };
  hardenSecretPath(path, { required: true });
  return sessionStoreSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

function save(path: string, value: z.infer<typeof sessionStoreSchema>): void {
  const parsed = sessionStoreSchema.parse(value);
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true });
  hardenSecretDir(directory, { required: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(parsed, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

export function loadCodexSession(path: string, scopeFingerprint: string): CodexSessionRecord | null {
  try {
    return load(path).sessions.find(record => record.scopeFingerprint === scopeFingerprint) ?? null;
  } catch {
    return null;
  }
}

export function saveCodexSession(path: string, record: CodexSessionRecord): void {
  const parsed = sessionRecordSchema.parse(record);
  let current: z.infer<typeof sessionStoreSchema>;
  try { current = load(path); }
  catch { current = { version: 1, sessions: [] }; }
  const sessions = [
    parsed,
    ...current.sessions.filter(item => item.scopeFingerprint !== parsed.scopeFingerprint),
  ].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt)).slice(0, 64);
  save(path, { version: 1, sessions });
}

export function deleteCodexSession(path: string, scopeFingerprint: string): void {
  let current: z.infer<typeof sessionStoreSchema>;
  try { current = load(path); }
  catch { return; }
  const sessions = current.sessions.filter(record => record.scopeFingerprint !== scopeFingerprint);
  if (sessions.length !== current.sessions.length) save(path, { version: 1, sessions });
}
