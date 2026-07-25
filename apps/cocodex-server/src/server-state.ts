import type { Database } from "bun:sqlite";

export function serverEpoch(db: Database): number {
  const row = db.query("SELECT value FROM server_state WHERE key = 'epoch'").get() as { value: string } | null;
  const epoch = Number(row?.value ?? "1");
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error("CoCodex Server epoch is invalid");
  return epoch;
}

export function advanceServerEpoch(db: Database): number {
  const next = serverEpoch(db) + 1;
  db.query("UPDATE server_state SET value = ? WHERE key = 'epoch'").run(String(next));
  return next;
}
