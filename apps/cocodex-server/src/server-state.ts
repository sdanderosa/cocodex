import type { Database } from "bun:sqlite";

export type ServerAuthorityStatus = "active" | "prepared" | "retired";

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

export function setServerEpoch(db: Database, epoch: number): number {
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error("CoCodex Server epoch is invalid");
  const current = serverEpoch(db);
  if (epoch < current) throw new Error(`CoCodex Server epoch ${epoch} is older than the current epoch ${current}`);
  db.query("UPDATE server_state SET value = ? WHERE key = 'epoch'").run(String(epoch));
  return epoch;
}

export function serverAuthorityStatus(db: Database): ServerAuthorityStatus {
  const row = db.query("SELECT value FROM server_state WHERE key = 'authority_status'").get() as { value: string } | null;
  const status = row?.value ?? "active";
  if (status !== "active" && status !== "prepared" && status !== "retired") {
    throw new Error("CoCodex Server authority status is invalid");
  }
  return status;
}

export function serverIdentityFingerprint(db: Database): string | undefined {
  const row = db.query("SELECT value FROM server_state WHERE key = 'identity_fingerprint'").get() as { value: string } | null;
  const value = row?.value?.trim();
  return value || undefined;
}

export function initializeServerAuthority(db: Database, fingerprint: string, status: ServerAuthorityStatus = "active"): void {
  if (!fingerprint.trim()) throw new Error("CoCodex Server identity fingerprint is required");
  db.query("UPDATE server_state SET value = ? WHERE key = 'identity_fingerprint'").run(fingerprint.trim());
  db.query("UPDATE server_state SET value = ? WHERE key = 'authority_status'").run(status);
}

export function requireActiveServerAuthority(db: Database): void {
  const status = serverAuthorityStatus(db);
  if (status !== "active") throw new Error(`CoCodex Server authority is ${status}`);
}

export function retireServerAuthority(db: Database): void {
  db.transaction(() => {
    db.query("UPDATE server_state SET value = 'retired' WHERE key = 'authority_status'").run();
  }).immediate();
}

export function prepareServerAuthority(db: Database, fingerprint: string): void {
  initializeServerAuthority(db, fingerprint, "prepared");
}
