import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Database } from "bun:sqlite";
import type { ServerConfig } from "./config";
import { serverAuthorityStatus, serverEpoch } from "./server-state";
import { tlsCertificateFingerprint } from "./tls";

export interface DatabaseAdminSummary {
  health: "ok" | "corrupt";
  quickCheck: string;
  foreignKeyViolations: number;
  schemaVersion: number;
  pageCount: number;
  pageSizeBytes: number;
  logicalBytes: number;
  counts: {
    devices: { pending: number; approved: number; revoked: number };
    projects: number;
    memberships: number;
    agents: number;
    tasks: { queued: number; running: number; completed: number; failed: number };
    privateCiphertexts: number;
    projectCiphertextRecords: number;
    auditEvents: number;
  };
}

function integerPragma(db: Database, pragma: string, field: string): number {
  const row = db.query(`PRAGMA ${pragma}`).get() as Record<string, unknown> | null;
  const value = Number(row?.[field] ?? 0);
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function scalarCount(db: Database, sql: string): number {
  const row = db.query(sql).get() as { count: number } | null;
  return Number(row?.count ?? 0);
}

function groupedCounts<T extends string>(
  db: Database,
  sql: string,
  keys: readonly T[],
): Record<T, number> {
  const result = Object.fromEntries(keys.map(key => [key, 0])) as Record<T, number>;
  for (const row of db.query(sql).all() as Array<{ state: T; count: number }>) {
    if (keys.includes(row.state)) result[row.state] = Number(row.count);
  }
  return result;
}

export function databaseAdminSummary(db: Database): DatabaseAdminSummary {
  const quick = db.query("PRAGMA quick_check(1)").get() as { quick_check?: string } | null;
  const quickCheck = String(quick?.quick_check ?? "unknown").slice(0, 256);
  const foreignKeyViolations = db.query("PRAGMA foreign_key_check").all().length;
  const pageCount = integerPragma(db, "page_count", "page_count");
  const pageSizeBytes = integerPragma(db, "page_size", "page_size");
  const schemaVersion = scalarCount(db, "SELECT COALESCE(MAX(version), 0) AS count FROM schema_migrations");
  const devices = groupedCounts(
    db,
    "SELECT status AS state, COUNT(*) AS count FROM devices GROUP BY status",
    ["pending", "approved", "revoked"] as const,
  );
  const tasks = groupedCounts(
    db,
    "SELECT status AS state, COUNT(*) AS count FROM agent_tasks GROUP BY status",
    ["queued", "running", "completed", "failed"] as const,
  );
  return {
    health: quickCheck === "ok" && foreignKeyViolations === 0 ? "ok" : "corrupt",
    quickCheck,
    foreignKeyViolations,
    schemaVersion,
    pageCount,
    pageSizeBytes,
    logicalBytes: pageCount * pageSizeBytes,
    counts: {
      devices,
      projects: scalarCount(db, "SELECT COUNT(*) AS count FROM projects"),
      memberships: scalarCount(db, "SELECT COUNT(*) AS count FROM project_members"),
      agents: scalarCount(db, "SELECT COUNT(*) AS count FROM agents"),
      tasks,
      privateCiphertexts: scalarCount(db, "SELECT COUNT(*) AS count FROM private_messages"),
      projectCiphertextRecords: scalarCount(db, `
        SELECT
          (SELECT COUNT(*) FROM project_key_envelopes)
          + (SELECT COUNT(*) FROM encrypted_project_context)
          + (SELECT COUNT(*) FROM project_chat_events)
          + (SELECT COUNT(*) FROM project_prompt_updates)
          + (SELECT COUNT(*) FROM project_artifacts)
          + (SELECT COUNT(*) FROM project_file_references)
          AS count
      `),
      auditEvents: scalarCount(db, "SELECT COUNT(*) AS count FROM audit_events"),
    },
  };
}

export interface AdminRuntimeStatus {
  startedAt: string;
  authenticatedSockets: number;
  authenticatedDeviceIds: readonly string[];
  agentWorkerSockets: number;
  unauthenticatedSockets: number;
  activePresenceProjects: number;
}

export function buildAdminStatus(
  config: ServerConfig,
  db: Database,
  identityFingerprint: string,
  runtime: AdminRuntimeStatus,
  now = new Date(),
): Record<string, unknown> {
  const certificate = new X509Certificate(readFileSync(config.tlsCertificate));
  const validFrom = new Date(certificate.validFrom);
  const validTo = new Date(certificate.validTo);
  const uniqueDevices = new Set(runtime.authenticatedDeviceIds);
  return {
    service: "cocodex-server",
    protocol: 1,
    status: "running",
    startedAt: runtime.startedAt,
    uptimeSeconds: Math.max(0, Math.floor((now.getTime() - Date.parse(runtime.startedAt)) / 1_000)),
    authority: {
      state: serverAuthorityStatus(db),
      epoch: serverEpoch(db),
      identityFingerprint,
    },
    endpoint: {
      bindHostname: config.hostname,
      listeningPort: config.port,
      publicHost: config.publicHost,
      publicPort: config.port,
      transport: "TLS/WSS",
    },
    tls: {
      certificateFingerprint: tlsCertificateFingerprint(config.tlsCertificate),
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      validNow: validFrom.getTime() <= now.getTime() && now.getTime() < validTo.getTime(),
      daysRemaining: Math.floor((validTo.getTime() - now.getTime()) / 86_400_000),
    },
    connections: {
      authenticatedSockets: runtime.authenticatedSockets,
      uniqueDevices: uniqueDevices.size,
      agentWorkerSockets: runtime.agentWorkerSockets,
      unauthenticatedSockets: runtime.unauthenticatedSockets,
    },
    activePresenceProjects: runtime.activePresenceProjects,
    database: databaseAdminSummary(db),
  };
}
