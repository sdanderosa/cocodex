import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  usageReportSchema,
  usageReportSigningTranscript,
  type UsageReport,
  type UsageReportView,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { requireProjectMembership } from "./shared-state";

interface DeviceRow {
  id: string;
  publicKeyPem: string;
  displayName: string;
  status: "pending" | "approved" | "revoked";
}

interface UsageRow {
  deviceId: string;
  displayName: string;
  reportJson: string | null;
  reportSignature: string | null;
  revision: number | null;
  acceptedAt: string | null;
}

function approvedDevice(db: Database, deviceId: string): DeviceRow {
  const row = db.query(`
    SELECT id, public_key_pem AS publicKeyPem, display_name AS displayName, status
    FROM devices WHERE id = ?
  `).get(deviceId) as DeviceRow | null;
  if (!row || row.status !== "approved") throw new Error("Usage reporting device is not approved");
  return row;
}

function viewFromRow(row: UsageRow): UsageReportView {
  if (!row.reportJson) return {
    deviceId: row.deviceId,
    displayName: row.displayName,
    report: null,
    acceptedAt: null,
  };
  const report = usageReportSchema.parse(JSON.parse(row.reportJson));
  if (report.deviceId !== row.deviceId || report.revision !== row.revision) {
    throw new Error("Stored usage report identity is invalid");
  }
  return {
    deviceId: row.deviceId,
    displayName: row.displayName,
    report,
    acceptedAt: row.acceptedAt,
  };
}

export function listUsageReports(db: Database, projectId: string, deviceId: string): UsageReportView[] {
  requireProjectMembership(db, projectId, deviceId);
  const rows = db.query(`
    SELECT d.id AS deviceId, d.display_name AS displayName,
      u.report_json AS reportJson, u.report_signature AS reportSignature,
      u.revision, u.accepted_at AS acceptedAt
    FROM project_members pm
    JOIN devices d ON d.id = pm.device_id AND d.status = 'approved'
    LEFT JOIN usage_reports u ON u.device_id = d.id
    WHERE pm.project_id = ?
    ORDER BY CASE pm.role WHEN 'owner' THEN 0 ELSE 1 END, d.display_name ASC, d.id ASC
  `).all(projectId) as UsageRow[];
  return rows.map(viewFromRow);
}

export function usageReportProjectIds(db: Database, deviceId: string): string[] {
  approvedDevice(db, deviceId);
  return (db.query(`
    SELECT pm.project_id AS projectId
    FROM project_members pm
    JOIN projects p ON p.id = pm.project_id
    WHERE pm.device_id = ?
  `).all(deviceId) as { projectId: string }[]).map(row => row.projectId);
}

export interface AcceptUsageReportResult {
  view: UsageReportView;
  created: boolean;
}

export function acceptUsageReport(
  db: Database,
  actorDeviceId: string,
  input: { report: UsageReport; signature: string },
  now = new Date(),
): AcceptUsageReportResult {
  const device = approvedDevice(db, actorDeviceId);
  const report = usageReportSchema.parse(input.report);
  if (report.deviceId !== actorDeviceId) throw new Error("Usage report device does not match authenticated device");
  const updatedMs = Date.parse(report.updatedAt);
  const nowMs = now.getTime();
  if (!Number.isFinite(updatedMs) || updatedMs > nowMs + 10 * 60_000) {
    throw new Error("Usage report timestamp is invalid or too far in the future");
  }
  const publicKey = createPublicKey(device.publicKeyPem);
  if (publicKey.asymmetricKeyType !== "ed25519"
    || !verify(null, usageReportSigningTranscript(report), publicKey, Buffer.from(input.signature, "base64url"))) {
    throw new Error("Usage report signature is invalid");
  }
  const existing = db.query(`
    SELECT report_json AS reportJson, report_signature AS reportSignature,
      revision, accepted_at AS acceptedAt
    FROM usage_reports WHERE device_id = ?
  `).get(actorDeviceId) as {
    reportJson: string; reportSignature: string; revision: number; acceptedAt: string;
  } | null;
  if (existing) {
    const previous = usageReportSchema.parse(JSON.parse(existing.reportJson));
    if (report.revision < previous.revision || (report.revision === previous.revision
      && (JSON.stringify(report) !== JSON.stringify(previous) || input.signature !== existing.reportSignature))) {
      throw new Error("Usage report revision is stale or was reused with different content");
    }
    if (report.revision === previous.revision) {
      return {
        view: { deviceId: actorDeviceId, displayName: device.displayName, report: previous, acceptedAt: existing.acceptedAt },
        created: false,
      };
    }
    if (updatedMs <= Date.parse(previous.updatedAt)) throw new Error("Usage report timestamp is stale");
  }
  const acceptedAt = now.toISOString();
  db.query(`
    INSERT INTO usage_reports (device_id, report_json, report_signature, revision, updated_at, accepted_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(device_id) DO UPDATE SET report_json = excluded.report_json,
      report_signature = excluded.report_signature, revision = excluded.revision,
      updated_at = excluded.updated_at, accepted_at = excluded.accepted_at
  `).run(actorDeviceId, JSON.stringify(report), input.signature, report.revision, report.updatedAt, acceptedAt);
  return {
    view: { deviceId: actorDeviceId, displayName: device.displayName, report, acceptedAt },
    created: true,
  };
}
