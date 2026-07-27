import { randomBytes, randomUUID, sign } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  deviceApprovalSigningTranscript,
  type DeviceApprovalUpdateFrame,
} from "@cocodex/protocol";
import {
  listPendingDeviceApprovals,
  updateDeviceApproval,
} from "../src/device-approvals";
import { bootstrapApproveDevice } from "../src/enrollment";
import {
  serverEpoch,
  serverIdentityFingerprint,
} from "../src/server-state";

export const TEST_SERVER_IDENTITY_FINGERPRINT =
  "1111-1111-1111-1111-1111-1111-1111-1111-1111-1111-1111-1111-1111-1111-1111-1111";

interface TestApprovalAuthority {
  deviceId: string;
  privateKeyPem: string;
}

const authorities = new WeakMap<Database, TestApprovalAuthority>();

export function testServerIdentityFingerprint(db: Database): string {
  return serverIdentityFingerprint(db) ?? TEST_SERVER_IDENTITY_FINGERPRINT;
}

/**
 * Test-only enrollment ceremony. Production code has no approval bypass: the
 * first device uses the one-shot bootstrap and every later device is approved
 * through the same signed operation service used by WSS.
 */
export function approvePendingDeviceForTest(
  db: Database,
  target: { id: string; fingerprint: string },
  targetPrivateKeyPem: string,
  serverTlsFingerprint: string,
  now = new Date(),
  identityFingerprint = testServerIdentityFingerprint(db),
): void {
  let authority = authorities.get(db);
  if (!authority) {
    if (!bootstrapApproveDevice(db, target.fingerprint, now)) {
      throw new Error("Test bootstrap approval failed");
    }
    authority = { deviceId: target.id, privateKeyPem: targetPrivateKeyPem };
    authorities.set(db, authority);
    return;
  }
  const pending = listPendingDeviceApprovals(
    db,
    authority.deviceId,
    serverTlsFingerprint,
    identityFingerprint,
    now,
  ).find(device => device.deviceId === target.id);
  if (!pending) throw new Error("Test pending device approval was not found");
  const issuedAt = now.toISOString();
  const unsigned = {
    version: 1 as const,
    operationId: randomUUID(),
    targetDeviceId: pending.deviceId,
    targetFingerprint: pending.fingerprint,
    targetEnrollmentDigest: pending.enrollmentDigest,
    expectedRevision: 0 as const,
    decision: "approve" as const,
    serverIdentityFingerprint: identityFingerprint,
    serverEpoch: serverEpoch(db),
    issuedAt,
    expiresAt: new Date(now.getTime() + 120_000).toISOString(),
    nonce: randomBytes(32).toString("base64url"),
  };
  const frame: DeviceApprovalUpdateFrame = {
    ...unsigned,
    type: "device.approval.update",
    requestId: randomUUID(),
    signature: sign(
      null,
      deviceApprovalSigningTranscript(unsigned),
      authority.privateKeyPem,
    ).toString("base64url"),
  };
  const result = updateDeviceApproval(
    db,
    authority.deviceId,
    frame,
    serverTlsFingerprint,
    identityFingerprint,
    serverEpoch(db),
    now,
  );
  if (!result.created || result.status !== "approved") {
    throw new Error("Test signed approval did not create an approved device");
  }
}
