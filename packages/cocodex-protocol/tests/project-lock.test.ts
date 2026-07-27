import { describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import {
  clientFrameSchema,
  projectLockChangedFrameSchema,
  projectLockSigningTranscript,
  projectLockUpdateFrameSchema,
  projectServerFrameSchema,
} from "../src";

function updateFrame() {
  return {
    version: 1 as const,
    type: "project.lock.update" as const,
    requestId: crypto.randomUUID(),
    operationId: crypto.randomUUID(),
    projectId: crypto.randomUUID(),
    action: "lock" as const,
    expectedRevision: 0,
    reason: "Security review",
    serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
    serverEpoch: 1,
    issuedAt: "2027-01-01T00:00:00.000Z",
    expiresAt: "2027-01-01T00:02:00.000Z",
    nonce: randomBytes(32).toString("base64url"),
    signature: randomBytes(64).toString("base64url"),
  };
}

describe("project-lock protocol", () => {
  test("strictly validates signed transitions and exposes bounded lock state", () => {
    const frame = updateFrame();
    expect(projectLockUpdateFrameSchema.parse(frame)).toEqual(frame);
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => projectLockUpdateFrameSchema.parse({ ...frame, extra: true })).toThrow();
    expect(() => projectLockUpdateFrameSchema.parse({ ...frame, nonce: "!".repeat(43) })).toThrow();
    expect(() => projectLockUpdateFrameSchema.parse({ ...frame, signature: "A".repeat(85) })).toThrow();
    const nonCanonicalLastCharacter = new Map([
      ["A", "B"],
      ["Q", "R"],
      ["g", "h"],
      ["w", "x"],
    ]).get(frame.signature.at(-1)!);
    expect(nonCanonicalLastCharacter).toBeDefined();
    expect(() => projectLockUpdateFrameSchema.parse({
      ...frame,
      signature: `${frame.signature.slice(0, -1)}${nonCanonicalLastCharacter}`,
    })).toThrow("canonically");

    const changed = {
      version: 1 as const,
      type: "project.lock.changed" as const,
      transition: {
        operationId: frame.operationId,
        projectId: frame.projectId,
        action: frame.action,
        actorDeviceId: crypto.randomUUID(),
        reason: frame.reason,
        state: {
          state: "locked" as const,
          revision: 1,
          lockedAt: "2027-01-01T00:00:01.000Z",
          lockedByDeviceId: crypto.randomUUID(),
          reason: frame.reason,
        },
        createdAt: "2027-01-01T00:00:01.000Z",
      },
      cancelledTaskCount: 0,
      cancelledTasks: [],
    };
    expect(projectLockChangedFrameSchema.parse(changed)).toEqual(changed);
    expect(projectServerFrameSchema.parse(changed)).toEqual(changed);
    expect(() => projectLockChangedFrameSchema.parse({
      ...changed,
      transition: {
        ...changed.transition,
        state: { ...changed.transition.state, reason: null },
      },
    })).toThrow();
  });

  test("binds every authority and transition field in the signing transcript", () => {
    const { type: _type, requestId: _requestId, signature: _signature, ...unsigned } = updateFrame();
    const baseline = projectLockSigningTranscript(unsigned);
    const mutations = [
      { ...unsigned, operationId: crypto.randomUUID() },
      { ...unsigned, projectId: crypto.randomUUID() },
      { ...unsigned, action: "unlock" as const },
      { ...unsigned, expectedRevision: 1 },
      { ...unsigned, reason: "Another reason" },
      { ...unsigned, serverFingerprint: "FFFF-EEEE-DDDD-CCCC" },
      { ...unsigned, serverEpoch: 2 },
      { ...unsigned, issuedAt: "2027-01-01T00:00:01.000Z" },
      { ...unsigned, expiresAt: "2027-01-01T00:03:00.000Z" },
      { ...unsigned, nonce: randomBytes(32).toString("base64url") },
    ];
    for (const mutation of mutations) {
      expect(projectLockSigningTranscript(mutation)).not.toEqual(baseline);
    }
  });
});
