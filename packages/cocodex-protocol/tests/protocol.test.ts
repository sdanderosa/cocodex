import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import {
  canonicalEd25519PublicKey,
  clientFrameSchema,
  decodeInvitation,
  encodeInvitation,
  enrollmentSigningTranscript,
  PROJECT_CONTEXT_MAX_BYTES,
  projectContextResultFrameSchema,
  projectKeyEnvelopeSchema,
  projectServerFrameSchema,
  publicKeyFingerprint,
  usageReportSchema,
  usageReportSigningTranscript,
  websocketAuthTranscript,
} from "../src";

describe("CoCodex protocol", () => {
  test("round-trips a strict versioned invitation", () => {
    const payload = {
      version: 1 as const,
      host: "example.test",
      port: 10443,
      serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
      invitationId: "e70b1cb4-1d63-4dfe-8e07-454738f75725",
      token: "A".repeat(43),
      expiresAt: "2030-01-01T00:00:00.000Z",
      scope: "device-enrollment" as const,
    };
    expect(decodeInvitation(encodeInvitation(payload))).toEqual(payload);
    expect(() => decodeInvitation("ccx1.not-json")).toThrow();
  });

  test("canonicalizes Ed25519 keys and derives stable fingerprints", () => {
    const pair = generateKeyPairSync("ed25519");
    const pem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(canonicalEd25519PublicKey(pem)).toBe(pem);
    expect(publicKeyFingerprint(pem)).toBe(publicKeyFingerprint(pem));

    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPem = rsa.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => canonicalEd25519PublicKey(rsaPem)).toThrow("Ed25519");
  });

  test("signing transcript is length-prefixed and binds every field", () => {
    const input = {
      serverFingerprint: "server",
      invitationId: "invite",
      challengeId: "challenge-id",
      challenge: "nonce",
      displayName: "Kai",
      devicePublicKeyPem: "key",
      messagingPublicKeyPem: "messaging-key",
    };
    const baseline = enrollmentSigningTranscript(input);
    expect(baseline.subarray(0, 19).toString()).toBe("COCODEX-ENROLLMENT\u0000");
    expect(enrollmentSigningTranscript({ ...input, challenge: "other" })).not.toEqual(baseline);
    expect(enrollmentSigningTranscript({ ...input, invitationId: "other" })).not.toEqual(baseline);
    expect(enrollmentSigningTranscript({ ...input, displayName: "Stephen" })).not.toEqual(baseline);
  });

  test("accepts bounded Yjs prompt frames and rejects extra fields", () => {
    const frame = {
      version: 1 as const,
      type: "prompt.update" as const,
      requestId: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      updateId: crypto.randomUUID(),
      update: "AQID",
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => clientFrameSchema.parse({ ...frame, targetDeviceId: crypto.randomUUID() })).toThrow();
  });
  test("accepts revisioned project-context updates and rejects invalid revisions", () => {
    const frame = {
      version: 1 as const,
      type: "context.update" as const,
      requestId: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      expectedRevision: 0,
      finalGoal: "Build the private alpha",
      context: { owner: "Stephen", phase: "alpha" },
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => clientFrameSchema.parse({ ...frame, expectedRevision: -1 })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, finalGoal: "x".repeat(32_769) })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, context: [] })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, context: { blob: "x".repeat(PROJECT_CONTEXT_MAX_BYTES) } })).toThrow();
  });
  test("strictly bounds opaque project-encryption frames in both directions", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const projectId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const keyEnvelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recipientDeviceId,
      senderDeviceId,
      sealedProjectKey: Buffer.alloc(80, 1).toString("base64url"),
      senderPublicKeyPem: signing.publicKey,
      signature: Buffer.alloc(64, 2).toString("base64url"),
    };
    const contentEnvelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recordType: "shared-context" as const,
      recordId: crypto.randomUUID(),
      nonce: Buffer.alloc(24, 3).toString("base64url"),
      ciphertext: Buffer.alloc(16, 4).toString("base64url"),
      senderDeviceId,
      senderPublicKeyPem: signing.publicKey,
      signature: Buffer.alloc(64, 5).toString("base64url"),
    };
    expect(projectKeyEnvelopeSchema.parse(keyEnvelope)).toEqual(keyEnvelope);
    const keyShare = {
      version: 1 as const,
      type: "project.key.share" as const,
      requestId: crypto.randomUUID(),
      projectId,
      envelope: keyEnvelope,
    };
    const contextUpdate = {
      version: 1 as const,
      type: "project.context.update" as const,
      requestId: crypto.randomUUID(),
      projectId,
      expectedRevision: 0,
      envelope: contentEnvelope,
    };
    expect(clientFrameSchema.parse(keyShare)).toEqual(keyShare);
    expect(clientFrameSchema.parse(contextUpdate)).toEqual(contextUpdate);
    expect(() => clientFrameSchema.parse({ ...keyShare, envelope: { ...keyEnvelope, extra: true } })).toThrow();
    expect(() => clientFrameSchema.parse({ ...contextUpdate, envelope: { ...contentEnvelope, ciphertext: "%%%" } })).toThrow();

    const result = {
      version: 1 as const,
      type: "project.context.result" as const,
      requestId: crypto.randomUUID(),
      projectId,
      envelope: contentEnvelope,
      revision: 1,
      updatedAt: "2030-01-01T00:00:00.000Z",
    };
    expect(projectContextResultFrameSchema.parse(result)).toEqual(result);
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.key.changed" as const,
      projectId,
      envelope: keyEnvelope,
    })).toMatchObject({ type: "project.key.changed", projectId });
    expect(() => projectServerFrameSchema.parse({ ...result, extra: true })).toThrow();
  });
  test("bounds presence cursor and caret frames", () => {
    const frame = {
      version: 1 as const,
      type: "presence.update" as const,
      requestId: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      cursor: { x: 0.25, y: 0.75 },
      caret: { anchor: 3, head: 8 },
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => clientFrameSchema.parse({ ...frame, cursor: { x: 2, y: 0 } })).toThrow();
  });
  test("requires a bounded reason for agent cancellation", () => {
    const frame = {
      version: 1 as const,
      type: "agent.cancel" as const,
      requestId: crypto.randomUUID(),
      taskId: crypto.randomUUID(),
      reason: "Stop this run",
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => clientFrameSchema.parse({ ...frame, reason: " " })).toThrow();
  });
  test("bounds signed sanitized usage reports and binds all fields", () => {
    const report = usageReportSchema.parse({
      version: 1,
      deviceId: crypto.randomUUID(),
      revision: 2,
      updatedAt: "2030-01-01T00:00:00.000Z",
      requests: 4,
      inputTokens: 100,
      cachedInputTokens: 25,
      outputTokens: 50,
      reasoningOutputTokens: 10,
      activeAgents: 1,
      accountLabel: "Stephen Main",
      fiveHourPercent: 68,
      fiveHourResetAt: 1_900_000_000,
      customWindows: [{ label: "daily", percent: 41 }],
    });
    const frame = {
      version: 1 as const,
      type: "usage.report" as const,
      requestId: crypto.randomUUID(),
      report,
      signature: "s".repeat(64),
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(usageReportSigningTranscript(report)).not.toEqual(
      usageReportSigningTranscript({ ...report, outputTokens: report.outputTokens + 1 }),
    );
    expect(() => clientFrameSchema.parse({ ...frame, report: { ...report, activeAgents: 257 } })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, report: { ...report, customWindows: Array.from({ length: 9 }, (_, i) => ({ label: String(i), percent: 1 })) } })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, extra: true })).toThrow();
  });
  test("WebSocket proof binds the server, device, request, and challenge", () => {
    const input = {
      serverFingerprint: "server-a",
      deviceId: "device-a",
      requestId: "request-a",
      challenge: "challenge-a",
    };
    const baseline = websocketAuthTranscript(input);
    for (const changed of [
      { ...input, serverFingerprint: "server-b" },
      { ...input, deviceId: "device-b" },
      { ...input, requestId: "request-b" },
      { ...input, challenge: "challenge-b" },
    ]) {
      expect(websocketAuthTranscript(changed)).not.toEqual(baseline);
    }
  });
});
