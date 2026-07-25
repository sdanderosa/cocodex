import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import {
  canonicalEd25519PublicKey,
  clientFrameSchema,
  decodeInvitation,
  encodeInvitation,
  enrollmentSigningTranscript,
  publicKeyFingerprint,
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
