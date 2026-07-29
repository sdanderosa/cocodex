import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import {
  clientFrameSchema,
  projectMemberLeaveRequestedFrameSchema,
  projectMemberLeaveSigningTranscript,
  projectServerFrameSchema,
} from "../src/index";

function signedLeave() {
  const pair = generateKeyPairSync("ed25519");
  const unsigned = {
    version: 1 as const,
    requestId: randomUUID(),
    projectId: randomUUID(),
    serverFingerprint: "AA:BB:CC:DD:EE:FF",
    serverEpoch: 4,
    issuedAt: "2030-01-01T00:00:00.000Z",
    expiresAt: "2030-01-01T00:02:00.000Z",
    nonce: randomBytes(32).toString("base64url"),
  };
  return {
    frame: {
      ...unsigned,
      type: "project.member.leave" as const,
      signature: sign(null, projectMemberLeaveSigningTranscript(unsigned), pair.privateKey)
        .toString("base64url"),
    },
    unsigned,
  };
}

describe("CoCodex project-member leave protocol", () => {
  test("strictly validates and binds every signed leave field", () => {
    const { frame, unsigned } = signedLeave();
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => clientFrameSchema.parse({ ...frame, deviceId: randomUUID() })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, nonce: "short" })).toThrow();
    const transcript = projectMemberLeaveSigningTranscript(unsigned);
    expect(transcript.equals(projectMemberLeaveSigningTranscript(unsigned))).toBeTrue();
    expect(transcript.equals(projectMemberLeaveSigningTranscript({
      ...unsigned,
      projectId: randomUUID(),
    }))).toBeFalse();
    expect(transcript.equals(projectMemberLeaveSigningTranscript({
      ...unsigned,
      serverEpoch: unsigned.serverEpoch + 1,
    }))).toBeFalse();
  });

  test("accepts only strict Server-derived leave acknowledgements", () => {
    const { frame } = signedLeave();
    const ack = {
      version: 1 as const,
      type: "project.member.leave-requested" as const,
      requestId: frame.requestId,
      projectId: frame.projectId,
      deviceId: randomUUID(),
      requestedAt: "2030-01-01T00:00:01.000Z",
      created: true,
    };
    expect(projectMemberLeaveRequestedFrameSchema.parse(ack)).toEqual(ack);
    expect(projectServerFrameSchema.parse(ack)).toEqual(ack);
    expect(() => projectServerFrameSchema.parse({ ...ack, envelopes: [] })).toThrow();
  });
});
