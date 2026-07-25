import { z } from "zod";

export const enrollmentClaimSchema = z
  .object({
    version: z.literal(1),
    invitationCode: z.string().startsWith("ccx1.").max(4096),
    challengeId: z.uuid(),
    challenge: z.string().min(43).max(128),
    displayName: z.string().trim().min(1).max(80),
    devicePublicKeyPem: z.string().min(64).max(2048),
    signature: z.string().min(64).max(256),
  })
  .strict();

export type EnrollmentClaim = z.infer<typeof enrollmentClaimSchema>;

interface EnrollmentTranscriptInput {
  serverFingerprint: string;
  invitationId: string;
  challengeId: string;
  challenge: string;
  displayName: string;
  devicePublicKeyPem: string;
}

function lengthPrefix(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

export function enrollmentSigningTranscript(input: EnrollmentTranscriptInput): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-ENROLLMENT\u0000", "utf8"),
    lengthPrefix("1"),
    lengthPrefix(input.serverFingerprint),
    lengthPrefix(input.invitationId),
    lengthPrefix(input.challengeId),
    lengthPrefix(input.challenge),
    lengthPrefix(input.displayName.trim()),
    lengthPrefix(input.devicePublicKeyPem),
  ]);
}
