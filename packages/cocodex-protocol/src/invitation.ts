import { z } from "zod";

export const invitationSchema = z
  .object({
    version: z.literal(1),
    host: z.string().trim().min(1).max(253),
    port: z.number().int().min(1).max(65535),
    serverFingerprint: z.string().min(16).max(256),
    invitationId: z.uuid(),
    token: z.string().min(43).max(128),
    expiresAt: z.iso.datetime(),
    scope: z.literal("device-enrollment"),
  })
  .strict();

export type InvitationPayload = z.infer<typeof invitationSchema>;

export function encodeInvitation(payload: InvitationPayload): string {
  const verified = invitationSchema.parse(payload);
  return `ccx1.${Buffer.from(JSON.stringify(verified), "utf8").toString("base64url")}`;
}

export function decodeInvitation(value: string): InvitationPayload {
  if (!value.startsWith("ccx1.")) throw new Error("Unsupported CoCodex invitation");
  try {
    return invitationSchema.parse(JSON.parse(Buffer.from(value.slice(5), "base64url").toString("utf8")));
  } catch {
    throw new Error("Malformed or invalid CoCodex invitation");
  }
}
