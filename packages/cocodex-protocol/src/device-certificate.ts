import { createPublicKey, sign, verify } from "node:crypto";
import { z } from "zod";
import { publicKeyFingerprint } from "./keys";

export const deviceKeyCertificateSchema = z.object({
  version: z.literal(1),
  deviceId: z.uuid(),
  devicePublicKeyPem: z.string().min(64).max(2048),
  messagingPublicKeyPem: z.string().min(64).max(2048),
  projectWrapPublicKeyPem: z.string().min(64).max(2048).optional(),
  signature: z.string().min(64).max(256),
}).strict();

export type DeviceKeyCertificate = z.infer<typeof deviceKeyCertificateSchema>;

function lengthPrefix(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

export function deviceKeyCertificateSigningTranscript(
  input: Omit<DeviceKeyCertificate, "version" | "signature">,
): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-DEVICE-KEY-CERTIFICATE\u0000", "utf8"),
    lengthPrefix("1"),
    lengthPrefix(input.deviceId),
    lengthPrefix(input.devicePublicKeyPem),
    lengthPrefix(input.messagingPublicKeyPem),
    lengthPrefix(input.projectWrapPublicKeyPem ?? ""),
  ]);
}

export function createDeviceKeyCertificate(
  deviceId: string,
  identity: {
    publicKeyPem: string;
    privateKeyPem: string;
    messagingPublicKeyPem: string;
    projectWrapPublicKeyPem?: string;
  },
): string {
  const unsigned = {
    deviceId,
    devicePublicKeyPem: identity.publicKeyPem,
    messagingPublicKeyPem: identity.messagingPublicKeyPem,
    ...(identity.projectWrapPublicKeyPem
      ? { projectWrapPublicKeyPem: identity.projectWrapPublicKeyPem }
      : {}),
  };
  return JSON.stringify(deviceKeyCertificateSchema.parse({
    version: 1,
    ...unsigned,
    signature: sign(
      null,
      deviceKeyCertificateSigningTranscript(unsigned),
      identity.privateKeyPem,
    ).toString("base64url"),
  }));
}

export function verifyDeviceKeyCertificate(value: string, expectedDeviceId: string): {
  fingerprint: string;
  devicePublicKeyPem: string;
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem?: string;
} {
  let certificate: DeviceKeyCertificate;
  try {
    certificate = deviceKeyCertificateSchema.parse(JSON.parse(value));
  } catch {
    throw new Error("Recipient device key certificate is invalid");
  }
  if (certificate.deviceId !== expectedDeviceId) {
    throw new Error("Recipient device key certificate is invalid");
  }
  const signingKey = createPublicKey(certificate.devicePublicKeyPem);
  if (signingKey.asymmetricKeyType !== "ed25519"
    || createPublicKey(certificate.messagingPublicKeyPem).asymmetricKeyType !== "x25519"
    || (certificate.projectWrapPublicKeyPem
      && createPublicKey(certificate.projectWrapPublicKeyPem).asymmetricKeyType !== "x25519")) {
    throw new Error("Recipient device key certificate has an invalid key");
  }
  const { version: _version, signature, ...unsigned } = certificate;
  if (!verify(
    null,
    deviceKeyCertificateSigningTranscript(unsigned),
    signingKey,
    Buffer.from(signature, "base64url"),
  )) {
    throw new Error("Recipient device key certificate signature is invalid");
  }
  return {
    fingerprint: publicKeyFingerprint(certificate.devicePublicKeyPem),
    devicePublicKeyPem: certificate.devicePublicKeyPem,
    messagingPublicKeyPem: certificate.messagingPublicKeyPem,
    ...(certificate.projectWrapPublicKeyPem
      ? { projectWrapPublicKeyPem: certificate.projectWrapPublicKeyPem }
      : {}),
  };
}
