import { createHash, createPublicKey } from "node:crypto";

export function canonicalEd25519PublicKey(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("Device identity must be an Ed25519 public key");
  }
  return key.export({ type: "spki", format: "pem" }).toString();
}

export function publicKeyFingerprint(publicKeyPem: string): string {
  const der = createPublicKey(canonicalEd25519PublicKey(publicKeyPem)).export({
    type: "spki",
    format: "der",
  });
  const hex = createHash("sha256").update(der).digest("hex").toUpperCase();
  return hex.match(/.{1,4}/g)?.join("-") ?? hex;
}
