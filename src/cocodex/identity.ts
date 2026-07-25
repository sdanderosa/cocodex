import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import type { ClientPaths } from "./paths";

export interface ClientIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
}

export function loadOrCreateClientIdentity(paths: ClientPaths): ClientIdentity {
  const privateExists = existsSync(paths.identityPrivateKey);
  const publicExists = existsSync(paths.identityPublicKey);
  if (privateExists !== publicExists) throw new Error("CoCodex device identity is incomplete");
  if (privateExists) {
    return {
      privateKeyPem: readFileSync(paths.identityPrivateKey, "utf8"),
      publicKeyPem: readFileSync(paths.identityPublicKey, "utf8"),
    };
  }
  mkdirSync(paths.root, { recursive: true });
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  writeFileSync(paths.identityPrivateKey, pair.privateKey, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  if (process.platform !== "win32") chmodSync(paths.identityPrivateKey, 0o600);
  writeFileSync(paths.identityPublicKey, pair.publicKey, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o644,
  });
  return { privateKeyPem: pair.privateKey, publicKeyPem: pair.publicKey };
}
