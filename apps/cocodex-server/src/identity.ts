import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { publicKeyFingerprint } from "../../../packages/cocodex-protocol/src/index.ts";
import { hardenSecretDir } from "../../../src/lib/windows-secret-acl";
import { readProtectedSecret, writeProtectedSecret } from "../../../src/lib/local-protected-secret";
import type { ServerPaths } from "./paths";

export interface ServerIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
}

const SERVER_IDENTITY_PURPOSE = "cocodex.server.identity-signing-key";

export function writeServerIdentityPrivateKey(path: string, value: string): void {
  mkdirSync(dirname(path), { recursive: true });
  hardenSecretDir(dirname(path), { required: true });
  writeProtectedSecret(path, SERVER_IDENTITY_PURPOSE, value);
}

export function readServerIdentityPrivateKey(path: string): string {
  return readProtectedSecret(path, SERVER_IDENTITY_PURPOSE).toString("utf8");
}

export function createServerIdentity(paths: ServerPaths): ServerIdentity {
  if (existsSync(paths.identityPrivateKey) || existsSync(paths.identityPublicKey)) {
    throw new Error("Server identity already exists");
  }
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  writeServerIdentityPrivateKey(paths.identityPrivateKey, pair.privateKey);
  mkdirSync(dirname(paths.identityPublicKey), { recursive: true });
  writeFileSync(paths.identityPublicKey, pair.publicKey, {
    encoding: "utf8",
    mode: 0o644,
    flag: "wx",
  });
  return {
    publicKeyPem: pair.publicKey,
    privateKeyPem: pair.privateKey,
    fingerprint: publicKeyFingerprint(pair.publicKey),
  };
}

export function loadServerIdentity(paths: ServerPaths): ServerIdentity {
  hardenSecretDir(paths.root, { required: true });
  const publicKeyPem = readFileSync(paths.identityPublicKey, "utf8");
  const privateKeyPem = readServerIdentityPrivateKey(paths.identityPrivateKey);
  let derivedPublic: Buffer;
  let expectedPublic: Buffer;
  try {
    derivedPublic = createPublicKey(privateKeyPem).export({ format: "der", type: "spki" });
    expectedPublic = createPublicKey(publicKeyPem).export({ format: "der", type: "spki" });
  } catch {
    throw new Error("CoCodex Server identity key is invalid");
  }
  if (!derivedPublic.equals(expectedPublic)) {
    throw new Error("CoCodex Server identity keypair does not match");
  }
  return {
    publicKeyPem,
    privateKeyPem,
    fingerprint: publicKeyFingerprint(publicKeyPem),
  };
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}
