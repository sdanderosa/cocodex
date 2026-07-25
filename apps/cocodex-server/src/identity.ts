import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { publicKeyFingerprint } from "@cocodex/protocol";
import { hardenSecretDir, hardenSecretPath } from "../../../src/lib/windows-secret-acl";
import type { ServerPaths } from "./paths";

export interface ServerIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
}

function writeSecret(path: string, value: string): void {
  mkdirSync(dirname(path), { recursive: true });
  hardenSecretDir(dirname(path), { required: true });
  writeFileSync(path, value, { encoding: "utf8", mode: 0o600, flag: "wx" });
  hardenSecretPath(path, { required: true });
  if (process.platform !== "win32") chmodSync(path, 0o600);
}

export function createServerIdentity(paths: ServerPaths): ServerIdentity {
  if (existsSync(paths.identityPrivateKey) || existsSync(paths.identityPublicKey)) {
    throw new Error("Server identity already exists");
  }
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  writeSecret(paths.identityPrivateKey, pair.privateKey);
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
  hardenSecretPath(paths.identityPrivateKey, { required: true });
  const publicKeyPem = readFileSync(paths.identityPublicKey, "utf8");
  const privateKeyPem = readFileSync(paths.identityPrivateKey, "utf8");
  return {
    publicKeyPem,
    privateKeyPem,
    fingerprint: publicKeyFingerprint(publicKeyPem),
  };
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}
