import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import type { ClientPaths } from "./paths";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

export interface ClientIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
  messagingPublicKeyPem: string;
  messagingPrivateKeyPem: string;
}

export function loadOrCreateClientIdentity(paths: ClientPaths): ClientIdentity {
  const privateExists = existsSync(paths.identityPrivateKey);
  const publicExists = existsSync(paths.identityPublicKey);
  const messagingPrivateExists = existsSync(paths.messagingPrivateKey);
  const messagingPublicExists = existsSync(paths.messagingPublicKey);
  if (privateExists !== publicExists || messagingPrivateExists !== messagingPublicExists) {
    throw new Error("CoCodex device identity is incomplete");
  }
  if (privateExists && messagingPrivateExists) {
    hardenSecretDir(paths.root, { required: true });
    hardenSecretPath(paths.identityPrivateKey, { required: true });
    return {
      privateKeyPem: readFileSync(paths.identityPrivateKey, "utf8"),
      publicKeyPem: readFileSync(paths.identityPublicKey, "utf8"),
      messagingPrivateKeyPem: readFileSync(paths.messagingPrivateKey, "utf8"),
      messagingPublicKeyPem: readFileSync(paths.messagingPublicKey, "utf8"),
    };
  }
  if (privateExists) {
    hardenSecretDir(paths.root, { required: true });
    hardenSecretPath(paths.identityPrivateKey, { required: true });
    const messagingPair = generateKeyPairSync("x25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    writeFileSync(paths.messagingPrivateKey, messagingPair.privateKey, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    hardenSecretPath(paths.messagingPrivateKey, { required: true });
    writeFileSync(paths.messagingPublicKey, messagingPair.publicKey, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o644,
    });
    return {
      privateKeyPem: readFileSync(paths.identityPrivateKey, "utf8"),
      publicKeyPem: readFileSync(paths.identityPublicKey, "utf8"),
      messagingPrivateKeyPem: messagingPair.privateKey,
      messagingPublicKeyPem: messagingPair.publicKey,
    };
  }
  mkdirSync(paths.root, { recursive: true });
  hardenSecretDir(paths.root, { required: true });
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messagingPair = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  hardenSecretPath(paths.identityPrivateKey, { required: true });
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
  writeFileSync(paths.messagingPrivateKey, messagingPair.privateKey, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  hardenSecretPath(paths.messagingPrivateKey, { required: true });
  writeFileSync(paths.messagingPublicKey, messagingPair.publicKey, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o644,
  });
  return {
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
    messagingPrivateKeyPem: messagingPair.privateKey,
    messagingPublicKeyPem: messagingPair.publicKey,
  };
}
