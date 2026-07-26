import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  createDeviceKeyCertificate as createProtocolDeviceKeyCertificate,
  verifyDeviceKeyCertificate as verifyProtocolDeviceKeyCertificate,
  type DeviceKeyCertificate,
} from "../../packages/cocodex-protocol/src/index.ts";
import type { ClientPaths } from "./paths";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

export type { DeviceKeyCertificate };

export interface ClientIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
  messagingPublicKeyPem: string;
  messagingPrivateKeyPem: string;
  projectWrapPublicKeyPem?: string;
  projectWrapPrivateKeyPem?: string;
}

export function createDeviceKeyCertificate(deviceId: string, identity: ClientIdentity): string {
  return createProtocolDeviceKeyCertificate(deviceId, identity);
}

export function verifyDeviceKeyCertificate(value: string, expectedDeviceId: string): {
  fingerprint: string;
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem?: string;
} {
  const { devicePublicKeyPem: _devicePublicKeyPem, ...verified } =
    verifyProtocolDeviceKeyCertificate(value, expectedDeviceId);
  return verified;
}

export function loadOrCreateClientIdentity(paths: ClientPaths): ClientIdentity {
  const privateExists = existsSync(paths.identityPrivateKey);
  const publicExists = existsSync(paths.identityPublicKey);
  const messagingPrivateExists = existsSync(paths.messagingPrivateKey);
  const messagingPublicExists = existsSync(paths.messagingPublicKey);
  const projectWrapPrivateExists = existsSync(paths.projectWrapPrivateKey);
  const projectWrapPublicExists = existsSync(paths.projectWrapPublicKey);
  if (privateExists !== publicExists || messagingPrivateExists !== messagingPublicExists
    || projectWrapPrivateExists !== projectWrapPublicExists) {
    throw new Error("CoCodex device identity is incomplete");
  }
  if (privateExists && messagingPrivateExists) {
    hardenSecretDir(paths.root, { required: true });
    hardenSecretPath(paths.identityPrivateKey, { required: true });
    let projectWrapPrivateKeyPem: string;
    let projectWrapPublicKeyPem: string;
    if (projectWrapPrivateExists) {
      hardenSecretPath(paths.projectWrapPrivateKey, { required: true });
      projectWrapPrivateKeyPem = readFileSync(paths.projectWrapPrivateKey, "utf8");
      projectWrapPublicKeyPem = readFileSync(paths.projectWrapPublicKey, "utf8");
    } else {
      const projectWrap = generateKeyPairSync("x25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      writeFileSync(paths.projectWrapPrivateKey, projectWrap.privateKey, {
        encoding: "utf8", flag: "wx", mode: 0o600,
      });
      hardenSecretPath(paths.projectWrapPrivateKey, { required: true });
      writeFileSync(paths.projectWrapPublicKey, projectWrap.publicKey, {
        encoding: "utf8", flag: "wx", mode: 0o644,
      });
      projectWrapPrivateKeyPem = projectWrap.privateKey;
      projectWrapPublicKeyPem = projectWrap.publicKey;
    }
    return {
      privateKeyPem: readFileSync(paths.identityPrivateKey, "utf8"),
      publicKeyPem: readFileSync(paths.identityPublicKey, "utf8"),
      messagingPrivateKeyPem: readFileSync(paths.messagingPrivateKey, "utf8"),
      messagingPublicKeyPem: readFileSync(paths.messagingPublicKey, "utf8"),
      projectWrapPrivateKeyPem,
      projectWrapPublicKeyPem,
    };
  }
  if (privateExists) {
    hardenSecretDir(paths.root, { required: true });
    hardenSecretPath(paths.identityPrivateKey, { required: true });
    const messagingPair = generateKeyPairSync("x25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const projectWrapPair = generateKeyPairSync("x25519", {
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
    writeFileSync(paths.projectWrapPrivateKey, projectWrapPair.privateKey, {
      encoding: "utf8", flag: "wx", mode: 0o600,
    });
    hardenSecretPath(paths.projectWrapPrivateKey, { required: true });
    writeFileSync(paths.projectWrapPublicKey, projectWrapPair.publicKey, {
      encoding: "utf8", flag: "wx", mode: 0o644,
    });
    return {
      privateKeyPem: readFileSync(paths.identityPrivateKey, "utf8"),
      publicKeyPem: readFileSync(paths.identityPublicKey, "utf8"),
      messagingPrivateKeyPem: messagingPair.privateKey,
      messagingPublicKeyPem: messagingPair.publicKey,
      projectWrapPrivateKeyPem: projectWrapPair.privateKey,
      projectWrapPublicKeyPem: projectWrapPair.publicKey,
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
  const projectWrapPair = generateKeyPairSync("x25519", {
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
  writeFileSync(paths.projectWrapPrivateKey, projectWrapPair.privateKey, {
    encoding: "utf8", flag: "wx", mode: 0o600,
  });
  hardenSecretPath(paths.projectWrapPrivateKey, { required: true });
  writeFileSync(paths.projectWrapPublicKey, projectWrapPair.publicKey, {
    encoding: "utf8", flag: "wx", mode: 0o644,
  });
  return {
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
    messagingPrivateKeyPem: messagingPair.privateKey,
    messagingPublicKeyPem: messagingPair.publicKey,
    projectWrapPrivateKeyPem: projectWrapPair.privateKey,
    projectWrapPublicKeyPem: projectWrapPair.publicKey,
  };
}
