import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  createDeviceKeyCertificate as createProtocolDeviceKeyCertificate,
  verifyDeviceKeyCertificate as verifyProtocolDeviceKeyCertificate,
  type DeviceKeyCertificate,
} from "../../packages/cocodex-protocol/src/index.ts";
import type { ClientPaths } from "./paths";
import { hardenSecretDir } from "../lib/windows-secret-acl";
import { readProtectedSecret, writeProtectedSecret } from "../lib/local-protected-secret";

export type { DeviceKeyCertificate };

export interface ClientIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
  messagingPublicKeyPem: string;
  messagingPrivateKeyPem: string;
  projectWrapPublicKeyPem?: string;
  projectWrapPrivateKeyPem?: string;
}

const DEVICE_SIGNING_PURPOSE = "cocodex.client.device-signing-key";
const PRIVATE_MESSAGING_PURPOSE = "cocodex.client.private-messaging-key";
const PROJECT_WRAP_PURPOSE = "cocodex.client.project-wrap-key";

function readPrivateKey(path: string, purpose: string): string {
  return readProtectedSecret(path, purpose).toString("utf8");
}

function writePrivateKey(path: string, purpose: string, value: string): void {
  writeProtectedSecret(path, purpose, value);
}

function assertKeyPair(privateKeyPem: string, publicKeyPem: string, label: string): void {
  let derived: Buffer;
  let expected: Buffer;
  try {
    derived = createPublicKey(privateKeyPem).export({ format: "der", type: "spki" });
    expected = createPublicKey(publicKeyPem).export({ format: "der", type: "spki" });
  } catch {
    throw new Error(`CoCodex ${label} key is invalid`);
  }
  if (!derived.equals(expected)) throw new Error(`CoCodex ${label} keypair does not match`);
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
    let projectWrapPrivateKeyPem: string;
    let projectWrapPublicKeyPem: string;
    if (projectWrapPrivateExists) {
      projectWrapPrivateKeyPem = readPrivateKey(paths.projectWrapPrivateKey, PROJECT_WRAP_PURPOSE);
      projectWrapPublicKeyPem = readFileSync(paths.projectWrapPublicKey, "utf8");
    } else {
      const projectWrap = generateKeyPairSync("x25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      writePrivateKey(paths.projectWrapPrivateKey, PROJECT_WRAP_PURPOSE, projectWrap.privateKey);
      writeFileSync(paths.projectWrapPublicKey, projectWrap.publicKey, {
        encoding: "utf8", flag: "wx", mode: 0o644,
      });
      projectWrapPrivateKeyPem = projectWrap.privateKey;
      projectWrapPublicKeyPem = projectWrap.publicKey;
    }
    const privateKeyPem = readPrivateKey(paths.identityPrivateKey, DEVICE_SIGNING_PURPOSE);
    const publicKeyPem = readFileSync(paths.identityPublicKey, "utf8");
    const messagingPrivateKeyPem = readPrivateKey(paths.messagingPrivateKey, PRIVATE_MESSAGING_PURPOSE);
    const messagingPublicKeyPem = readFileSync(paths.messagingPublicKey, "utf8");
    assertKeyPair(privateKeyPem, publicKeyPem, "device-signing");
    assertKeyPair(messagingPrivateKeyPem, messagingPublicKeyPem, "private-messaging");
    assertKeyPair(projectWrapPrivateKeyPem, projectWrapPublicKeyPem, "project-wrap");
    return {
      privateKeyPem,
      publicKeyPem,
      messagingPrivateKeyPem,
      messagingPublicKeyPem,
      projectWrapPrivateKeyPem,
      projectWrapPublicKeyPem,
    };
  }
  if (privateExists) {
    hardenSecretDir(paths.root, { required: true });
    const messagingPair = generateKeyPairSync("x25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const projectWrapPair = generateKeyPairSync("x25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    writePrivateKey(paths.messagingPrivateKey, PRIVATE_MESSAGING_PURPOSE, messagingPair.privateKey);
    writeFileSync(paths.messagingPublicKey, messagingPair.publicKey, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o644,
    });
    writePrivateKey(paths.projectWrapPrivateKey, PROJECT_WRAP_PURPOSE, projectWrapPair.privateKey);
    writeFileSync(paths.projectWrapPublicKey, projectWrapPair.publicKey, {
      encoding: "utf8", flag: "wx", mode: 0o644,
    });
    const privateKeyPem = readPrivateKey(paths.identityPrivateKey, DEVICE_SIGNING_PURPOSE);
    const publicKeyPem = readFileSync(paths.identityPublicKey, "utf8");
    assertKeyPair(privateKeyPem, publicKeyPem, "device-signing");
    return {
      privateKeyPem,
      publicKeyPem,
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
  writePrivateKey(paths.identityPrivateKey, DEVICE_SIGNING_PURPOSE, pair.privateKey);
  writeFileSync(paths.identityPublicKey, pair.publicKey, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o644,
  });
  writePrivateKey(paths.messagingPrivateKey, PRIVATE_MESSAGING_PURPOSE, messagingPair.privateKey);
  writeFileSync(paths.messagingPublicKey, messagingPair.publicKey, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o644,
  });
  writePrivateKey(paths.projectWrapPrivateKey, PROJECT_WRAP_PURPOSE, projectWrapPair.privateKey);
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
