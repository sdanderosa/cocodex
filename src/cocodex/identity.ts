import { createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { publicKeyFingerprint } from "@cocodex/protocol";
import type { ClientPaths } from "./paths";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

export interface ClientIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
  messagingPublicKeyPem: string;
  messagingPrivateKeyPem: string;
  projectWrapPublicKeyPem?: string;
  projectWrapPrivateKeyPem?: string;
}

export interface DeviceKeyCertificate {
  version: 1;
  deviceId: string;
  devicePublicKeyPem: string;
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem?: string;
  signature: string;
}

function certificateTranscript(input: Omit<DeviceKeyCertificate, "version" | "signature">): Buffer {
  const values = ["1", input.deviceId, input.devicePublicKeyPem, input.messagingPublicKeyPem, input.projectWrapPublicKeyPem ?? ""];
  return Buffer.concat([
    Buffer.from("COCODEX-DEVICE-KEY-CERTIFICATE\u0000", "utf8"),
    ...values.map(value => {
      const data = Buffer.from(value, "utf8");
      const length = Buffer.allocUnsafe(4);
      length.writeUInt32BE(data.length);
      return Buffer.concat([length, data]);
    }),
  ]);
}

export function createDeviceKeyCertificate(deviceId: string, identity: ClientIdentity): string {
  const unsigned = {
    deviceId,
    devicePublicKeyPem: identity.publicKeyPem,
    messagingPublicKeyPem: identity.messagingPublicKeyPem,
    ...(identity.projectWrapPublicKeyPem ? { projectWrapPublicKeyPem: identity.projectWrapPublicKeyPem } : {}),
  };
  const certificate: DeviceKeyCertificate = {
    version: 1,
    ...unsigned,
    signature: sign(null, certificateTranscript(unsigned), identity.privateKeyPem).toString("base64url"),
  };
  return JSON.stringify(certificate);
}

export function verifyDeviceKeyCertificate(value: string, expectedDeviceId: string): {
  fingerprint: string;
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem?: string;
} {
  const decoded = JSON.parse(value) as Partial<DeviceKeyCertificate>;
  const keys = decoded && typeof decoded === "object" ? Object.keys(decoded).sort() : [];
  const expectedLegacyKeys = "deviceId,devicePublicKeyPem,messagingPublicKeyPem,signature,version";
  const expectedProjectKeys = "deviceId,devicePublicKeyPem,messagingPublicKeyPem,projectWrapPublicKeyPem,signature,version";
  if (keys.join(",") !== expectedLegacyKeys && keys.join(",") !== expectedProjectKeys
    || decoded.version !== 1 || decoded.deviceId !== expectedDeviceId
    || typeof decoded.devicePublicKeyPem !== "string"
    || typeof decoded.messagingPublicKeyPem !== "string"
    || typeof decoded.signature !== "string") {
    throw new Error("Recipient device key certificate is invalid");
  }
  const messagingKey = createPublicKey(decoded.messagingPublicKeyPem);
  if (messagingKey.asymmetricKeyType !== "x25519") {
    throw new Error("Recipient device key certificate has an invalid messaging key");
  }
  if (decoded.projectWrapPublicKeyPem !== undefined
    && createPublicKey(decoded.projectWrapPublicKeyPem).asymmetricKeyType !== "x25519") {
    throw new Error("Recipient device certificate has an invalid project-wrap key");
  }
  const valid = verify(null, certificateTranscript({
    deviceId: decoded.deviceId,
    devicePublicKeyPem: decoded.devicePublicKeyPem,
    messagingPublicKeyPem: decoded.messagingPublicKeyPem,
    projectWrapPublicKeyPem: decoded.projectWrapPublicKeyPem,
  }), createPublicKey(decoded.devicePublicKeyPem), Buffer.from(decoded.signature, "base64url"));
  if (!valid) throw new Error("Recipient device key certificate signature is invalid");
  return {
    fingerprint: publicKeyFingerprint(decoded.devicePublicKeyPem),
    messagingPublicKeyPem: decoded.messagingPublicKeyPem,
    projectWrapPublicKeyPem: decoded.projectWrapPublicKeyPem,
  };
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
