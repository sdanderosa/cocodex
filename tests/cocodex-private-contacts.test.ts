import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDeviceKeyCertificate, publicKeyFingerprint } from "@cocodex/protocol";
import {
  safePrivateContacts,
  loadPrivateContactSnapshot,
  savePrivateContactSnapshot,
  verifyPrivateContactSnapshot,
} from "../src/cocodex/private-contacts";

function contact(displayName: string) {
  const signing = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messaging = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const projectWrap = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const deviceId = randomUUID();
  const fingerprint = publicKeyFingerprint(signing.publicKey);
  return {
    deviceId,
    displayName,
    fingerprint,
    deviceKeyCertificate: createDeviceKeyCertificate(deviceId, {
      publicKeyPem: signing.publicKey,
      privateKeyPem: signing.privateKey,
      messagingPublicKeyPem: messaging.publicKey,
      projectWrapPublicKeyPem: projectWrap.publicKey,
    }),
  };
}

describe("CoCodex verified private contacts", () => {
  const authority = {
    serverIdentityFingerprint: "SHA256:server-authority-test-fingerprint",
    serverEpoch: 1,
  };
  test("retains public keys only in the resident cache and projects trust safely", () => {
    const kai = contact("Kai");
    const verified = verifyPrivateContactSnapshot([kai], randomUUID());
    expect(verified.get(kai.deviceId)?.messagingPublicKeyPem).toContain("PUBLIC KEY");
    expect(safePrivateContacts(verified, {})).toEqual([{
      deviceId: kai.deviceId,
      displayName: "Kai",
      fingerprint: kai.fingerprint,
      trusted: false,
      projectCapable: true,
    }]);
    expect(safePrivateContacts(verified, { [kai.deviceId]: kai.fingerprint })[0]?.trusted).toBeTrue();
    expect(JSON.stringify(safePrivateContacts(verified, {}))).not.toContain("deviceKeyCertificate");
  });

  test("rejects self, duplicate identities, and directory/certificate mismatch", () => {
    const kai = contact("Kai");
    expect(() => verifyPrivateContactSnapshot([kai], kai.deviceId)).toThrow("local device");
    expect(() => verifyPrivateContactSnapshot([kai, kai], randomUUID())).toThrow("duplicate identity");
    const other = contact("Stephen");
    expect(() => verifyPrivateContactSnapshot([
      { ...kai, fingerprint: other.fingerprint },
    ], randomUUID())).toThrow("does not match");
  });

  test("persists only verified public contact material for offline restart", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-private-contacts-"));
    try {
      const path = join(root, "private-contacts.json");
      const localDeviceId = randomUUID();
      const kai = contact("Kai");
      savePrivateContactSnapshot(path, localDeviceId, authority, [kai]);
      expect(loadPrivateContactSnapshot(path, localDeviceId, authority)).toEqual([kai]);
      const raw = readFileSync(path, "utf8");
      expect(JSON.parse(raw).contacts[0].deviceKeyCertificate).toBe(kai.deviceKeyCertificate);
      expect(raw).not.toContain("PRIVATE KEY");
      expect(() => loadPrivateContactSnapshot(path, randomUUID(), authority)).toThrow("different device");
      expect(() => loadPrivateContactSnapshot(path, localDeviceId, {
        ...authority,
        serverEpoch: 2,
      })).toThrow("different server authority");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
