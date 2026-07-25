import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { publicKeyFingerprint } from "@cocodex/protocol";
import {
  openPrivateMessage,
  openSignedPrivateMessage,
  sealPrivateMessage,
  sealSignedPrivateMessage,
} from "../src/cocodex/private-messaging";

function identity() {
  const signing = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messaging = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { signing, messaging };
}

describe("CoCodex private-message encryption", () => {
  test("uses sealed boxes so only the recipient device can decrypt", async () => {
    const stephen = identity();
    const kai = identity();
    const plaintext = "private alpha secret";
    const ciphertext = await sealPrivateMessage(plaintext, stephen.messaging.publicKey);
    expect(ciphertext).not.toContain(plaintext);
    expect(await openPrivateMessage(
      ciphertext, stephen.messaging.privateKey, stephen.messaging.publicKey,
    )).toBe(plaintext);
    await expect(openPrivateMessage(ciphertext, kai.messaging.privateKey, kai.messaging.publicKey))
      .rejects.toThrow("could not be decrypted");
  });

  test("binds a signed sender identity and outer delivery envelope inside ciphertext", async () => {
    const stephen = identity();
    const kai = identity();
    const messageId = randomUUID();
    const senderDeviceId = randomUUID();
    const recipientDeviceId = randomUUID();
    const clientCreatedAt = new Date().toISOString();
    const envelope = { messageId, senderDeviceId, recipientDeviceId, clientCreatedAt };
    const ciphertext = await sealSignedPrivateMessage({ ...envelope, text: "signed private alpha secret" },
      kai.signing.privateKey, kai.signing.publicKey, stephen.messaging.publicKey);
    const opened = await openSignedPrivateMessage(
      ciphertext, stephen.messaging.privateKey, stephen.messaging.publicKey,
      envelope, publicKeyFingerprint(kai.signing.publicKey),
    );
    expect(opened.text).toBe("signed private alpha secret");
    await expect(openSignedPrivateMessage(
      ciphertext, stephen.messaging.privateKey, stephen.messaging.publicKey,
      { ...envelope, senderDeviceId: randomUUID() }, publicKeyFingerprint(kai.signing.publicKey),
    )).rejects.toThrow("envelope validation failed");
    await expect(openSignedPrivateMessage(
      ciphertext, stephen.messaging.privateKey, stephen.messaging.publicKey,
      envelope, publicKeyFingerprint(identity().signing.publicKey),
    )).rejects.toThrow("sender identity is not trusted");
  });
});