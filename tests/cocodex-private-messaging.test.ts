import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { publicKeyFingerprint } from "@cocodex/protocol";
import { createDeviceKeyCertificate, verifyDeviceKeyCertificate } from "../src/cocodex/identity";
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
  test("binds the recipient messaging key to its trusted signing identity", () => {
    const recipient = identity();
    const deviceId = randomUUID();
    const certificate = createDeviceKeyCertificate(deviceId, {
      publicKeyPem: recipient.signing.publicKey,
      privateKeyPem: recipient.signing.privateKey,
      messagingPublicKeyPem: recipient.messaging.publicKey,
      messagingPrivateKeyPem: recipient.messaging.privateKey,
    });
    expect(verifyDeviceKeyCertificate(certificate, deviceId)).toEqual({
      fingerprint: publicKeyFingerprint(recipient.signing.publicKey),
      messagingPublicKeyPem: recipient.messaging.publicKey,
    });
    const tampered = JSON.parse(certificate);
    tampered.messagingPublicKeyPem = identity().messaging.publicKey;
    expect(() => verifyDeviceKeyCertificate(JSON.stringify(tampered), deviceId))
      .toThrow("signature is invalid");
    expect(() => verifyDeviceKeyCertificate(certificate, randomUUID()))
      .toThrow("certificate is invalid");
  });
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
    await expect(openPrivateMessage(`${ciphertext}=`, stephen.messaging.privateKey, stephen.messaging.publicKey))
      .rejects.toThrow("could not be decrypted");
    await expect(openPrivateMessage("not-base64", stephen.messaging.privateKey, stephen.messaging.publicKey))
      .rejects.toThrow("could not be decrypted");
    await expect(sealPrivateMessage("x".repeat(64 * 1024 + 1), stephen.messaging.publicKey))
      .rejects.toThrow("plaintext is outside the supported bounds");
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
  test("authenticates reply and mutation metadata inside version-two ciphertext", async () => {
    const sender = identity();
    const recipient = identity();
    const envelope = {
      messageId: randomUUID(),
      senderDeviceId: randomUUID(),
      recipientDeviceId: randomUUID(),
      clientCreatedAt: new Date().toISOString(),
    };
    const targetMessageId = randomUUID();
    const ciphertext = await sealSignedPrivateMessage({
      ...envelope,
      kind: "reaction",
      text: "",
      targetMessageId,
      emoji: "thumbs-up",
      reactionOperation: "add",
    }, sender.signing.privateKey, sender.signing.publicKey, recipient.messaging.publicKey);
    const opened = await openSignedPrivateMessage(
      ciphertext,
      recipient.messaging.privateKey,
      recipient.messaging.publicKey,
      envelope,
      publicKeyFingerprint(sender.signing.publicKey),
    );
    expect(opened).toMatchObject({
      version: 2,
      kind: "reaction",
      targetMessageId,
      emoji: "thumbs-up",
      reactionOperation: "add",
    });

    await expect(sealSignedPrivateMessage({
      ...envelope,
      messageId: randomUUID(),
      kind: "delete",
      targetMessageId,
      text: "plaintext must be empty",
    }, sender.signing.privateKey, sender.signing.publicKey, recipient.messaging.publicKey))
      .rejects.toThrow("delete payload is invalid");
    await expect(sealSignedPrivateMessage({
      ...envelope,
      messageId: randomUUID(),
      kind: "message",
      replyToMessageId: "not-a-uuid",
      text: "reply",
    }, sender.signing.privateKey, sender.signing.publicKey, recipient.messaging.publicKey))
      .rejects.toThrow("reply target is invalid");
  });

});
