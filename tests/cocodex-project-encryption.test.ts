import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import {
  projectContentAad,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  projectKeyEnvelopeSchema,
  type ProjectContentEnvelope,
} from "@cocodex/protocol";
import {
  createProjectKey,
  openProjectContent,
  openProjectKeyEnvelope,
  sealProjectContent,
  sealProjectKeyEnvelope,
} from "../src/cocodex/project-encryption";

function signingIdentity() {
  return generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function projectWrapIdentity() {
  return generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function device() {
  return {
    id: randomUUID(),
    signing: signingIdentity(),
    projectWrap: projectWrapIdentity(),
  };
}

describe("CoCodex project encryption foundation", () => {
  test("wraps one random project key to a dedicated recipient key and rejects another recipient", async () => {
    const sender = device();
    const recipient = device();
    const wrongRecipient = device();
    const projectId = randomUUID();
    const projectKey = createProjectKey();
    const envelope = await sealProjectKeyEnvelope({
      projectId,
      keyEpoch: 1,
      recipientDeviceId: recipient.id,
      senderDeviceId: sender.id,
      projectKey,
      recipientProjectWrapPublicKeyPem: recipient.projectWrap.publicKey,
      senderPrivateKeyPem: sender.signing.privateKey,
      senderPublicKeyPem: sender.signing.publicKey,
    });

    expect(envelope.projectId).toBe(projectId);
    expect(envelope.keyEpoch).toBe(1);
    expect(envelope.sealedProjectKey).not.toContain(projectKey.toString("base64url"));
    expect(await openProjectKeyEnvelope({
      envelope,
      recipientDeviceId: recipient.id,
      recipientProjectWrapPrivateKeyPem: recipient.projectWrap.privateKey,
      recipientProjectWrapPublicKeyPem: recipient.projectWrap.publicKey,
      expectedSenderPublicKeyPem: sender.signing.publicKey,
    })).toEqual(projectKey);

    await expect(openProjectKeyEnvelope({
      envelope,
      recipientDeviceId: wrongRecipient.id,
      recipientProjectWrapPrivateKeyPem: wrongRecipient.projectWrap.privateKey,
      recipientProjectWrapPublicKeyPem: wrongRecipient.projectWrap.publicKey,
      expectedSenderPublicKeyPem: sender.signing.publicKey,
    })).rejects.toThrow("another device");
    await expect(openProjectKeyEnvelope({
      envelope,
      recipientDeviceId: recipient.id,
      recipientProjectWrapPrivateKeyPem: wrongRecipient.projectWrap.privateKey,
      recipientProjectWrapPublicKeyPem: wrongRecipient.projectWrap.publicKey,
      expectedSenderPublicKeyPem: sender.signing.publicKey,
    })).rejects.toThrow("could not be decrypted");
  });

  test("rejects a tampered key envelope and an untrusted sender key", async () => {
    const sender = device();
    const recipient = device();
    const projectKey = createProjectKey();
    const envelope = await sealProjectKeyEnvelope({
      projectId: randomUUID(),
      keyEpoch: 2,
      recipientDeviceId: recipient.id,
      senderDeviceId: sender.id,
      projectKey,
      recipientProjectWrapPublicKeyPem: recipient.projectWrap.publicKey,
      senderPrivateKeyPem: sender.signing.privateKey,
      senderPublicKeyPem: sender.signing.publicKey,
    });
    const tampered = {
      ...envelope,
      sealedProjectKey: `${envelope.sealedProjectKey.slice(0, -1)}${envelope.sealedProjectKey.endsWith("A") ? "B" : "A"}`,
    };
    expect(() => projectKeyEnvelopeSchema.parse(tampered)).not.toThrow();
    await expect(openProjectKeyEnvelope({
      envelope: tampered,
      recipientDeviceId: recipient.id,
      recipientProjectWrapPrivateKeyPem: recipient.projectWrap.privateKey,
      recipientProjectWrapPublicKeyPem: recipient.projectWrap.publicKey,
      expectedSenderPublicKeyPem: sender.signing.publicKey,
    })).rejects.toThrow("signature is invalid");
    await expect(openProjectKeyEnvelope({
      envelope,
      recipientDeviceId: recipient.id,
      recipientProjectWrapPrivateKeyPem: recipient.projectWrap.privateKey,
      recipientProjectWrapPublicKeyPem: recipient.projectWrap.publicKey,
      expectedSenderPublicKeyPem: signingIdentity().publicKey,
    })).rejects.toThrow("not trusted");
  });

  test("encrypts and signs content with metadata-bound XChaCha20-Poly1305", async () => {
    const sender = device();
    const projectKey = createProjectKey();
    const projectId = randomUUID();
    const recordId = randomUUID();
    const plaintext = "shared context must not appear in server storage";
    const envelope = await sealProjectContent({
      projectId,
      keyEpoch: 7,
      recordType: "shared-context",
      recordId,
      plaintext,
      projectKey,
      senderDeviceId: sender.id,
      senderPrivateKeyPem: sender.signing.privateKey,
      senderPublicKeyPem: sender.signing.publicKey,
    });

    expect(envelope.ciphertext).not.toContain(plaintext);
    expect(projectContentAad(envelope)).not.toEqual(projectContentAad({ ...envelope, recordId: randomUUID() }));
    expect(await openProjectContent({
      envelope,
      projectKey,
      expectedSenderDeviceId: sender.id,
      expectedSenderPublicKeyPem: sender.signing.publicKey,
    })).toEqual(Buffer.from(plaintext, "utf8"));
    await expect(openProjectContent({ envelope, projectKey: createProjectKey() }))
      .rejects.toThrow("could not be decrypted");
    await expect(openProjectContent({
      envelope,
      projectKey,
      expectedProjectId: randomUUID(),
    })).rejects.toThrow("another project");
    await expect(openProjectContent({
      envelope,
      projectKey,
      expectedSenderDeviceId: randomUUID(),
    })).rejects.toThrow("sender device");
  });

  test("rejects ciphertext tampering, sender tampering, and a re-signed AAD transplant", async () => {
    const sender = device();
    const projectKey = createProjectKey();
    const envelope = await sealProjectContent({
      projectId: randomUUID(),
      keyEpoch: 1,
      recordType: "chat",
      recordId: randomUUID(),
      plaintext: "keep this opaque",
      projectKey,
      senderDeviceId: sender.id,
      senderPrivateKeyPem: sender.signing.privateKey,
      senderPublicKeyPem: sender.signing.publicKey,
    });

    const bytes = Buffer.from(envelope.ciphertext, "base64url");
    bytes[0] ^= 0x01;
    await expect(openProjectContent({
      envelope: { ...envelope, ciphertext: bytes.toString("base64url") },
      projectKey,
    })).rejects.toThrow("signature is invalid");

    const modifiedRecordId = randomUUID();
    const unsignedModified = { ...envelope, recordId: modifiedRecordId };
    const reSigned: ProjectContentEnvelope = {
      ...unsignedModified,
      signature: sign(
        null,
        projectContentSigningTranscript(unsignedModified),
        sender.signing.privateKey,
      ).toString("base64url"),
    };
    await expect(openProjectContent({ envelope: reSigned, projectKey }))
      .rejects.toThrow("could not be decrypted");

    const senderReplacement = device();
    await expect(openProjectContent({
      envelope,
      projectKey,
      expectedSenderPublicKeyPem: senderReplacement.signing.publicKey,
    })).rejects.toThrow("not trusted");
  });

  test("keeps protocol envelopes strictly bounded and rejects malformed base64url", async () => {
    const sender = device();
    const recipient = device();
    const keyEnvelope = await sealProjectKeyEnvelope({
      projectId: randomUUID(),
      keyEpoch: 1,
      recipientDeviceId: recipient.id,
      senderDeviceId: sender.id,
      projectKey: createProjectKey(),
      recipientProjectWrapPublicKeyPem: recipient.projectWrap.publicKey,
      senderPrivateKeyPem: sender.signing.privateKey,
      senderPublicKeyPem: sender.signing.publicKey,
    });
    expect(() => projectKeyEnvelopeSchema.parse({ ...keyEnvelope, sealedProjectKey: "%%%" })).toThrow();
    const content = await sealProjectContent({
      projectId: keyEnvelope.projectId,
      keyEpoch: 1,
      recordType: "artifact",
      recordId: randomUUID(),
      plaintext: "bounded",
      projectKey: createProjectKey(),
      senderDeviceId: sender.id,
      senderPrivateKeyPem: sender.signing.privateKey,
      senderPublicKeyPem: sender.signing.publicKey,
    });
    expect(() => projectContentEnvelopeSchema.parse({ ...content, nonce: "%%%" })).toThrow();
    expect(() => projectContentEnvelopeSchema.parse({ ...content, extra: true })).toThrow();
  });
});
