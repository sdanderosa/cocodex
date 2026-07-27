import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import {
  canonicalEd25519PublicKey,
  createDeviceKeyCertificate,
  agentListFrameSchema,
  agentReadyAcceptedFrameSchema,
  agentTaskListFrameSchema,
  clientFrameSchema,
  decodeInvitation,
  encodeInvitation,
  enrollmentSigningTranscript,
  encryptedFileReferenceSchema,
  fileReferencePlaintextSchema,
  PROJECT_CONTEXT_MAX_BYTES,
  projectContextResultFrameSchema,
  projectKeyEnvelopeSchema,
  projectDeviceRevokedFrameSchema,
  projectKeyInitializedFrameSchema,
  projectKeyRotatedFrameSchema,
  projectKeyRotationRequiredFrameSchema,
  projectInvitationDecisionTranscript,
  projectInvitationSigningTranscript,
  projectMemberRemovedFrameSchema,
  projectServerFrameSchema,
  privateAcceptedFrameSchema,
  privateContactSnapshotFrameSchema,
  privateMessageFrameSchema,
  privateReceiptAcceptedFrameSchema,
  privateReceiptFrameSchema,
  privateServerFrameSchema,
  privateSnapshotFrameSchema,
  presenceAcceptedFrameSchema,
  presenceLeaveFrameSchema,
  presenceSnapshotFrameSchema,
  presenceUpdateFrameSchema,
  publicKeyFingerprint,
  usageReportSchema,
  usageReportSigningTranscript,
  websocketAuthTranscript,
} from "../src";

describe("CoCodex protocol", () => {
  test("validates an agent-scoped ready acknowledgement", () => {
    const frame = {
      version: 1 as const,
      type: "agent.ready.accepted" as const,
      requestId: crypto.randomUUID(),
      agentId: crypto.randomUUID(),
    };
    expect(agentReadyAcceptedFrameSchema.parse(frame)).toEqual(frame);
    expect(projectServerFrameSchema.parse(frame)).toEqual(frame);
    expect(() => agentReadyAcceptedFrameSchema.parse({ ...frame, agentId: "" })).toThrow();
  });

  test("round-trips a strict versioned invitation", () => {
    const payload = {
      version: 1 as const,
      host: "example.test",
      port: 10443,
      serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
      invitationId: "e70b1cb4-1d63-4dfe-8e07-454738f75725",
      token: "A".repeat(43),
      expiresAt: "2030-01-01T00:00:00.000Z",
      scope: "device-enrollment" as const,
    };
    expect(decodeInvitation(encodeInvitation(payload))).toEqual(payload);
    expect(() => decodeInvitation("ccx1.not-json")).toThrow();
  });

  test("canonicalizes Ed25519 keys and derives stable fingerprints", () => {
    const pair = generateKeyPairSync("ed25519");
    const pem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(canonicalEd25519PublicKey(pem)).toBe(pem);
    expect(publicKeyFingerprint(pem)).toBe(publicKeyFingerprint(pem));

    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPem = rsa.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => canonicalEd25519PublicKey(rsaPem)).toThrow("Ed25519");
  });

  test("signing transcript is length-prefixed and binds every field", () => {
    const input = {
      serverFingerprint: "server",
      invitationId: "invite",
      challengeId: "challenge-id",
      challenge: "nonce",
      displayName: "Kai",
      devicePublicKeyPem: "key",
      messagingPublicKeyPem: "messaging-key",
    };
    const baseline = enrollmentSigningTranscript(input);
    expect(baseline.subarray(0, 19).toString()).toBe("COCODEX-ENROLLMENT\u0000");
    expect(enrollmentSigningTranscript({ ...input, challenge: "other" })).not.toEqual(baseline);
    expect(enrollmentSigningTranscript({ ...input, invitationId: "other" })).not.toEqual(baseline);
    expect(enrollmentSigningTranscript({ ...input, displayName: "Stephen" })).not.toEqual(baseline);
  });

  test("accepts bounded Yjs prompt frames and rejects extra fields", () => {
    const frame = {
      version: 1 as const,
      type: "prompt.update" as const,
      requestId: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      updateId: crypto.randomUUID(),
      update: "AQID",
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => clientFrameSchema.parse({ ...frame, targetDeviceId: crypto.randomUUID() })).toThrow();
  });

  test("strictly validates encrypted file-reference metadata and frames", () => {
    const projectId = crypto.randomUUID();
    const referenceId = crypto.randomUUID();
    const artifactId = crypto.randomUUID();
    const deviceId = crypto.randomUUID();
    const envelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recordType: "file-reference" as const,
      recordId: referenceId,
      nonce: "A".repeat(32),
      ciphertext: "B".repeat(64),
      senderDeviceId: deviceId,
      senderPublicKeyPem: "P".repeat(64),
      signature: Buffer.alloc(64, 7).toString("base64url"),
    };
    const publish = {
      version: 1 as const,
      type: "project.file-reference.publish" as const,
      requestId: crypto.randomUUID(),
      referenceId,
      projectId,
      chatId: projectId,
      artifactId,
      envelope,
    };
    expect(clientFrameSchema.parse(publish)).toEqual(publish);
    expect(() => clientFrameSchema.parse({ ...publish, relativePath: "secret.txt" })).toThrow();
    expect(() => clientFrameSchema.parse({
      ...publish,
      envelope: { ...envelope, recordType: "artifact" },
    })).toThrow();
    const wrapper = {
      referenceId,
      projectId,
      chatId: projectId,
      artifactId,
      hostDeviceId: deviceId,
      authorDeviceId: deviceId,
      envelope,
      createdAt: "2030-01-01T00:00:00.000Z",
      updatedAt: "2030-01-01T00:00:00.000Z",
    };
    expect(encryptedFileReferenceSchema.parse(wrapper)).toEqual(wrapper);
    expect(projectServerFrameSchema.parse({
      version: 1,
      type: "project.file-reference.list.result",
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      references: [wrapper],
    })).toBeTruthy();
    const plaintext = {
      version: 1 as const,
      referenceId,
      projectId,
      chatId: projectId,
      artifactId,
      hostDeviceId: deviceId,
      relativePath: "reports/result.txt",
      workspaceMode: "shared" as const,
      workspaceRef: "main",
      branch: null,
      commitSha: null,
      sha256: "a".repeat(64),
      sizeBytes: 12,
      mediaType: "text/plain",
    };
    expect(fileReferencePlaintextSchema.parse(plaintext)).toEqual(plaintext);
    for (const relativePath of ["/secret", "../secret", "a/../secret", "C:/secret", "\\\\server\\share", "a\\b", "https:secret"]) {
      expect(() => fileReferencePlaintextSchema.parse({ ...plaintext, relativePath })).toThrow();
    }
  });
  test("accepts revisioned project-context updates and rejects invalid revisions", () => {
    const frame = {
      version: 1 as const,
      type: "context.update" as const,
      requestId: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      expectedRevision: 0,
      finalGoal: "Build the private alpha",
      context: { owner: "Stephen", phase: "alpha" },
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => clientFrameSchema.parse({ ...frame, expectedRevision: -1 })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, finalGoal: "x".repeat(32_769) })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, context: [] })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, context: { blob: "x".repeat(PROJECT_CONTEXT_MAX_BYTES) } })).toThrow();
  });
  test("strictly bounds opaque project-encryption frames in both directions", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const projectId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const keyEnvelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recipientDeviceId,
      senderDeviceId,
      sealedProjectKey: Buffer.alloc(80, 1).toString("base64url"),
      senderPublicKeyPem: signing.publicKey,
      signature: Buffer.alloc(64, 2).toString("base64url"),
    };
    const contentEnvelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recordType: "shared-context" as const,
      recordId: crypto.randomUUID(),
      nonce: Buffer.alloc(24, 3).toString("base64url"),
      ciphertext: Buffer.alloc(16, 4).toString("base64url"),
      senderDeviceId,
      senderPublicKeyPem: signing.publicKey,
      signature: Buffer.alloc(64, 5).toString("base64url"),
    };
    expect(projectKeyEnvelopeSchema.parse(keyEnvelope)).toEqual(keyEnvelope);
    const keyShare = {
      version: 1 as const,
      type: "project.key.share" as const,
      requestId: crypto.randomUUID(),
      projectId,
      envelope: keyEnvelope,
    };
    const contextUpdate = {
      version: 1 as const,
      type: "project.context.update" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      expectedRevision: 0,
      envelope: contentEnvelope,
    };
    expect(clientFrameSchema.parse(keyShare)).toEqual(keyShare);
    const initialize = {
      version: 1 as const,
      type: "project.key.initialize" as const,
      requestId: crypto.randomUUID(),
      projectId,
      keyEpoch: 1 as const,
      envelopes: [keyEnvelope],
    };
    expect(clientFrameSchema.parse(initialize)).toEqual(initialize);
    expect(() => clientFrameSchema.parse({ ...initialize, keyEpoch: 2 })).toThrow();
    const createProject = {
      version: 1 as const,
      type: "project.create" as const,
      requestId: crypto.randomUUID(),
      projectId,
      name: "Nocturne Launcher",
      keyEpoch: 1 as const,
      envelopes: [keyEnvelope],
      signature: Buffer.alloc(64, 7).toString("base64url"),
    };
    expect(clientFrameSchema.parse(createProject)).toEqual(createProject);
    expect(() => clientFrameSchema.parse({ ...createProject, extra: true })).toThrow();
    expect(() => clientFrameSchema.parse({ ...createProject, keyEpoch: 2 })).toThrow();
    const invitation = {
      version: 1 as const,
      type: "project.invite.create" as const,
      requestId: crypto.randomUUID(),
      invitationId: crypto.randomUUID(),
      projectId,
      serverFingerprint: "AA:BB:CC:DD:EE:FF",
      recipientDeviceId,
      keyEpoch: 1,
      envelope: keyEnvelope,
      issuedAt: "2030-01-01T00:00:00.000Z",
      expiresAt: "2030-01-02T00:00:00.000Z",
      nonce: Buffer.alloc(32, 9).toString("base64url"),
      signature: Buffer.alloc(64, 10).toString("base64url"),
    };
    expect(clientFrameSchema.parse(invitation)).toEqual(invitation);
    expect(() => clientFrameSchema.parse({ ...invitation, nonce: "not-random" })).toThrow();
    const invitationTranscript = projectInvitationSigningTranscript({
      ...invitation,
      ownerDeviceId: senderDeviceId,
    });
    expect(invitationTranscript.equals(projectInvitationSigningTranscript({
      ...invitation,
      ownerDeviceId: senderDeviceId,
    }))).toBeTrue();
    expect(invitationTranscript.equals(projectInvitationSigningTranscript({
      ...invitation,
      ownerDeviceId: senderDeviceId,
      recipientDeviceId: crypto.randomUUID(),
    }))).toBeFalse();
    expect(projectInvitationDecisionTranscript({
      ...invitation,
      ownerDeviceId: senderDeviceId,
    }, "accept").equals(projectInvitationDecisionTranscript({
      ...invitation,
      ownerDeviceId: senderDeviceId,
    }, "decline"))).toBeFalse();
    expect(clientFrameSchema.parse(contextUpdate)).toEqual(contextUpdate);
    const rotate = {
      version: 1 as const,
      type: "project.key.rotate" as const,
      requestId: crypto.randomUUID(),
      projectId,
      expectedEpoch: 0,
      envelopes: [keyEnvelope],
    };
    expect(clientFrameSchema.parse(rotate)).toEqual(rotate);
    expect(() => clientFrameSchema.parse({ ...rotate, expectedEpoch: -1 })).toThrow();
    const remove = {
      version: 1 as const,
      type: "project.member.remove" as const,
      requestId: crypto.randomUUID(),
      projectId,
      deviceId: recipientDeviceId,
    };
    expect(clientFrameSchema.parse(remove)).toEqual(remove);
    const listMembers = {
      version: 1 as const,
      type: "project.member.list" as const,
      requestId: crypto.randomUUID(),
      projectId,
    };
    expect(clientFrameSchema.parse(listMembers)).toEqual(listMembers);
    const removeAndRotate = {
      version: 1 as const,
      type: "project.member.remove-and-rotate" as const,
      requestId: crypto.randomUUID(),
      projectId,
      deviceId: recipientDeviceId,
      expectedEpoch: 1,
      envelopes: [{ ...keyEnvelope, keyEpoch: 2, recipientDeviceId: senderDeviceId }],
    };
    expect(clientFrameSchema.parse(removeAndRotate)).toEqual(removeAndRotate);
    expect(() => clientFrameSchema.parse({ ...removeAndRotate, unexpected: true })).toThrow();
    expect(() => clientFrameSchema.parse({ ...removeAndRotate, expectedEpoch: 0 })).toThrow();
    expect(() => clientFrameSchema.parse({ ...keyShare, envelope: { ...keyEnvelope, extra: true } })).toThrow();
    expect(() => clientFrameSchema.parse({ ...contextUpdate, envelope: { ...contentEnvelope, ciphertext: "%%%" } })).toThrow();

    const result = {
      version: 1 as const,
      type: "project.context.result" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      envelope: contentEnvelope,
      revision: 1,
      updatedAt: "2030-01-01T00:00:00.000Z",
    };
    expect(projectContextResultFrameSchema.parse(result)).toEqual(result);
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.key.changed" as const,
      projectId,
      envelope: keyEnvelope,
    })).toMatchObject({ type: "project.key.changed", projectId });
    expect(projectKeyInitializedFrameSchema.parse({
      version: 1 as const,
      type: "project.key.initialized" as const,
      requestId: initialize.requestId,
      projectId,
      keyEpoch: 1,
      envelopes: [keyEnvelope],
      created: true,
    })).toMatchObject({ type: "project.key.initialized", projectId, created: true });
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.key.initialized" as const,
      requestId: initialize.requestId,
      projectId,
      keyEpoch: 1,
      envelopes: [keyEnvelope],
      created: true,
    })).toMatchObject({ type: "project.key.initialized", projectId });
    expect(projectKeyRotatedFrameSchema.parse({
      version: 1 as const,
      type: "project.key.rotated" as const,
      requestId: crypto.randomUUID(),
      projectId,
      keyEpoch: 1,
      envelopes: [keyEnvelope],
      created: true,
    })).toMatchObject({ type: "project.key.rotated", keyEpoch: 1 });
    expect(projectMemberRemovedFrameSchema.parse({
      version: 1 as const,
      type: "project.member.removed" as const,
      projectId,
      deviceId: recipientDeviceId,
    })).toMatchObject({ type: "project.member.removed", deviceId: recipientDeviceId });
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.member.list.result" as const,
      requestId: listMembers.requestId,
      projectId,
      members: [{
        deviceId: senderDeviceId,
        displayName: "Stephen",
        fingerprint: "AAAA-BBBB-CCCC-DDDD",
        role: "owner",
        status: "approved",
        deviceKeyCertificate: "C".repeat(256),
      }],
    })).toMatchObject({ type: "project.member.list.result", projectId });
    expect(() => projectServerFrameSchema.parse({
      version: 1,
      type: "project.member.list.result",
      requestId: listMembers.requestId,
      projectId,
      members: [{
        deviceId: recipientDeviceId,
        displayName: "Revoked member",
        fingerprint: "AAAA-BBBB-CCCC-DDDD",
        role: "member",
        status: "pending",
        deviceKeyCertificate: null,
      }],
    })).toThrow();
    const projectList = {
      version: 1 as const,
      type: "project.list.result" as const,
      requestId: crypto.randomUUID(),
      projects: [{ id: projectId, name: "Nocturne Launcher", role: "owner" as const }],
    };
    expect(projectServerFrameSchema.parse(projectList)).toEqual(projectList);
    expect(projectServerFrameSchema.parse({
      version: 1,
      type: "project.created",
      requestId: createProject.requestId,
      project: projectList.projects[0],
      defaultChat: {
        id: projectId,
        projectId,
        title: "General",
        createdByDeviceId: senderDeviceId,
        state: "active",
        createdAt: "2030-01-01T00:00:00.000Z",
        updatedAt: "2030-01-01T00:00:00.000Z",
      },
      keyEpoch: 1,
      envelopes: [keyEnvelope],
      created: true,
    })).toMatchObject({ type: "project.created", created: true });
    expect(projectServerFrameSchema.parse({
      version: 1,
      type: "project.changed",
      project: { ...projectList.projects[0], role: "member" },
    })).toMatchObject({ type: "project.changed" });
    expect(() => projectServerFrameSchema.parse({ ...projectList, extra: "withheld" })).toThrow();
    expect(() => projectServerFrameSchema.parse({ ...result, extra: true })).toThrow();
  });
  test("accepts encrypted shared-chat frames while keeping payloads opaque", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const projectId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const eventId = crypto.randomUUID();
    const envelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recordType: "chat" as const,
      recordId: eventId,
      nonce: Buffer.alloc(24, 3).toString("base64url"),
      ciphertext: Buffer.alloc(32, 4).toString("base64url"),
      senderDeviceId,
      senderPublicKeyPem: signing.publicKey,
      signature: Buffer.alloc(64, 5).toString("base64url"),
    };
    const send = {
      version: 1 as const,
      type: "project.chat.send" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      eventId,
      envelope,
      clientCreatedAt: "2030-01-01T00:00:00.000Z",
    };
    expect(clientFrameSchema.parse(send)).toEqual(send);
    const event = {
      sequence: 1,
      projectId,
      chatId: projectId,
      eventId,
      senderDeviceId,
      envelope,
      clientCreatedAt: send.clientCreatedAt,
      acceptedAt: send.clientCreatedAt,
    };
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.chat.snapshot" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      events: [event],
    })).toMatchObject({ type: "project.chat.snapshot", events: [event] });
    expect(projectServerFrameSchema.parse({ version: 1 as const, type: "project.chat.event" as const, event }))
      .toMatchObject({ type: "project.chat.event", event });
    expect(() => clientFrameSchema.parse({ ...send, envelope: { ...envelope, extra: true } })).toThrow();
  });
  test("accepts encrypted Yjs prompt-update frames", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const projectId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const updateId = crypto.randomUUID();
    const envelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recordType: "shared-prompt" as const,
      recordId: updateId,
      nonce: Buffer.alloc(24, 7).toString("base64url"),
      ciphertext: Buffer.alloc(40, 8).toString("base64url"),
      senderDeviceId,
      senderPublicKeyPem: signing.publicKey,
      signature: Buffer.alloc(64, 9).toString("base64url"),
    };
    const update = {
      version: 1 as const,
      type: "project.prompt.update" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      updateId,
      envelope,
    };
    expect(clientFrameSchema.parse(update)).toEqual(update);
    const routed = {
      sequence: 1,
      projectId,
      chatId: projectId,
      updateId,
      senderDeviceId,
      envelope,
      acceptedAt: "2030-01-01T00:00:00.000Z",
    };
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.prompt.snapshot" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      updates: [routed],
    })).toMatchObject({ type: "project.prompt.snapshot", updates: [routed] });
    expect(projectServerFrameSchema.parse({ version: 1 as const, type: "project.prompt.changed" as const, update: routed }))
      .toMatchObject({ type: "project.prompt.changed", update: routed });
  });
  test("accepts opaque encrypted artifact publish and list frames", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const projectId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const artifactId = crypto.randomUUID();
    const envelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recordType: "artifact" as const,
      recordId: artifactId,
      nonce: Buffer.alloc(24, 10).toString("base64url"),
      ciphertext: Buffer.alloc(80, 11).toString("base64url"),
      senderDeviceId,
      senderPublicKeyPem: signing.publicKey,
      signature: Buffer.alloc(64, 12).toString("base64url"),
    };
    const publish = {
      version: 1 as const,
      type: "project.artifact.publish" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      artifactId,
      taskId: null,
      envelope,
    };
    expect(clientFrameSchema.parse(publish)).toEqual(publish);
    const artifact = {
      artifactId,
      projectId,
      chatId: projectId,
      taskId: null,
      authorDeviceId: senderDeviceId,
      envelope,
      createdAt: "2030-01-01T00:00:00.000Z",
      updatedAt: "2030-01-01T00:00:00.000Z",
    };
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.artifact.published" as const,
      artifact,
    })).toMatchObject({ type: "project.artifact.published", artifact });
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.artifact.list.result" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      artifacts: [artifact],
    })).toMatchObject({ type: "project.artifact.list.result", artifacts: [artifact] });
    expect(() => clientFrameSchema.parse({ ...publish, envelope: { ...envelope, extra: true } })).toThrow();
  });
  test("accepts encrypted agent dispatch and result frames without exposing plaintext", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const projectId = crypto.randomUUID();
    const requesterDeviceId = crypto.randomUUID();
    const targetDeviceId = crypto.randomUUID();
    const taskId = crypto.randomUUID();
    const eventId = crypto.randomUUID();
    const envelope = {
      version: 1 as const,
      projectId,
      keyEpoch: 1,
      recordType: "task" as const,
      recordId: taskId,
      nonce: Buffer.alloc(24, 13).toString("base64url"),
      ciphertext: Buffer.alloc(96, 14).toString("base64url"),
      senderDeviceId: requesterDeviceId,
      senderPublicKeyPem: signing.publicKey,
      signature: Buffer.alloc(64, 15).toString("base64url"),
    };
    const request = {
      version: 1 as const,
      type: "project.agent.request" as const,
      requestId: crypto.randomUUID(),
      taskId,
      projectId,
      chatId: projectId,
      agentId: "kai-agent",
      nonce: "N".repeat(43),
      issuedAt: "2030-01-01T00:00:00.000Z",
      expiresAt: "2030-01-01T00:05:00.000Z",
      dependencies: [],
      inputArtifactIds: [],
      envelope,
    };
    expect(clientFrameSchema.parse(request)).toEqual(request);
    expect(() => clientFrameSchema.parse({ ...request, prompt: "must stay encrypted" })).toThrow();

    const task = {
      id: taskId,
      projectId,
      chatId: projectId,
      requesterDeviceId,
      targetDeviceId,
      agentId: request.agentId,
      prompt: "[encrypted]" as const,
      promptEnvelope: envelope,
      nonce: request.nonce,
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      dependencies: [],
      inputArtifactIds: [],
      inputArtifacts: [],
      requesterSignature: "R".repeat(64),
      requesterPublicKeyPem: signing.publicKey,
      serverSignature: "S".repeat(64),
      status: "queued" as const,
      acceptedAt: request.issuedAt,
    };
    expect(projectServerFrameSchema.parse({ version: 1 as const, type: "project.agent.task" as const, task }))
      .toMatchObject({ type: "project.agent.task", task: { prompt: "[encrypted]", promptEnvelope: envelope } });

    const resultEnvelope = {
      ...envelope,
      recordType: "agent-response" as const,
      recordId: eventId,
      nonce: Buffer.alloc(24, 16).toString("base64url"),
      ciphertext: Buffer.alloc(64, 17).toString("base64url"),
      senderDeviceId: targetDeviceId,
    };
    const result = {
      version: 1 as const,
      type: "project.agent.result" as const,
      requestId: crypto.randomUUID(),
      taskId,
      chatId: projectId,
      eventId,
      envelope: resultEnvelope,
      final: true,
      status: "completed" as const,
    };
    expect(clientFrameSchema.parse(result)).toEqual(result);
    const event = {
      sequence: 7,
      projectId,
      chatId: projectId,
      taskId,
      eventId,
      senderDeviceId: targetDeviceId,
      envelope: resultEnvelope,
      final: true,
      status: "completed" as const,
      clientCreatedAt: "2030-01-01T00:05:01.000Z",
      acceptedAt: "2030-01-01T00:05:02.000Z",
    };
    expect(projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.agent.result" as const,
      taskId,
      chatId: projectId,
      final: true,
      status: "completed" as const,
      event,
    })).toMatchObject({ type: "project.agent.result", event });
    expect(() => projectServerFrameSchema.parse({
      version: 1 as const,
      type: "project.agent.result" as const,
      taskId,
      chatId: projectId,
      final: true,
      status: "completed" as const,
      event: { ...event, content: "plaintext must not be present" },
    })).toThrow();
  });
  test("bounds presence cursor and caret frames", () => {
    const frame = {
      version: 1 as const,
      type: "presence.update" as const,
      requestId: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      chatId: null,
      cursor: { x: 0.25, y: 0.75 },
      caret: { anchor: 3, head: 8 },
      typing: true,
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    const legacyFrame = { ...frame };
    delete (legacyFrame as Partial<typeof frame>).typing;
    expect(clientFrameSchema.parse(legacyFrame)).toMatchObject({ ...frame, typing: false });
    expect(() => clientFrameSchema.parse({ ...frame, cursor: { x: 2, y: 0 } })).toThrow();
  });
  test("strictly validates private-message ciphertext and server delivery frames", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const messageId = crypto.randomUUID();
    const acceptedAt = "2030-01-01T00:00:00.000Z";
    const envelope = {
      sequence: 1,
      messageId,
      senderDeviceId,
      recipientDeviceId,
      ciphertext: Buffer.alloc(48, 7).toString("base64url"),
      clientCreatedAt: acceptedAt,
      acceptedAt,
    };
    const send = {
      version: 1 as const,
      type: "private.send" as const,
      requestId: crypto.randomUUID(),
      messageId,
      recipientDeviceId,
      ciphertext: envelope.ciphertext,
      clientCreatedAt: acceptedAt,
    };
    expect(clientFrameSchema.parse(send)).toEqual(send);
    const snapshot = privateSnapshotFrameSchema.parse({
      version: 1,
      type: "private.snapshot",
      requestId: crypto.randomUUID(),
      messages: [envelope],
    });
    expect(snapshot.messages).toEqual([envelope]);
    expect(snapshot.receipts).toEqual([]);
    expect(privateAcceptedFrameSchema.parse({
      version: 1,
      type: "private.accepted",
      requestId: send.requestId,
      message: envelope,
    })).toMatchObject({ type: "private.accepted", message: envelope });
    expect(privateServerFrameSchema.parse({
      version: 1,
      type: "private.message",
      message: envelope,
    })).toMatchObject({ type: "private.message", message: envelope });
    const receipt = {
      sequence: 1,
      messageId,
      senderDeviceId,
      recipientDeviceId,
      receipt: "delivered" as const,
      acceptedAt,
    };
    const receiptSend = {
      version: 1 as const,
      type: "private.receipt.send" as const,
      requestId: crypto.randomUUID(),
      messageId,
      receipt: "delivered" as const,
    };
    expect(clientFrameSchema.parse(receiptSend)).toEqual(receiptSend);
    expect(privateReceiptAcceptedFrameSchema.parse({
      version: 1,
      type: "private.receipt.accepted",
      requestId: receiptSend.requestId,
      receipt,
    })).toMatchObject({ type: "private.receipt.accepted", receipt });
    expect(privateReceiptFrameSchema.parse({
      version: 1,
      type: "private.receipt",
      receipt,
    })).toMatchObject({ type: "private.receipt", receipt });
    expect(privateServerFrameSchema.parse({
      version: 1,
      type: "private.snapshot",
      requestId: crypto.randomUUID(),
      messages: [],
      receipts: [receipt],
    })).toMatchObject({ receipts: [receipt] });
    expect(() => clientFrameSchema.parse({ ...send, ciphertext: "%%%" })).toThrow("canonical base64url");
    expect(() => privateSnapshotFrameSchema.parse({
      version: 1,
      type: "private.snapshot",
      requestId: crypto.randomUUID(),
      messages: [{ ...envelope, ciphertext: Buffer.alloc(48, 0xfb).toString("base64") }],
    })).toThrow();
    expect(() => privateServerFrameSchema.parse({
      version: 1,
      type: "private.message",
      message: { ...envelope, sequence: 0 },
    })).toThrow();
    expect(() => clientFrameSchema.parse({ ...receiptSend, receipt: "seen" })).toThrow();
  });

  test("strictly bounds private-contact discovery without treating names as identity", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const messaging = generateKeyPairSync("x25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const deviceId = crypto.randomUUID();
    const request = {
      version: 1 as const,
      type: "private.contact.list" as const,
      requestId: crypto.randomUUID(),
    };
    expect(clientFrameSchema.parse(request)).toEqual(request);
    const frame = {
      version: 1 as const,
      type: "private.contact.snapshot" as const,
      requestId: request.requestId,
      contacts: [{
        deviceId,
        displayName: "Stephen",
        fingerprint: publicKeyFingerprint(signing.publicKey),
        deviceKeyCertificate: createDeviceKeyCertificate(deviceId, {
          publicKeyPem: signing.publicKey,
          privateKeyPem: signing.privateKey,
          messagingPublicKeyPem: messaging.publicKey,
        }),
      }],
    };
    expect(privateContactSnapshotFrameSchema.parse(frame)).toEqual(frame);
    expect(privateServerFrameSchema.parse(frame)).toEqual(frame);
    expect(() => privateContactSnapshotFrameSchema.parse({
      ...frame,
      contacts: [{ ...frame.contacts[0], fingerprint: "Stephen" }],
    })).toThrow();
    expect(() => clientFrameSchema.parse({ ...request, displayName: "Stephen" })).toThrow();
  });
  test("strictly validates the authoritative agent roster", () => {
    const projectId = crypto.randomUUID();
    const agent = {
      id: "lucas",
      projectId,
      name: "Lucas",
      primaryModel: "gpt-5.6-sol",
      primaryEffort: "medium" as const,
      coAgentModel: "gpt-5.6-luna",
      coAgentEffort: "medium" as const,
      maxConcurrentCoAgents: 3,
      hostDeviceId: crypto.randomUUID(),
      hostDisplayName: "Stephen",
      enabled: true,
      status: "working" as const,
      activeTasks: 1,
      queuedTasks: 2,
      lastTaskAt: "2030-01-01T00:00:00.000Z",
    };
    const frame = {
      version: 1 as const,
      type: "agent.list.result" as const,
      requestId: crypto.randomUUID(),
      projectId,
      agents: [agent],
    };
    expect(agentListFrameSchema.parse(frame)).toEqual(frame);
    expect(projectServerFrameSchema.parse(frame)).toEqual(frame);
    expect(clientFrameSchema.parse({
      version: 1, type: "agent.list", requestId: crypto.randomUUID(), projectId,
    })).toMatchObject({ type: "agent.list", projectId });
    expect(() => agentListFrameSchema.parse({ ...frame, agents: [{ ...agent, extra: true }] })).toThrow();
    expect(() => agentListFrameSchema.parse({
      ...frame,
      agents: [{ ...agent, maxConcurrentCoAgents: 0 }],
    })).toThrow("Positive co-agent limits");
    const createdAgentId = crypto.randomUUID();
    const create = {
      version: 1 as const,
      type: "agent.create" as const,
      requestId: crypto.randomUUID(),
      projectId,
      agentId: createdAgentId,
      name: "Angela",
      primaryModel: "gpt-5.6-sol",
      primaryEffort: "xhigh" as const,
      coAgentModel: null,
      coAgentEffort: null,
      maxConcurrentCoAgents: 0,
      signature: "s".repeat(64),
    };
    expect(clientFrameSchema.parse(create)).toEqual(create);
    expect(() => clientFrameSchema.parse({
      ...create,
      hostDeviceId: crypto.randomUUID(),
    })).toThrow();
    expect(() => clientFrameSchema.parse({
      ...create,
      workspaceRoot: "C:\\secret",
    })).toThrow();
    expect(projectServerFrameSchema.parse({
      version: 1,
      type: "agent.created",
      requestId: create.requestId,
      projectId,
      agent: {
        id: createdAgentId,
        projectId,
        name: "Angela",
        primaryModel: create.primaryModel,
        primaryEffort: create.primaryEffort,
        coAgentModel: create.coAgentModel,
        coAgentEffort: create.coAgentEffort,
        maxConcurrentCoAgents: create.maxConcurrentCoAgents,
        hostDeviceId: agent.hostDeviceId,
        enabled: true,
      },
      created: true,
    })).toMatchObject({ type: "agent.created", created: true });
    expect(() => clientFrameSchema.parse({
      ...create,
      maxConcurrentCoAgents: 1,
    })).toThrow();
    expect(() => clientFrameSchema.parse({
      ...create,
      primaryModel: "gpt-5.6-sol\"; approval_policy=\"never",
    })).toThrow("Agent model IDs");
    expect(() => clientFrameSchema.parse({
      version: 1,
      type: "agent.ready",
      requestId: crypto.randomUUID(),
      agentId: createdAgentId,
      primaryModel: "gpt-5.6-sol",
    })).toThrow("complete");
  });
  test("strictly validates task activity without carrying prompt content", () => {
    const projectId = crypto.randomUUID();
    const task = {
      id: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      agentId: "lucas",
      agentName: "Lucas",
      requesterDeviceId: crypto.randomUUID(),
      targetDeviceId: crypto.randomUUID(),
      status: "running" as const,
      dependencies: [],
      inputArtifactIds: [],
      workspaceMode: "git-worktree" as const,
      workspaceRef: `worktrees/${projectId}/lucas/${crypto.randomUUID()}`,
      branch: `cocodex/${projectId.slice(0, 8)}/lucas/task`,
      baseCommit: "a".repeat(40),
      mergeTarget: "main",
      acceptedAt: "2030-01-01T00:00:00.000Z",
      startedAt: "2030-01-01T00:00:01.000Z",
      completedAt: null,
      lastActivityAt: "2030-01-01T00:00:02.000Z",
      eventCount: 2,
      encrypted: true,
    };
    const frame = {
      version: 1 as const,
      type: "agent.task.list.result" as const,
      requestId: crypto.randomUUID(),
      projectId,
      chatId: projectId,
      tasks: [task],
    };
    expect(agentTaskListFrameSchema.parse(frame)).toEqual(frame);
    expect(projectServerFrameSchema.parse(frame)).toEqual(frame);
    expect(clientFrameSchema.parse({
      version: 1, type: "agent.task.list", requestId: crypto.randomUUID(), projectId, chatId: projectId,
    })).toMatchObject({ type: "agent.task.list", projectId });
    const executionReport = {
      version: 1 as const,
      type: "agent.execution.report" as const,
      requestId: crypto.randomUUID(),
      taskId: task.id,
      projectId,
      chatId: projectId,
      agentId: task.agentId,
      workspaceMode: task.workspaceMode,
      workspaceRef: task.workspaceRef,
      branch: task.branch,
      baseCommit: task.baseCommit,
      mergeTarget: task.mergeTarget,
      startedAt: task.startedAt,
      signature: "s".repeat(64),
    };
    expect(clientFrameSchema.parse(executionReport)).toEqual(executionReport);
    expect(projectServerFrameSchema.parse({
      version: 1,
      type: "agent.execution.accepted",
      requestId: executionReport.requestId,
      taskId: task.id,
      startedAt: task.startedAt,
    })).toMatchObject({ type: "agent.execution.accepted", taskId: task.id });
    expect(() => agentTaskListFrameSchema.parse({ ...frame, tasks: [{ ...task, prompt: "secret" }] })).toThrow();
  });
  test("strictly validates key-rotation-required notices", () => {
    const frame = {
      version: 1 as const,
      type: "project.key.rotation-required" as const,
      projectId: crypto.randomUUID(),
      removedDeviceId: crypto.randomUUID(),
      currentEpoch: 3,
    };
    expect(projectKeyRotationRequiredFrameSchema.parse(frame)).toEqual(frame);
    expect(projectServerFrameSchema.parse(frame)).toEqual(frame);
    expect(() => projectKeyRotationRequiredFrameSchema.parse({ ...frame, removedDeviceId: "not-a-uuid" })).toThrow();
    expect(() => projectKeyRotationRequiredFrameSchema.parse({ ...frame, currentEpoch: 0 })).toThrow();
  });
  test("strictly bounds project device-revocation incident notices", () => {
    const frame = {
      version: 1 as const,
      type: "project.device-revoked" as const,
      incidentId: crypto.randomUUID(),
      projectId: crypto.randomUUID(),
      revokedDeviceId: crypto.randomUUID(),
      currentEpoch: 4,
      promotedOwnerDeviceId: crypto.randomUUID(),
      cancelledTaskCount: 1,
      cancelledTasks: [{
        taskId: crypto.randomUUID(),
        targetDeviceId: crypto.randomUUID(),
      }],
      createdAt: "2030-01-01T00:00:00.000Z",
    };
    expect(projectDeviceRevokedFrameSchema.parse(frame)).toEqual(frame);
    expect(projectServerFrameSchema.parse(frame)).toEqual(frame);
    expect(projectDeviceRevokedFrameSchema.parse({
      ...frame,
      promotedOwnerDeviceId: null,
      cancelledTaskCount: 0,
      cancelledTasks: [],
    })).toMatchObject({ promotedOwnerDeviceId: null, cancelledTaskCount: 0, cancelledTasks: [] });
    expect(() => projectDeviceRevokedFrameSchema.parse({ ...frame, currentEpoch: 0 })).toThrow();
    expect(() => projectDeviceRevokedFrameSchema.parse({
      ...frame,
      cancelledTaskCount: 257,
      cancelledTasks: Array.from({ length: 257 }, () => frame.cancelledTasks[0]),
    })).toThrow();
    expect(() => projectDeviceRevokedFrameSchema.parse({
      ...frame,
      cancelledTaskCount: 0,
    })).toThrow();
    expect(() => projectDeviceRevokedFrameSchema.parse({
      ...frame,
      cancelledTaskCount: 0x8000_0000,
    })).toThrow();
    expect(() => projectDeviceRevokedFrameSchema.parse({ ...frame, extra: true })).toThrow();
  });
  test("strictly validates server presence snapshots, updates, and leaves", () => {
    const projectId = crypto.randomUUID();
    const deviceId = crypto.randomUUID();
    const updatedAt = "2030-01-01T00:00:00.000Z";
    const member = {
      deviceId,
      displayName: "Kai",
      chatId: projectId,
      cursor: null,
      caret: { anchor: 2, head: 7 },
      typing: true,
      updatedAt,
    };
    expect(presenceSnapshotFrameSchema.parse({
      version: 1, type: "presence.snapshot", projectId, chatId: projectId, members: [member],
    })).toMatchObject({ members: [member] });
    expect(presenceUpdateFrameSchema.parse({
      version: 1, type: "presence.update", projectId, ...member,
    })).toMatchObject(member);
    expect(presenceLeaveFrameSchema.parse({
      version: 1, type: "presence.leave", projectId, chatId: projectId, deviceId,
    })).toEqual({ version: 1, type: "presence.leave", projectId, chatId: projectId, deviceId });
    expect(presenceAcceptedFrameSchema.parse({
      version: 1, type: "presence.accepted", requestId: crypto.randomUUID(), projectId, chatId: projectId,
    })).toBeTruthy();
    expect(() => projectServerFrameSchema.parse({
      version: 1, type: "presence.update", projectId, ...member, extra: true,
    })).toThrow();
  });
  test("requires a bounded reason for agent cancellation", () => {
    const frame = {
      version: 1 as const,
      type: "agent.cancel" as const,
      requestId: crypto.randomUUID(),
      taskId: crypto.randomUUID(),
      reason: "Stop this run",
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(() => clientFrameSchema.parse({ ...frame, reason: " " })).toThrow();
  });
  test("bounds signed sanitized usage reports and binds all fields", () => {
    const report = usageReportSchema.parse({
      version: 1,
      deviceId: crypto.randomUUID(),
      revision: 2,
      updatedAt: "2030-01-01T00:00:00.000Z",
      requests: 4,
      inputTokens: 100,
      cachedInputTokens: 25,
      outputTokens: 50,
      reasoningOutputTokens: 10,
      activeAgents: 1,
      accountLabel: "Stephen Main",
      fiveHourPercent: 68,
      fiveHourResetAt: 1_900_000_000,
      customWindows: [{ label: "daily", percent: 41 }],
    });
    const frame = {
      version: 1 as const,
      type: "usage.report" as const,
      requestId: crypto.randomUUID(),
      report,
      signature: "s".repeat(64),
    };
    expect(clientFrameSchema.parse(frame)).toEqual(frame);
    expect(usageReportSigningTranscript(report)).not.toEqual(
      usageReportSigningTranscript({ ...report, outputTokens: report.outputTokens + 1 }),
    );
    expect(() => clientFrameSchema.parse({ ...frame, report: { ...report, activeAgents: 257 } })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, report: { ...report, customWindows: Array.from({ length: 9 }, (_, i) => ({ label: String(i), percent: 1 })) } })).toThrow();
    expect(() => clientFrameSchema.parse({ ...frame, extra: true })).toThrow();
  });
  test("WebSocket proof binds the server, device, request, and challenge", () => {
    const input = {
      serverFingerprint: "server-a",
      deviceId: "device-a",
      requestId: "request-a",
      challenge: "challenge-a",
    };
    const baseline = websocketAuthTranscript(input);
    for (const changed of [
      { ...input, serverFingerprint: "server-b" },
      { ...input, deviceId: "device-b" },
      { ...input, requestId: "request-b" },
      { ...input, challenge: "challenge-b" },
    ]) {
      expect(websocketAuthTranscript(changed)).not.toEqual(baseline);
    }
  });
});
