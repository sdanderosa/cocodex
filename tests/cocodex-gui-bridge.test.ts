import { describe, expect, test } from "bun:test";
import { mkdirSync, writeFileSync } from "node:fs";
import { PassThrough } from "node:stream";
import { join } from "node:path";
import { CoCodexGuiBridge } from "../src/cocodex/gui-bridge";
import { clientPaths } from "../src/cocodex/paths";

describe("CoCodex GUI bridge", () => {
  test("runs the resident session without exposing private ciphertext", async () => {
    const root = join(import.meta.dir, ".tmp", crypto.randomUUID());
    mkdirSync(root, { recursive: true });
    const paths = clientPaths(root);
    writeFileSync(paths.connection, JSON.stringify({
      version: 1,
      host: "server.example",
      port: 48120,
      serverFingerprint: "server-fingerprint",
      serverCertificatePem: "certificate",
      serverIdentityPublicKeyPem: "identity",
      deviceId: crypto.randomUUID(),
      displayName: "Stephen",
    }));

    const received: unknown[] = [];
    const runner = async (_paths: typeof paths, options: { input?: NodeJS.ReadableStream; output?: NodeJS.WritableStream }) => {
      const input = options.input as PassThrough;
      const output = options.output as PassThrough;
      output.write(`${JSON.stringify({ source: "session", state: "connected", deviceId: "device" })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: { type: "private.message", message: { messageId: "message", ciphertext: "secret-box" } },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "private",
        message: {
          messageId: "local-history-message",
          senderDeviceId: "sender",
          recipientDeviceId: "recipient",
          text: "safe local history text",
          clientCreatedAt: "2030-01-01T00:00:00.000Z",
          direction: "sent",
          restored: true,
          deliveryState: "rejected",
          rejectionReason: "Private-message device is not approved",
          localCiphertext: "LOCAL_HISTORY_CIPHERTEXT_CANARY",
          signature: "LOCAL_HISTORY_SIGNATURE_CANARY",
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "private-contacts",
        contacts: [{
          deviceId: "contact-device",
          displayName: "Kai",
          fingerprint: "AAAA-BBBB",
          trusted: true,
          projectCapable: true,
          deviceKeyCertificate: "PRIVATE_CONTACT_CERTIFICATE_CANARY",
          messagingPublicKeyPem: "PRIVATE_CONTACT_PUBLIC_KEY_CANARY",
        }],
      })}\n`);
      output.write(`${JSON.stringify({
        source: "project-invitations",
        invitations: [{
          invitationId: "project-invitation",
          projectId: "invited-project",
          projectName: "Nocturne Launcher",
          ownerDeviceId: "owner-device",
          ownerDisplayName: "Stephen",
          ownerFingerprint: "OWNER-FINGERPRINT",
          recipientDeviceId: "recipient-device",
          recipientDisplayName: "Kai",
          recipientFingerprint: "RECIPIENT-FINGERPRINT",
          keyEpoch: 1,
          issuedAt: "2030-01-01T00:00:00.000Z",
          expiresAt: "2030-01-02T00:00:00.000Z",
          status: "pending",
          direction: "incoming",
          trusted: true,
          actionable: true,
          envelope: { sealedProjectKey: "INVITATION_SEALED_KEY_CANARY" },
          ownerDeviceKeyCertificate: "INVITATION_CERTIFICATE_CANARY",
          ownerSignature: "INVITATION_SIGNATURE_CANARY",
          projectKey: "INVITATION_PLAINTEXT_KEY_CANARY",
        }],
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          type: "private.receipt",
          receipt: {
            sequence: 4,
            messageId: "message",
            senderDeviceId: "sender",
            recipientDeviceId: "recipient",
            receipt: "read",
            acceptedAt: "2030-01-01T00:00:00.000Z",
          },
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          type: "project.key.result",
          requestId: "key-request",
          projectId: "project",
          currentEpoch: 2,
          envelopes: [{
            sealedProjectKey: "SEALED_PROJECT_KEY_CANARY",
            recipientEncryptionPublicKeyPem: "PUBLIC_KEY_CANARY",
            senderSignature: "SIGNATURE_CANARY",
          }],
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          type: "project.created",
          requestId: "create-request",
          project: { id: "project", name: "Nocturne Launcher", role: "owner" },
          keyEpoch: 1,
          created: true,
          envelopes: [{ sealedProjectKey: "CREATE_SEALED_PROJECT_KEY_CANARY" }],
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          type: "future.secret.frame",
          nested: {
            deviceKeyCertificate: "DEVICE_CERTIFICATE_CANARY",
            ciphertext: "UNKNOWN_CIPHERTEXT_CANARY",
          },
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          type: "project.list.result",
          projects: [],
          sealedProjectKey: "MALFORMED_PROJECT_LIST_CANARY",
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          version: 1,
          type: "chat.event",
          projectId: "project",
          event: {
            sequence: 7,
            projectId: "project",
            eventId: "event",
            senderDeviceId: "device",
            content: "safe chat content",
            acceptedAt: "2030-01-01T00:00:00.000Z",
            workspaceRoot: "C:\\\\PRIVATE_WORKSPACE_CANARY",
            senderPublicKeyPem: "SENDER_KEY_CANARY",
            signature: "SIGNATURE_FIELD_CANARY",
            token: "TOKEN_FIELD_CANARY",
          },
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          type: "project.key.accepted",
          requestId: "accepted-request",
          projectId: "project",
          keyEpoch: 2,
          envelope: {
            sealedProjectKey: "ACCEPTED_SEALED_KEY_CANARY",
            recipientEncryptionPublicKeyPem: "ACCEPTED_PUBLIC_KEY_CANARY",
            senderSignature: "ACCEPTED_SIGNATURE_CANARY",
          },
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          version: 1,
          type: "project.device-revoked",
          incidentId: "incident-1",
          projectId: "project",
          revokedDeviceId: "revoked-device",
          currentEpoch: 3,
          promotedOwnerDeviceId: "promoted-owner",
          createdAt: "2030-01-01T00:00:00.000Z",
          cancelledTasks: [{ taskId: "task-1", targetDeviceId: "revoked-device" }],
          envelope: { sealedProjectKey: "REVOCATION_ENVELOPE_CANARY" },
          deviceKeyCertificate: "REVOCATION_CERTIFICATE_CANARY",
          privateKey: "REVOCATION_PRIVATE_KEY_CANARY",
        },
      })}\n`);
      output.write(`${JSON.stringify({
        source: "project-security",
        state: "device-revoked",
        projectId: "project",
        revokedDeviceId: "revoked-device",
        currentEpoch: 3,
        promotedOwnerDeviceId: "promoted-owner",
        incidentId: "incident-1",
        localDeviceRevoked: false,
        keyRotationRequired: true,
        envelope: { sealedProjectKey: "SECURITY_EVENT_ENVELOPE_CANARY" },
        certificate: "SECURITY_EVENT_CERTIFICATE_CANARY",
      })}\n`);
      output.write(`${JSON.stringify({
        source: "project-security",
        state: "locked",
        projectId: "locked-project",
        revision: 4,
        reason: "Owner review",
        lockedAt: "2030-01-01T00:00:00.000Z",
        lockedByDeviceId: "owner-device",
        signature: "PROJECT_LOCK_SIGNATURE_CANARY",
        cancelledTasks: [{ taskId: "PRIVATE_TASK_CANARY" }],
      })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: {
          version: 1,
          type: "project.lock.changed",
          transition: {
            operationId: "lock-operation",
            projectId: "raw-lock-project",
            action: "lock",
            actorDeviceId: "owner-device",
            reason: "Raw owner review",
            state: {
              state: "locked",
              revision: 7,
              lockedAt: "2030-01-01T00:00:00.000Z",
              lockedByDeviceId: "owner-device",
              reason: "Raw owner review",
            },
            createdAt: "2030-01-01T00:00:00.000Z",
            signature: "RAW_LOCK_SIGNATURE_CANARY",
            nonce: "RAW_LOCK_NONCE_CANARY",
          },
          cancelledTaskCount: 1,
          cancelledTasks: [{ taskId: "RAW_LOCK_TASK_CANARY", targetDeviceId: "host-device" }],
        },
      })}\n`);
      for await (const chunk of input) {
        for (const line of String(chunk).trim().split("\n")) {
          const command = JSON.parse(line);
          received.push(command);
          if (command.type === "shutdown") return;
        }
      }
    };
    const bridge = new CoCodexGuiBridge(paths, runner);
    const capability = bridge.issueCapability();
    expect(bridge.acceptsCapability(capability)).toBeTrue();
    expect(bridge.acceptsCapability("wrong-capability")).toBeFalse();

    expect(bridge.start().configured).toBe(true);
    await Bun.sleep(5);
    expect(bridge.status().state).toBe("connected");
    expect(bridge.command({ type: "project.list" }).accepted).toBe(true);
    expect(bridge.command({
      type: "project.lock.update",
      projectId: crypto.randomUUID(),
      action: "lock",
      expectedRevision: 0,
      reason: "Owner review",
    }).accepted).toBe(true);
    expect(() => bridge.command({
      type: "project.lock.update",
      projectId: crypto.randomUUID(),
      action: "unlock",
      signature: "RENDERER_SIGNATURE_CANARY",
    })).toThrow("Invalid project lock command");
    expect(bridge.command({
      type: "project.create",
      projectId: crypto.randomUUID(),
      name: "Nocturne Launcher",
      memberDeviceIds: [],
    }).accepted).toBe(true);
    expect(bridge.command({ type: "project.invite.list" }).accepted).toBe(true);
    expect(bridge.command({
      type: "project.invite.create",
      projectId: "invited-project",
      recipientDeviceId: "contact-device",
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "project.invite.respond",
      invitationId: "project-invitation",
      decision: "accept",
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "project.invite.cancel",
      invitationId: "project-invitation",
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "context.get",
      projectId: crypto.randomUUID(),
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "context.update",
      projectId: crypto.randomUUID(),
      expectedRevision: 0,
      finalGoal: "Keep the shared goal authoritative",
      context: { source: "gui-test" },
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "usage.get",
      projectId: crypto.randomUUID(),
    }).accepted).toBe(true);
    const memberProjectId = crypto.randomUUID();
    const removedDeviceId = crypto.randomUUID();
    expect(bridge.command({
      type: "project.member.list",
      projectId: memberProjectId,
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "project.member.remove-and-rotate",
      projectId: memberProjectId,
      deviceId: removedDeviceId,
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "agent.list",
      projectId: crypto.randomUUID(),
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "agent.configure",
      projectId: crypto.randomUUID(),
      name: "Lucas",
      workspaceRoot: root,
      trustedRequesterDeviceId: crypto.randomUUID(),
      trustedRequesterFingerprint: "trusted-fingerprint-1234",
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "agent.task.list",
      projectId: crypto.randomUUID(),
    }).accepted).toBe(true);
    const referenceProjectId = crypto.randomUUID();
    const referenceArtifactId = crypto.randomUUID();
    expect(bridge.command({
      type: "project.file-reference.list",
      projectId: referenceProjectId,
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "project.file-reference.publish",
      projectId: referenceProjectId,
      artifactId: referenceArtifactId,
      workspaceRoot: root,
      path: "reports/result.txt",
      workspaceMode: "shared",
      workspaceRef: "main",
      mediaType: "text/plain",
    }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.approval", taskId: "task-1", approved: true }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.safety.status" }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.emergency.stop", reason: "GUI safety test" }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.emergency.resume" }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.full-computer.enable", confirm: true }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.full-computer.disable" }).accepted).toBe(true);
    expect(bridge.command({ type: "private.read", messageId: "message" }).accepted).toBe(true);
    expect(bridge.command({
      type: "private.send",
      recipientDeviceId: "contact-device",
      text: "safe message",
    }).accepted).toBe(true);
    expect(() => bridge.command({
      type: "private.send",
      recipientDeviceId: "contact-device",
      recipientKeyCertificate: "renderer-supplied-certificate",
      text: "unsafe message",
    })).toThrow("resolve private contacts");
    bridge.stop();
    await Bun.sleep(5);

    expect(received.some((value: any) => value.type === "project.list")).toBe(true);
    expect(received.some((value: any) => value.type === "project.create"
      && value.name === "Nocturne Launcher")).toBe(true);
    expect(received.some((value: any) => value.type === "project.invite.list")).toBe(true);
    expect(received.some((value: any) => value.type === "project.invite.create"
      && value.recipientDeviceId === "contact-device")).toBe(true);
    expect(received.some((value: any) => value.type === "project.invite.respond"
      && value.decision === "accept")).toBe(true);
    expect(received.some((value: any) => value.type === "project.invite.cancel")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.list")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.configure" && value.name === "Lucas")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.task.list")).toBe(true);
    expect(received.some((value: any) => value.type === "project.file-reference.list"
      && value.projectId === referenceProjectId)).toBe(true);
    expect(received.some((value: any) => value.type === "project.file-reference.publish"
      && value.artifactId === referenceArtifactId && value.path === "reports/result.txt")).toBe(true);
    expect(received.some((value: any) => value.type === "context.get")).toBe(true);
    expect(received.some((value: any) => value.type === "context.update" && value.finalGoal === "Keep the shared goal authoritative")).toBe(true);
    expect(received.some((value: any) => value.type === "usage.get")).toBe(true);
    expect(received.some((value: any) => value.type === "project.member.list"
      && value.projectId === memberProjectId)).toBe(true);
    expect(received.some((value: any) => value.type === "project.member.remove-and-rotate"
      && value.deviceId === removedDeviceId)).toBe(true);
    expect(received.some((value: any) => value.type === "agent.approval" && value.approved === true)).toBe(true);
    expect(received.some((value: any) => value.type === "agent.safety.status")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.emergency.stop")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.emergency.resume")).toBe(true);
    const privateEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.frame?.type === "private.message");
    expect(JSON.stringify(privateEvent)).not.toContain("secret-box");
    const localHistoryEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.message?.messageId === "local-history-message");
    expect(localHistoryEvent?.value).toEqual({
      source: "private",
      message: {
        messageId: "local-history-message",
        senderDeviceId: "sender",
        recipientDeviceId: "recipient",
        text: "safe local history text",
        clientCreatedAt: "2030-01-01T00:00:00.000Z",
        direction: "sent",
        restored: true,
        deliveryState: "rejected",
        rejectionReason: "Private-message device is not approved",
      },
    });
    const privateReceiptEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.frame?.type === "private.receipt");
    expect(privateReceiptEvent?.value).toEqual({
      source: "server",
      frame: {
        type: "private.receipt",
        receipt: {
          sequence: 4,
          messageId: "message",
          senderDeviceId: "sender",
          recipientDeviceId: "recipient",
          receipt: "read",
          acceptedAt: "2030-01-01T00:00:00.000Z",
        },
      },
    });
    const privateContactsEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.source === "private-contacts");
    expect(privateContactsEvent?.value).toEqual({
      source: "private-contacts",
      contacts: [{
        deviceId: "contact-device",
        displayName: "Kai",
        fingerprint: "AAAA-BBBB",
        trusted: true,
        projectCapable: true,
      }],
    });
    const projectInvitationsEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.source === "project-invitations");
    expect(projectInvitationsEvent?.value).toEqual({
      source: "project-invitations",
      invitations: [{
        invitationId: "project-invitation",
        projectId: "invited-project",
        projectName: "Nocturne Launcher",
        ownerDeviceId: "owner-device",
        ownerDisplayName: "Stephen",
        ownerFingerprint: "OWNER-FINGERPRINT",
        recipientDeviceId: "recipient-device",
        recipientDisplayName: "Kai",
        recipientFingerprint: "RECIPIENT-FINGERPRINT",
        keyEpoch: 1,
        issuedAt: "2030-01-01T00:00:00.000Z",
        expiresAt: "2030-01-02T00:00:00.000Z",
        status: "pending",
        direction: "incoming",
        trusted: true,
        actionable: true,
      }],
    });
    expect(JSON.stringify(projectInvitationsEvent)).not.toContain("INVITATION_SEALED_KEY_CANARY");
    expect(JSON.stringify(projectInvitationsEvent)).not.toContain("INVITATION_CERTIFICATE_CANARY");
    expect(JSON.stringify(projectInvitationsEvent)).not.toContain("INVITATION_SIGNATURE_CANARY");
    expect(JSON.stringify(projectInvitationsEvent)).not.toContain("INVITATION_PLAINTEXT_KEY_CANARY");
    const keyEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.frame?.type === "project.key.result");
    expect(keyEvent?.value).toEqual({
      source: "server",
      frame: {
        type: "project.key.result",
        requestId: "key-request",
        projectId: "project",
        currentEpoch: 2,
      },
    });
    expect(JSON.stringify(keyEvent)).not.toContain("SEALED_PROJECT_KEY_CANARY");
    expect(JSON.stringify(keyEvent)).not.toContain("PUBLIC_KEY_CANARY");
    expect(JSON.stringify(keyEvent)).not.toContain("SIGNATURE_CANARY");
    const acceptedKeyEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.frame?.type === "project.key.accepted");
    expect(acceptedKeyEvent?.value).toEqual({
      source: "server",
      frame: {
        type: "project.key.accepted",
        requestId: "accepted-request",
        projectId: "project",
        keyEpoch: 2,
      },
    });
    expect(JSON.stringify(acceptedKeyEvent)).not.toContain("ACCEPTED_SEALED_KEY_CANARY");
    expect(JSON.stringify(acceptedKeyEvent)).not.toContain("ACCEPTED_PUBLIC_KEY_CANARY");
    expect(JSON.stringify(acceptedKeyEvent)).not.toContain("ACCEPTED_SIGNATURE_CANARY");
    const revokedEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.frame?.type === "project.device-revoked");
    expect(revokedEvent?.value).toEqual({
      source: "server",
      frame: {
        type: "project.device-revoked",
        incidentId: "incident-1",
        projectId: "project",
        revokedDeviceId: "revoked-device",
        currentEpoch: 3,
        promotedOwnerDeviceId: "promoted-owner",
        createdAt: "2030-01-01T00:00:00.000Z",
      },
    });
    expect(JSON.stringify(revokedEvent)).not.toContain("REVOCATION_ENVELOPE_CANARY");
    expect(JSON.stringify(revokedEvent)).not.toContain("REVOCATION_CERTIFICATE_CANARY");
    expect(JSON.stringify(revokedEvent)).not.toContain("REVOCATION_PRIVATE_KEY_CANARY");
    const securityEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.source === "project-security");
    expect(securityEvent?.value).toEqual({
      source: "project-security",
      state: "device-revoked",
      projectId: "project",
      revokedDeviceId: "revoked-device",
      currentEpoch: 3,
      promotedOwnerDeviceId: "promoted-owner",
      incidentId: "incident-1",
      keyRotationRequired: true,
    });
    expect(JSON.stringify(securityEvent)).not.toContain("SECURITY_EVENT_ENVELOPE_CANARY");
    expect(JSON.stringify(securityEvent)).not.toContain("SECURITY_EVENT_CERTIFICATE_CANARY");
    const lockSecurityEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.source === "project-security"
        && event.value?.state === "locked");
    expect(lockSecurityEvent?.value).toEqual({
      source: "project-security",
      state: "locked",
      projectId: "locked-project",
      revision: 4,
      reason: "Owner review",
      lockedAt: "2030-01-01T00:00:00.000Z",
      lockedByDeviceId: "owner-device",
    });
    expect(JSON.stringify(lockSecurityEvent)).not.toContain("PROJECT_LOCK_SIGNATURE_CANARY");
    expect(JSON.stringify(lockSecurityEvent)).not.toContain("PRIVATE_TASK_CANARY");
    const rawLockEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.frame?.type === "project.lock.changed");
    expect(rawLockEvent?.value).toMatchObject({
      source: "server",
      frame: {
        version: 1,
        type: "project.lock.changed",
        transition: {
          operationId: "lock-operation",
          projectId: "raw-lock-project",
          action: "lock",
          reason: "Raw owner review",
          state: {
            state: "locked",
            revision: 7,
            lockedAt: "2030-01-01T00:00:00.000Z",
            lockedByDeviceId: "owner-device",
            reason: "Raw owner review",
          },
          createdAt: "2030-01-01T00:00:00.000Z",
        },
        cancelledTaskCount: 1,
      },
    });
    expect(JSON.stringify(rawLockEvent)).not.toContain("RAW_LOCK_SIGNATURE_CANARY");
    expect(JSON.stringify(rawLockEvent)).not.toContain("RAW_LOCK_NONCE_CANARY");
    expect(JSON.stringify(rawLockEvent)).not.toContain("RAW_LOCK_TASK_CANARY");
    const projectCreatedEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.frame?.type === "project.created");
    expect(projectCreatedEvent?.value).toMatchObject({
      source: "server",
      frame: {
        type: "project.created",
        project: { id: "project", name: "Nocturne Launcher", role: "owner" },
        keyEpoch: 1,
        created: true,
      },
    });
    expect(JSON.stringify(projectCreatedEvent)).not.toContain("CREATE_SEALED_PROJECT_KEY_CANARY");
    const rendererEvents = JSON.stringify(bridge.eventsAfter(0).events);
    expect(rendererEvents).not.toContain("DEVICE_CERTIFICATE_CANARY");
    expect(rendererEvents).not.toContain("UNKNOWN_CIPHERTEXT_CANARY");
    expect(rendererEvents).not.toContain("MALFORMED_PROJECT_LIST_CANARY");
    expect(rendererEvents).not.toContain("PRIVATE_CONTACT_CERTIFICATE_CANARY");
    expect(rendererEvents).not.toContain("PRIVATE_CONTACT_PUBLIC_KEY_CANARY");
    expect(rendererEvents).not.toContain("PRIVATE_WORKSPACE_CANARY");
    expect(rendererEvents).not.toContain("SENDER_KEY_CANARY");
    expect(rendererEvents).not.toContain("SIGNATURE_FIELD_CANARY");
    expect(rendererEvents).not.toContain("TOKEN_FIELD_CANARY");
    expect(rendererEvents).not.toContain("LOCAL_HISTORY_CIPHERTEXT_CANARY");
    expect(rendererEvents).not.toContain("LOCAL_HISTORY_SIGNATURE_CANARY");
    expect(rendererEvents).toContain("safe local history text");
    expect(rendererEvents).toContain("safe chat content");
    expect(rendererEvents).toContain("Unsupported server frame withheld");
  });
});
