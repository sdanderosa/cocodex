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
    bridge.stop();
    await Bun.sleep(5);

    expect(received.some((value: any) => value.type === "project.list")).toBe(true);
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
    const rendererEvents = JSON.stringify(bridge.eventsAfter(0).events);
    expect(rendererEvents).not.toContain("DEVICE_CERTIFICATE_CANARY");
    expect(rendererEvents).not.toContain("UNKNOWN_CIPHERTEXT_CANARY");
    expect(rendererEvents).not.toContain("MALFORMED_PROJECT_LIST_CANARY");
    expect(rendererEvents).not.toContain("PRIVATE_WORKSPACE_CANARY");
    expect(rendererEvents).not.toContain("SENDER_KEY_CANARY");
    expect(rendererEvents).not.toContain("SIGNATURE_FIELD_CANARY");
    expect(rendererEvents).not.toContain("TOKEN_FIELD_CANARY");
    expect(rendererEvents).toContain("safe chat content");
    expect(rendererEvents).toContain("Unsupported server frame withheld");
  });
});
