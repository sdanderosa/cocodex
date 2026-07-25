import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  agentEncryptedDispatchSigningTranscript,
  agentDispatchSigningTranscript,
  agentRequestSigningTranscript,
  publicKeyFingerprint,
  type AgentTask,
} from "@cocodex/protocol";
import { attachLocalAgentBridge } from "../src/cocodex/agent-bridge";
import { beginAgentTask, pendingAgentResults } from "../src/cocodex/agent-journal";

class AcknowledgingSocket extends EventTarget {
  readonly sent: Array<Record<string, unknown>> = [];

  send(data: string): void {
    const frame = JSON.parse(data) as Record<string, unknown>;
    this.sent.push(frame);
    if (frame.type !== "agent.result" && frame.type !== "project.agent.result") return;
    queueMicrotask(() => this.dispatchEvent(new MessageEvent("message", {
      data: JSON.stringify({
        version: 1,
        type: "agent.result.accepted",
        requestId: frame.requestId,
        taskId: frame.taskId,
        eventId: frame.eventId,
      }),
    })));
  }
}

function signedTask(
  localDeviceId: string,
  status: "queued" | "running" = "running",
  dependencies: string[] = [],
): {
  task: AgentTask;
  requesterFingerprint: string;
  serverPublicKeyPem: string;
} {
  const requester = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const server = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const taskId = randomUUID();
  const projectId = randomUUID();
  const requesterDeviceId = randomUUID();
  const issuedAt = new Date(Date.now() - (status === "running" ? 120_000 : 0)).toISOString();
  const expiresAt = new Date(Date.now() + (status === "running" ? -60_000 : 60_000)).toISOString();
  const nonce = randomUUID();
  const request = {
    taskId,
    projectId,
    agentId: "local-codex",
    prompt: "Continue the interrupted task.",
    nonce,
    issuedAt,
    expiresAt,
    dependencies,
  };
  const requesterSignature = sign(
    null,
    agentRequestSigningTranscript(request),
    requester.privateKey,
  ).toString("base64url");
  const dispatch = {
    ...request,
    requesterDeviceId,
    targetDeviceId: localDeviceId,
    requesterSignature,
    requesterPublicKeyPem: requester.publicKey,
  };
  const serverSignature = sign(
    null,
    agentDispatchSigningTranscript(dispatch),
    server.privateKey,
  ).toString("base64url");
  return {
    task: {
      id: taskId,
      projectId,
      requesterDeviceId,
      targetDeviceId: localDeviceId,
      agentId: request.agentId,
      prompt: request.prompt,
      nonce,
      issuedAt,
      expiresAt,
      requesterSignature,
      requesterPublicKeyPem: requester.publicKey,
      serverSignature,
      status,
      acceptedAt: issuedAt,
      dependencies,
    },
    requesterFingerprint: publicKeyFingerprint(requester.publicKey),
    serverPublicKeyPem: server.publicKey,
  };
}

function signedEncryptedTask(localDeviceId: string): {
  task: any;
  requesterFingerprint: string;
  serverPublicKeyPem: string;
} {
  const requester = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const server = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const taskId = randomUUID();
  const projectId = randomUUID();
  const requesterDeviceId = randomUUID();
  const issuedAt = new Date(Date.now() - 10_000).toISOString();
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  const nonce = "N".repeat(43);
  const promptEnvelope = {
    version: 1 as const,
    projectId,
    keyEpoch: 1,
    recordType: "task" as const,
    recordId: taskId,
    nonce: Buffer.alloc(24, 1).toString("base64url"),
    ciphertext: Buffer.alloc(16, 2).toString("base64url"),
    senderDeviceId: requesterDeviceId,
    senderPublicKeyPem: requester.publicKey,
    signature: Buffer.alloc(64, 3).toString("base64url"),
  };
  const dispatch = {
    taskId,
    projectId,
    agentId: "local-codex",
    nonce,
    issuedAt,
    expiresAt,
    dependencies: [],
    requesterDeviceId,
    targetDeviceId: localDeviceId,
    envelopeProjectId: projectId,
    envelopeKeyEpoch: 1,
    envelopeRecordId: taskId,
    envelopeNonce: promptEnvelope.nonce,
    envelopeCiphertext: promptEnvelope.ciphertext,
    envelopeSenderDeviceId: requesterDeviceId,
    envelopeSenderPublicKeyPem: requester.publicKey,
    envelopeSignature: promptEnvelope.signature,
  };
  const serverSignature = sign(null, agentEncryptedDispatchSigningTranscript(dispatch), server.privateKey)
    .toString("base64url");
  return {
    task: {
      id: taskId,
      projectId,
      requesterDeviceId,
      targetDeviceId: localDeviceId,
      agentId: dispatch.agentId,
      prompt: "[encrypted]",
      promptEnvelope,
      nonce,
      issuedAt,
      expiresAt,
      dependencies: [],
      requesterSignature: promptEnvelope.signature,
      requesterPublicKeyPem: requester.publicKey,
      serverSignature,
      status: "queued",
      acceptedAt: issuedAt,
    },
    requesterFingerprint: publicKeyFingerprint(requester.publicKey),
    serverPublicKeyPem: server.publicKey,
  };
}

describe("CoCodex local agent crash recovery", () => {
  test("verifies plaintext dependency IDs in both signed task transcripts", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-dependency-"));
    const journalPath = join(root, "agent-journal.json");
    const localDeviceId = randomUUID();
    const fixture = signedTask(localDeviceId, "queued", [randomUUID()]);
    const socket = new AcknowledgingSocket();
    let executeCount = 0;
    const detach = attachLocalAgentBridge(socket as unknown as WebSocket, {
      authorize: () => true,
      async *execute() {
        executeCount += 1;
        yield "Dependency task ran.";
      },
    }, {
      localDeviceId,
      serverPublicKeyPem: fixture.serverPublicKeyPem,
      trustedRequesterFingerprints: new Map([
        [fixture.task.requesterDeviceId, fixture.requesterFingerprint],
      ]),
      journalPath,
    });
    try {
      socket.dispatchEvent(new MessageEvent("message", {
        data: JSON.stringify({ version: 1, type: "agent.task", task: fixture.task }),
      }));
      for (let attempt = 0; attempt < 100
        && !socket.sent.some(frame => frame.type === "agent.result" && frame.final === true); attempt += 1) {
        await Bun.sleep(5);
      }
      expect(socket.sent.find(frame => frame.type === "agent.result" && frame.final === true)).toMatchObject({
        taskId: fixture.task.id,
        final: true,
        status: "completed",
        content: "Dependency task ran.",
      });
      expect(executeCount).toBe(1);
    } finally {
      await detach();
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("fails a server-running task closed after reconnect instead of executing it twice", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-recovery-"));
    const journalPath = join(root, "agent-journal.json");
    const localDeviceId = randomUUID();
    const fixture = signedTask(localDeviceId);
    const socket = new AcknowledgingSocket();
    let executeCount = 0;
    const detach = attachLocalAgentBridge(socket as unknown as WebSocket, {
      authorize: () => true,
      async *execute() {
        executeCount += 1;
        yield "This must never run.";
      },
    }, {
      localDeviceId,
      serverPublicKeyPem: fixture.serverPublicKeyPem,
      trustedRequesterFingerprints: new Map([
        [fixture.task.requesterDeviceId, fixture.requesterFingerprint],
      ]),
      journalPath,
    });
    try {
      socket.dispatchEvent(new MessageEvent("message", {
        data: JSON.stringify({ version: 1, type: "agent.task", task: fixture.task }),
      }));
      for (let attempt = 0; attempt < 100
        && !socket.sent.some(frame => frame.type === "agent.result"); attempt += 1) {
        await Bun.sleep(5);
      }
      const result = socket.sent.find(frame => frame.type === "agent.result");
      expect(result).toMatchObject({
        taskId: fixture.task.id,
        final: true,
        status: "failed",
        content: "Local agent execution was interrupted and was not rerun.",
      });
      for (let attempt = 0; attempt < 100 && pendingAgentResults(journalPath, fixture.task.id).length; attempt += 1) {
        await Bun.sleep(5);
      }
      expect(executeCount).toBe(0);
      expect(beginAgentTask(journalPath, fixture.task.id)).toBe("finished");
      expect(pendingAgentResults(journalPath, fixture.task.id)).toEqual([]);
    } finally {
      await detach();
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("aborts and awaits active local execution when the bridge disconnects", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-cancel-"));
    const journalPath = join(root, "agent-journal.json");
    const localDeviceId = randomUUID();
    const fixture = signedTask(localDeviceId, "queued");
    const socket = new AcknowledgingSocket();
    let started = false;
    let aborted = false;
    const detach = attachLocalAgentBridge(socket as unknown as WebSocket, {
      authorize: () => true,
      async *execute(_task, signal) {
        started = true;
        await new Promise<void>(resolve => {
          if (signal?.aborted) resolve();
          else signal?.addEventListener("abort", () => resolve(), { once: true });
        });
        aborted = Boolean(signal?.aborted);
      },
    }, {
      localDeviceId,
      serverPublicKeyPem: fixture.serverPublicKeyPem,
      trustedRequesterFingerprints: new Map([
        [fixture.task.requesterDeviceId, fixture.requesterFingerprint],
      ]),
      journalPath,
    });
    try {
      socket.dispatchEvent(new MessageEvent("message", {
        data: JSON.stringify({ version: 1, type: "agent.task", task: fixture.task }),
      }));
      for (let attempt = 0; attempt < 100 && !started; attempt += 1) await Bun.sleep(5);
      expect(started).toBeTrue();
      await detach();
      expect(aborted).toBeTrue();
      expect(beginAgentTask(journalPath, fixture.task.id)).toBe("started");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("aborts active local execution when the server delivers an authorized cancellation", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-server-cancel-"));
    const journalPath = join(root, "agent-journal.json");
    const localDeviceId = randomUUID();
    const fixture = signedTask(localDeviceId, "queued");
    const socket = new AcknowledgingSocket();
    let started = false;
    let aborted = false;
    const detach = attachLocalAgentBridge(socket as unknown as WebSocket, {
      authorize: () => true,
      async *execute(_task, signal) {
        started = true;
        await new Promise<void>(resolve => {
          if (signal?.aborted) resolve();
          else signal?.addEventListener("abort", () => resolve(), { once: true });
        });
        aborted = Boolean(signal?.aborted);
      },
    }, {
      localDeviceId,
      serverPublicKeyPem: fixture.serverPublicKeyPem,
      trustedRequesterFingerprints: new Map([
        [fixture.task.requesterDeviceId, fixture.requesterFingerprint],
      ]),
      journalPath,
    });
    try {
      socket.dispatchEvent(new MessageEvent("message", {
        data: JSON.stringify({ version: 1, type: "agent.task", task: fixture.task }),
      }));
      for (let attempt = 0; attempt < 100 && !started; attempt += 1) await Bun.sleep(5);
      expect(started).toBeTrue();
      socket.dispatchEvent(new MessageEvent("message", {
        data: JSON.stringify({
          version: 1,
          type: "agent.cancel",
          taskId: fixture.task.id,
          reason: "Requester cancelled.",
        }),
      }));
      for (let attempt = 0; attempt < 100 && !aborted; attempt += 1) await Bun.sleep(5);
      expect(aborted).toBeTrue();
      expect(socket.sent.some(frame => frame.type === "agent.result" && frame.status === "completed")).toBeFalse();
    } finally {
      await detach();
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("returns an encrypted terminal result when an encrypted task is cancelled", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-encrypted-cancel-"));
    const journalPath = join(root, "agent-journal.json");
    const localDeviceId = randomUUID();
    const fixture = signedEncryptedTask(localDeviceId);
    const socket = new AcknowledgingSocket();
    let started = false;
    let aborted = false;
    const detach = attachLocalAgentBridge(socket as unknown as WebSocket, {
      authorize: () => true,
      async *execute(_task, signal) {
        started = true;
        await new Promise<void>(resolve => {
          if (signal?.aborted) resolve();
          else signal?.addEventListener("abort", () => resolve(), { once: true });
        });
        aborted = Boolean(signal?.aborted);
      },
    }, {
      localDeviceId,
      serverPublicKeyPem: fixture.serverPublicKeyPem,
      trustedRequesterFingerprints: new Map([[fixture.task.requesterDeviceId, fixture.requesterFingerprint]]),
      journalPath,
      decryptTaskPrompt: async () => "encrypted cancellation prompt",
      encryptResult: async result => ({
        version: 1,
        projectId: fixture.task.projectId,
        keyEpoch: 1,
        recordType: "agent-response",
        recordId: result.eventId,
        nonce: Buffer.alloc(24, 4).toString("base64url"),
        ciphertext: Buffer.alloc(16, 5).toString("base64url"),
        senderDeviceId: localDeviceId,
        senderPublicKeyPem: "-----BEGIN PUBLIC KEY-----\ninvalid-test-key\n-----END PUBLIC KEY-----\n",
        signature: Buffer.alloc(64, 6).toString("base64url"),
      }),
    });
    try {
      socket.dispatchEvent(new MessageEvent("message", {
        data: JSON.stringify({ version: 1, type: "project.agent.task", task: fixture.task }),
      }));
      for (let attempt = 0; attempt < 100 && !started; attempt += 1) await Bun.sleep(5);
      expect(started).toBeTrue();
      socket.dispatchEvent(new MessageEvent("message", {
        data: JSON.stringify({ version: 1, type: "agent.cancel", taskId: fixture.task.id, reason: "Stop encrypted task." }),
      }));
      for (let attempt = 0; attempt < 100 && !aborted; attempt += 1) await Bun.sleep(5);
      expect(aborted).toBeTrue();
      for (let attempt = 0; attempt < 100
        && !socket.sent.some(frame => frame.type === "project.agent.result"); attempt += 1) await Bun.sleep(5);
      const result = socket.sent.find(frame => frame.type === "project.agent.result");
      expect(result).toMatchObject({ taskId: fixture.task.id, final: true, status: "failed" });
      expect(result?.content).toBeUndefined();
      expect(result?.envelope).toMatchObject({ recordType: "agent-response", recordId: expect.any(String) });
    } finally {
      await detach();
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("emergency stop aborts an active local task and blocks queued work", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-emergency-stop-"));
    const journalPath = join(root, "agent-journal.json");
    const localDeviceId = randomUUID();
    const fixture = signedTask(localDeviceId, "queued");
    const socket = new AcknowledgingSocket();
    let started = false;
    let aborted = false;
    const detach = attachLocalAgentBridge(socket as unknown as WebSocket, {
      authorize: () => true,
      async *execute(_task, signal) {
        started = true;
        await new Promise<void>(resolve => {
          if (signal?.aborted) resolve();
          else signal?.addEventListener("abort", () => resolve(), { once: true });
        });
        aborted = Boolean(signal?.aborted);
      },
    }, {
      localDeviceId,
      serverPublicKeyPem: fixture.serverPublicKeyPem,
      trustedRequesterFingerprints: new Map([[fixture.task.requesterDeviceId, fixture.requesterFingerprint]]),
      journalPath,
      isExecutionAllowed: () => !detach.isEmergencyStopped(),
    });
    try {
      socket.dispatchEvent(new MessageEvent("message", {
        data: JSON.stringify({ version: 1, type: "agent.task", task: fixture.task }),
      }));
      for (let attempt = 0; attempt < 100 && !started; attempt += 1) await Bun.sleep(5);
      expect(started).toBeTrue();
      detach.emergencyStop("Host incident response");
      for (let attempt = 0; attempt < 100 && !aborted; attempt += 1) await Bun.sleep(5);
      expect(aborted).toBeTrue();
      expect(detach.isEmergencyStopped()).toBeTrue();
      detach.resume();
      expect(detach.isEmergencyStopped()).toBeFalse();
    } finally {
      await detach();
      rmSync(root, { recursive: true, force: true });
    }
  });
});
