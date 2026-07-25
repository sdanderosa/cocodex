import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
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
    if (frame.type !== "agent.result") return;
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

function signedRunningTask(localDeviceId: string): {
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
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  const nonce = randomUUID();
  const request = {
    taskId,
    projectId,
    agentId: "local-codex",
    prompt: "Continue the interrupted task.",
    nonce,
    issuedAt,
    expiresAt,
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
      status: "running",
      acceptedAt: issuedAt,
    },
    requesterFingerprint: publicKeyFingerprint(requester.publicKey),
    serverPublicKeyPem: server.publicKey,
  };
}

describe("CoCodex local agent crash recovery", () => {
  test("fails a server-running task closed after reconnect instead of executing it twice", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-recovery-"));
    const journalPath = join(root, "agent-journal.json");
    const localDeviceId = randomUUID();
    const fixture = signedRunningTask(localDeviceId);
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
      detach();
      rmSync(root, { recursive: true, force: true });
    }
  });
});