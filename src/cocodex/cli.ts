#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";
import {
  connectAuthenticatedClient,
  enrollClient,
  loadClientConnection,
  maintainAuthenticatedClient,
  sendAgentRequest,
} from "./client";
import { attachLocalAgentBridge } from "./agent-bridge";
import { CodexAgentAdapter } from "./codex-agent-adapter";
import { loadLocalAgentPolicy, saveLocalAgentPolicy } from "./agent-policy";
import { clientPaths } from "./paths";
import { loadOrCreateClientIdentity } from "./identity";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "./private-messaging";
import { enqueueDurableEvent, flushDurableOutbox } from "./outbox";
import { runJsonLineSession } from "./session";
import { trustDevice } from "./trusted-devices";

function option(name: string): string | undefined {
  const index = Bun.argv.indexOf(name);
  return index >= 0 ? Bun.argv[index + 1] : undefined;
}

function required(name: string): string {
  const value = option(name);
  if (!value) throw new Error(`Missing required option ${name}`);
  return value;
}

function nextFrame(socket: WebSocket, type: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`Timed out waiting for ${type}`)), 10 * 60_000);
    const listener = (event: MessageEvent) => {
      const frame = JSON.parse(String(event.data)) as Record<string, unknown>;
      if (frame.type === "error") {
        clearTimeout(timeout);
        socket.removeEventListener("message", listener);
        reject(new Error(String(frame.error)));
      } else if (frame.type === type) {
        clearTimeout(timeout);
        socket.removeEventListener("message", listener);
        resolve(frame);
      }
    };
    socket.addEventListener("message", listener);
  });
}
async function run(): Promise<void> {
  const paths = clientPaths(option("--state-root"));
  switch (Bun.argv[2] ?? "help") {
    case "enroll": {
      const connection = await enrollClient(required("--invite"), required("--name"), paths);
      console.log(JSON.stringify({
        enrolled: true,
        deviceId: connection.deviceId,
        approvalRequired: true,
      }));
      return;
    }
    case "status":
      console.log(JSON.stringify(loadClientConnection(paths), null, 2));
      return;
    case "configure-agent": {
      const trustedDeviceId = required("--trust-device");
      const policy = saveLocalAgentPolicy(paths.agentPolicy, {
        version: 1,
        projectId: required("--project"),
        agentId: required("--agent"),
        workspaceRoot: required("--workspace"),
        sandbox: option("--sandbox") === "read-only" ? "read-only" : "workspace-write",
        trustedRequesterFingerprints: {
          [trustedDeviceId]: required("--trust-fingerprint"),
        },
      });
      trustDevice(paths.trustedDevices, trustedDeviceId, required("--trust-fingerprint"));
      console.log(JSON.stringify({ configured: true, projectId: policy.projectId, agentId: policy.agentId }));
      return;
    }
    case "private-send": {
      const connection = loadClientConnection(paths);
      const identity = loadOrCreateClientIdentity(paths);
      const recipientDeviceId = required("--recipient-device");
      const messageId = crypto.randomUUID();
      const clientCreatedAt = new Date().toISOString();
      const ciphertext = await sealSignedPrivateMessage({
        messageId,
        senderDeviceId: connection.deviceId,
        recipientDeviceId,
        text: required("--message"),
        clientCreatedAt,
      }, identity.privateKeyPem, identity.publicKeyPem, readFileSync(required("--recipient-key"), "utf8"));
      enqueueDurableEvent(paths, {
        version: 1, type: "private.send", requestId: crypto.randomUUID(), messageId,
        recipientDeviceId, ciphertext, clientCreatedAt,
      });
      try {
        const socket = await connectAuthenticatedClient(paths);
        const flushedEvents = await flushDurableOutbox(socket, paths);
        socket.close();
        console.log(JSON.stringify({ queued: false, flushedEvents, messageId }));
      } catch {
        console.log(JSON.stringify({ queued: true, messageId }));
      }
      return;
    }
    case "private-listen": {
      const socket = await connectAuthenticatedClient(paths);
      const connection = loadClientConnection(paths);
      const identity = loadOrCreateClientIdentity(paths);
      const expectedFingerprint = required("--trust-fingerprint");
      const render = async (message: any) => {
        if (message.recipientDeviceId !== connection.deviceId) return;
        const opened = await openSignedPrivateMessage(
          message.ciphertext, identity.messagingPrivateKeyPem, identity.messagingPublicKeyPem, message, expectedFingerprint,
        );
        console.log(JSON.stringify({ ...message, ciphertext: undefined, text: opened.text }));
      };
      const snapshot = nextFrame(socket, "private.snapshot");
      socket.send(JSON.stringify({
        version: 1, type: "private.subscribe", requestId: crypto.randomUUID(),
        afterSequence: Number(option("--after") ?? "0"),
      }));
      for (const message of ((await snapshot).messages as any[])) await render(message);
      socket.addEventListener("message", event => {
        const frame = JSON.parse(String(event.data)) as any;
        if (frame.type === "private.message") void render(frame.message);
      });
      await new Promise<void>(resolve => socket.addEventListener("close", () => resolve(), { once: true }));
      return;
    }
    case "chat-send": {
      const eventId = crypto.randomUUID();
      enqueueDurableEvent(paths, {
        version: 1,
        type: "chat.send",
        requestId: crypto.randomUUID(),
        projectId: required("--project"),
        eventId,
        content: required("--message"),
        clientCreatedAt: new Date().toISOString(),
      });
      try {
        const socket = await connectAuthenticatedClient(paths);
        const flushedEvents = await flushDurableOutbox(socket, paths);
        socket.close();
        console.log(JSON.stringify({ queued: false, flushedEvents, eventId }));
      } catch {
        console.log(JSON.stringify({ queued: true, eventId }));
      }
      return;
    }
    case "request-agent": {
      const socket = await connectAuthenticatedClient(paths);
      const projectId = required("--project");
      const snapshot = nextFrame(socket, "chat.snapshot");
      socket.send(JSON.stringify({ version: 1, type: "chat.subscribe", requestId: crypto.randomUUID(), projectId, afterSequence: 0 }));
      await snapshot;
      const taskId = sendAgentRequest(socket, projectId, required("--agent"), required("--prompt"), paths);
      while (true) {
        const frame = await nextFrame(socket, "agent.result");
        if (frame.taskId !== taskId) continue;
        console.log(JSON.stringify(frame));
        if (frame.final === true) break;
      }
      socket.close();
      return;
    }
    case "session": {
      await runJsonLineSession(paths);
      return;
    }
    case "connect": {
      if (Bun.argv.includes("--json-lines")) {
        await runJsonLineSession(paths);
        return;
      }
      if (Bun.argv.includes("--json-lines")) {
        await runJsonLineSession(paths);
        return;
      }
      const connection = loadClientConnection(paths);
      await maintainAuthenticatedClient(paths, async socket => {
        const flushedEvents = await flushDurableOutbox(socket, paths);
        let detachAgentBridge: (() => void) | undefined;
        if (existsSync(paths.agentPolicy)) {
          const policy = loadLocalAgentPolicy(paths.agentPolicy);
          const adapter = new CodexAgentAdapter({
            projectId: policy.projectId,
            agentId: policy.agentId,
            workspaceRoot: policy.workspaceRoot,
            sandbox: policy.sandbox,
          });
          detachAgentBridge = attachLocalAgentBridge(socket, adapter, {
            localDeviceId: connection.deviceId,
        serverPublicKeyPem: connection.serverIdentityPublicKeyPem,
        trustedRequesterFingerprints: new Map(Object.entries(policy.trustedRequesterFingerprints)),
        journalPath: paths.agentJournal,
      });
        }
        console.log(JSON.stringify({
          connected: true,
          deviceId: connection.deviceId,
          agentEnabled: Boolean(detachAgentBridge),
          flushedEvents,
        }));
        return detachAgentBridge;
      }, {
        onConnectionError: error => {
          console.error(JSON.stringify({ connected: false, retrying: true, error: error.message }));
        },
      });
      return;
    }
    case "trust-device":
      trustDevice(paths.trustedDevices, required("--device"), required("--fingerprint"));
      console.log(JSON.stringify({ trusted: true }));
      return;
    default:
      console.log(`CoCodex Client

Usage:
  cocodex-client enroll --invite CODE --name NAME [--state-root PATH]
  cocodex-client status [--state-root PATH]
  cocodex-client configure-agent --project ID --agent ID --workspace PATH --trust-device ID --trust-fingerprint FP [--sandbox read-only|workspace-write] [--state-root PATH]
  cocodex-client private-send --recipient-device ID --recipient-key PEM_PATH --message TEXT [--state-root PATH]
  cocodex-client private-listen --trust-fingerprint FP [--after SEQUENCE] [--state-root PATH]
  cocodex-client chat-send --project ID --message TEXT [--state-root PATH]
  cocodex-client request-agent --project ID --agent ID --prompt TEXT [--state-root PATH]
  cocodex-client connect [--json-lines] [--state-root PATH]`);
  }
}

run().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
