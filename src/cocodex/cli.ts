#!/usr/bin/env bun
import { existsSync } from "node:fs";
import { connectAuthenticatedClient, enrollClient, loadClientConnection, sendAgentRequest } from "./client";
import { attachLocalAgentBridge } from "./agent-bridge";
import { CodexAgentAdapter } from "./codex-agent-adapter";
import { loadLocalAgentPolicy, saveLocalAgentPolicy } from "./agent-policy";
import { clientPaths } from "./paths";

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
      console.log(JSON.stringify({ configured: true, projectId: policy.projectId, agentId: policy.agentId }));
      return;
    }    case "request-agent": {
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
    }    case "connect": {
      const socket = await connectAuthenticatedClient(paths);
      const connection = loadClientConnection(paths);
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
        });
      }
      console.log(JSON.stringify({ connected: true, deviceId: connection.deviceId, agentEnabled: Boolean(detachAgentBridge) }));
      await new Promise<void>(resolve => socket.addEventListener("close", () => resolve(), { once: true }));
      detachAgentBridge?.();
      return;
    }
    default:
      console.log(`CoCodex Client

Usage:
  cocodex-client enroll --invite CODE --name NAME [--state-root PATH]
  cocodex-client status [--state-root PATH]
  cocodex-client configure-agent --project ID --agent ID --workspace PATH --trust-device ID --trust-fingerprint FP [--sandbox read-only|workspace-write] [--state-root PATH]
  cocodex-client request-agent --project ID --agent ID --prompt TEXT [--state-root PATH]
  cocodex-client connect [--state-root PATH]`);
  }
}

run().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
