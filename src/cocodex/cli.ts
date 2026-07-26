#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";
import {
  acceptServerAuthorityTransfer,
  connectAuthenticatedClient,
  enrollClient,
  loadClientConnection,
  maintainAuthenticatedClient,
  sendAgentRequest,
} from "./client";
import { attachLocalAgentBridge, type LocalAgentBridgeHandle } from "./agent-bridge";
import { CodexAgentAdapter } from "./codex-agent-adapter";
import {
  loadLocalAgentPolicies,
  loadLocalAgentPolicy,
  loadLocalAgentPolicyStore,
  saveLocalAgentPolicy,
  upsertLocalAgentPolicy,
  validateLocalAgentPolicy,
  type LocalAgentPolicy,
} from "./agent-policy";
import { agentRuntimePaths, stageLegacyAgentRuntimeState } from "./agent-runtime-paths";
import {
  configureAgentSafety,
  emergencyStopAgent,
  loadAgentSafety,
  resumeAgent,
  setFullComputerEnabled,
} from "./agent-safety";
import { clientPaths } from "./paths";
import { createDeviceKeyCertificate, loadOrCreateClientIdentity, verifyDeviceKeyCertificate } from "./identity";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "./private-messaging";
import { enqueueDurableEvent, flushDurableOutbox } from "./outbox";
import { runJsonLineSession } from "./session";
import { reportAgentExecution } from "./agent-execution-client";
import { prepareTaskWorkspace } from "./task-worktree";
import { loadTrustedDevices, trustDevice } from "./trusted-devices";

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
    case "accept-transfer": {
      const codePath = option("--code-file");
      const code = codePath ? readFileSync(codePath, "utf8") : required("--code");
      const connection = acceptServerAuthorityTransfer(code, paths);
      console.log(JSON.stringify({ accepted: true, host: connection.host, port: connection.port, serverEpoch: connection.serverEpoch, serverFingerprint: connection.serverFingerprint }));
      return;
    }
    case "identity-card": {
      const connection = loadClientConnection(paths);
      console.log(createDeviceKeyCertificate(connection.deviceId, loadOrCreateClientIdentity(paths)));
      return;
    }
    case "configure-agent": {
      const trustedDeviceId = required("--trust-device");
      const approvalMode = option("--approval") ?? "trusted-device";
      if (approvalMode !== "trusted-device" && approvalMode !== "always") {
        throw new Error("--approval must be trusted-device or always");
      }
      const workspaceMode = option("--workspace-mode") ?? "git-worktree";
      if (workspaceMode !== "shared" && workspaceMode !== "git-worktree") {
        throw new Error("--workspace-mode must be shared or git-worktree");
      }
      const accessProfile = option("--access") ?? "project-only";
      if (accessProfile !== "project-only" && accessProfile !== "full-computer") {
        throw new Error("--access must be project-only or full-computer");
      }
      const fullComputerOptIn = Bun.argv.includes("--confirm-full-computer");
      if (accessProfile === "full-computer" && !fullComputerOptIn) {
        throw new Error("Full-computer access requires --confirm-full-computer");
      }
      const primaryEffort = option("--effort") ?? "medium";
      const coAgentModel = option("--co-agent-model") ?? null;
      const coAgentEffort = option("--co-agent-effort") ?? null;
      const maxConcurrentCoAgents = Number(option("--max-co-agents") ?? 0);
      const policy = {
        version: 1,
        projectId: required("--project"),
        agentId: required("--agent"),
        workspaceRoot: required("--workspace"),
        workspaceMode,
        sandbox: option("--sandbox") === "read-only" ? "read-only" : "workspace-write",
        primaryModel: option("--model") ?? "gpt-5.6-sol",
        primaryEffort,
        coAgentModel,
        coAgentEffort,
        maxConcurrentCoAgents,
        accessProfile,
        fullComputerOptIn,
        approvalMode,
        trustedRequesterFingerprints: {
          [trustedDeviceId]: required("--trust-fingerprint"),
        },
      };
      const validatedPolicy = validateLocalAgentPolicy(policy as LocalAgentPolicy);
      const currentStore = existsSync(paths.agentPolicy) ? loadLocalAgentPolicyStore(paths.agentPolicy) : undefined;
      const existing = currentStore?.agents.find(candidate => candidate.agentId === validatedPolicy.agentId);
      if (currentStore?.version === 1 && !existing) {
        stageLegacyAgentRuntimeState(paths, currentStore.agents[0].agentId);
      }
      const legacyRuntime = !currentStore || (currentStore.version === 1 && Boolean(existing));
      const runtime = agentRuntimePaths(paths, validatedPolicy.agentId, legacyRuntime);
      if (!existing) configureAgentSafety(runtime.safety, validatedPolicy);
      trustDevice(paths.trustedDevices, trustedDeviceId, required("--trust-fingerprint"));
      if (!currentStore || (currentStore.version === 1 && existing)) {
        saveLocalAgentPolicy(paths.agentPolicy, validatedPolicy);
      } else {
        upsertLocalAgentPolicy(paths.agentPolicy, validatedPolicy);
      }
      console.log(JSON.stringify({
        configured: true,
        projectId: validatedPolicy.projectId,
        agentId: validatedPolicy.agentId,
        accessProfile: validatedPolicy.accessProfile,
        primaryModel: validatedPolicy.primaryModel,
        primaryEffort: validatedPolicy.primaryEffort,
        coAgentModel: validatedPolicy.coAgentModel,
        coAgentEffort: validatedPolicy.coAgentEffort,
        maxConcurrentCoAgents: validatedPolicy.maxConcurrentCoAgents,
      }));
      return;
    }
    case "agent-safety-status": {
      const policy = loadLocalAgentPolicy(paths.agentPolicy, option("--agent"));
      const store = loadLocalAgentPolicyStore(paths.agentPolicy);
      const runtime = agentRuntimePaths(paths, policy.agentId, store.version === 1);
      console.log(JSON.stringify({
        policy: { accessProfile: policy.accessProfile, fullComputerOptIn: policy.fullComputerOptIn },
        safety: loadAgentSafety(runtime.safety, policy),
      }, null, 2));
      return;
    }
    case "emergency-stop": {
      const policies = loadLocalAgentPolicies(paths.agentPolicy);
      const store = loadLocalAgentPolicyStore(paths.agentPolicy);
      const selected = option("--agent")
        ? [loadLocalAgentPolicy(paths.agentPolicy, option("--agent"))]
        : policies;
      const safety = selected.map(policy => ({
        agentId: policy.agentId,
        state: emergencyStopAgent(
          agentRuntimePaths(paths, policy.agentId, store.version === 1).safety,
          option("--reason") ?? "Stopped by the local host user.",
        ),
      }));
      console.log(JSON.stringify({ stopped: true, safety }));
      return;
    }
    case "emergency-resume": {
      const policy = loadLocalAgentPolicy(paths.agentPolicy, option("--agent"));
      const store = loadLocalAgentPolicyStore(paths.agentPolicy);
      console.log(JSON.stringify({ resumed: true, agentId: policy.agentId, safety: resumeAgent(
        agentRuntimePaths(paths, policy.agentId, store.version === 1).safety, policy,
      ) }));
      return;
    }
    case "full-computer-enable": {
      if (!Bun.argv.includes("--confirm")) throw new Error("Full-computer access requires --confirm");
      const policy = loadLocalAgentPolicy(paths.agentPolicy, option("--agent"));
      const store = loadLocalAgentPolicyStore(paths.agentPolicy);
      console.log(JSON.stringify({ enabled: true, agentId: policy.agentId, safety: setFullComputerEnabled(
        agentRuntimePaths(paths, policy.agentId, store.version === 1).safety, policy, true,
      ) }));
      return;
    }
    case "full-computer-disable": {
      const policy = loadLocalAgentPolicy(paths.agentPolicy, option("--agent"));
      const store = loadLocalAgentPolicyStore(paths.agentPolicy);
      console.log(JSON.stringify({ enabled: false, agentId: policy.agentId, safety: setFullComputerEnabled(
        agentRuntimePaths(paths, policy.agentId, store.version === 1).safety, policy, false,
      ) }));
      return;
    }
    case "private-send": {
      const connection = loadClientConnection(paths);
      const identity = loadOrCreateClientIdentity(paths);
      const recipientDeviceId = required("--recipient-device");
      const certificate = verifyDeviceKeyCertificate(
        readFileSync(required("--recipient-card"), "utf8"),
        recipientDeviceId,
      );
      if (loadTrustedDevices(paths.trustedDevices)[recipientDeviceId] !== certificate.fingerprint) {
        throw new Error("Recipient device key certificate does not match the trusted fingerprint");
      }
      const messageId = crypto.randomUUID();
      const clientCreatedAt = new Date().toISOString();
      const ciphertext = await sealSignedPrivateMessage({
        messageId,
        senderDeviceId: connection.deviceId,
        recipientDeviceId,
        text: required("--message"),
        clientCreatedAt,
      }, identity.privateKeyPem, identity.publicKeyPem, certificate.messagingPublicKeyPem);
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
      const connection = loadClientConnection(paths);
      const policies = existsSync(paths.agentPolicy) ? loadLocalAgentPolicies(paths.agentPolicy) : [];
      const storeVersion = existsSync(paths.agentPolicy) ? loadLocalAgentPolicyStore(paths.agentPolicy).version : 2;
      const control = maintainAuthenticatedClient(paths, async socket => {
        const flushedEvents = await flushDurableOutbox(socket, paths);
        console.log(JSON.stringify({
          connected: true,
          deviceId: connection.deviceId,
          agentEnabled: policies.length > 0,
          agentCount: policies.length,
          flushedEvents,
        }));
      }, {
        onConnectionError: error => {
          console.error(JSON.stringify({ connected: false, retrying: true, error: error.message }));
        },
      });
      const workers = policies.map(policy => maintainAuthenticatedClient(paths, async socket => {
        const runtime = agentRuntimePaths(paths, policy.agentId, storeVersion === 1);
        let safety = loadAgentSafety(runtime.safety, policy);
        let detachAgentBridge: LocalAgentBridgeHandle | undefined;
        let safetyPoll: ReturnType<typeof setInterval> | undefined;
        const executionAllowed = () => {
          try {
            safety = loadAgentSafety(runtime.safety, policy);
            return safety.executionEnabled && (policy.accessProfile !== "full-computer" || safety.fullComputerEnabled);
          } catch {
            return false;
          }
        };
        const adapter = new CodexAgentAdapter({
          projectId: policy.projectId,
          agentId: policy.agentId,
          workspaceRoot: policy.workspaceRoot,
          primaryModel: policy.primaryModel,
          primaryEffort: policy.primaryEffort,
          coAgentModel: policy.coAgentModel,
          coAgentEffort: policy.coAgentEffort,
          maxConcurrentCoAgents: policy.maxConcurrentCoAgents,
          sandbox: policy.accessProfile === "full-computer" ? "danger-full-access" : policy.sandbox,
          accessProfile: policy.accessProfile,
          fullComputerOptIn: policy.fullComputerOptIn,
          prepareWorkspace: task => prepareTaskWorkspace(policy, task, {
            worktreeRoot: runtime.worktreeRoot,
            registryPath: runtime.worktreeRegistry,
          }),
          onWorkspacePrepared: (task, workspace) =>
            reportAgentExecution(socket, loadOrCreateClientIdentity(paths), task, workspace),
          authorizeTask: () => executionAllowed(),
        });
        detachAgentBridge = attachLocalAgentBridge(socket, adapter, {
          localDeviceId: connection.deviceId,
          agentId: policy.agentId,
          primaryModel: policy.primaryModel,
          primaryEffort: policy.primaryEffort,
          coAgentModel: policy.coAgentModel,
          coAgentEffort: policy.coAgentEffort,
          maxConcurrentCoAgents: policy.maxConcurrentCoAgents,
          serverPublicKeyPem: connection.serverIdentityPublicKeyPem,
          trustedRequesterFingerprints: new Map(Object.entries(policy.trustedRequesterFingerprints)),
          journalPath: runtime.journal,
          isExecutionAllowed: executionAllowed,
        });
        if (!executionAllowed()) detachAgentBridge.emergencyStop("Local safety state is disabled.");
        safetyPoll = setInterval(() => {
          if (!detachAgentBridge) return;
          if (!executionAllowed()) detachAgentBridge.emergencyStop("Local safety state is disabled.");
          else if (detachAgentBridge.isEmergencyStopped()) detachAgentBridge.resume();
        }, 250);
        return async () => {
          if (safetyPoll) clearInterval(safetyPoll);
          await detachAgentBridge?.();
        };
      }, {
        onConnectionError: error => {
          console.error(JSON.stringify({ connected: false, agentId: policy.agentId, retrying: true, error: error.message }));
        },
      }));
      await Promise.all([control, ...workers]);
      return;
    }
    case "trust-device":
      trustDevice(paths.trustedDevices, required("--device"), required("--fingerprint"));
      console.log(JSON.stringify({ trusted: true }));
      return;
    default:
      console.log(`CoCodex Client

Usage:
  cocodex enroll --invite CODE --name NAME [--state-root PATH]
  cocodex status [--state-root PATH]
  cocodex accept-transfer --code CODE [--state-root PATH]
  cocodex accept-transfer --code-file FILE [--state-root PATH]
  cocodex identity-card [--state-root PATH]
  cocodex configure-agent --project ID --agent ID --workspace PATH --trust-device ID --trust-fingerprint FP [--model ID] [--effort minimal|low|medium|high|xhigh|max] [--co-agent-model ID --co-agent-effort LEVEL --max-co-agents 1..8] [--workspace-mode git-worktree|shared] [--sandbox read-only|workspace-write] [--approval trusted-device|always] [--access project-only|full-computer --confirm-full-computer] [--state-root PATH]
  cocodex agent-safety-status [--agent ID] [--state-root PATH]
  cocodex emergency-stop [--agent ID] [--reason TEXT] [--state-root PATH]
  cocodex emergency-resume [--agent ID] [--state-root PATH]
  cocodex full-computer-enable --confirm [--agent ID] [--state-root PATH]
  cocodex full-computer-disable [--agent ID] [--state-root PATH]
  cocodex private-send --recipient-device ID --recipient-card JSON_PATH --message TEXT [--state-root PATH]
  cocodex private-listen --trust-fingerprint FP [--after SEQUENCE] [--state-root PATH]
  cocodex chat-send --project ID --message TEXT [--state-root PATH]
  cocodex request-agent --project ID --agent ID --prompt TEXT [--state-root PATH]
  cocodex connect [--json-lines] [--state-root PATH]

Short alias: ccx`);
  }
}

run().then(
  () => process.exit(0),
  error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  },
);
