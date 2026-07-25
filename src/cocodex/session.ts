import { randomUUID } from "node:crypto";
import {
  PROJECT_CONTEXT_MAX_BYTES,
  projectContentEnvelopeSchema,
  projectKeyEnvelopeSchema,
  publicKeyFingerprint,
  type Artifact,
  type AgentTask,
  type ChatEvent,
} from "@cocodex/protocol";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { attachLocalAgentBridge } from "./agent-bridge";
import { loadLocalAgentPolicy } from "./agent-policy";
import { CodexAgentAdapter, type CodexUsage } from "./codex-agent-adapter";
import { createAgentRequest, loadClientConnection, maintainAuthenticatedClient } from "./client";
import { loadOrCreateClientIdentity, verifyDeviceKeyCertificate } from "./identity";
import { enqueueDurableEvent, flushDurableOutbox } from "./outbox";
import type { ClientPaths } from "./paths";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "./private-messaging";
import { loadTrustedDevices, trustDevice } from "./trusted-devices";
import { loadUsageReport, saveUsageReport, signUsageReport } from "./usage";
import {
  createProjectKey,
  openProjectContent,
  openProjectKeyEnvelope,
  sealProjectContent,
  sealProjectKeyEnvelope,
} from "./project-encryption";
import { loadProjectKey, loadProjectKeyForEncryption, revokeProjectKey, storeProjectKey } from "./project-key-store";

interface ControlCommand extends Record<string, unknown> {
  id?: string;
  type: string;
}

function controlRequestId(value: unknown): string {
  return typeof value === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
    ? value
    : randomUUID();
}

const SNAPSHOT_PAGE_SIZE = 500;

export interface JsonLineSessionOptions {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  errorOutput?: NodeJS.WritableStream;
}

export async function runJsonLineSession(
  paths: ClientPaths,
  options: JsonLineSessionOptions = {},
): Promise<void> {
  const output = options.output ?? process.stdout;
  const errorOutput = options.errorOutput ?? process.stderr;
  const connection = loadClientConnection(paths);
  const identity = loadOrCreateClientIdentity(paths);
  const controller = new AbortController();
  const chatCursors = new Map<string, number>();
  const encryptedChatCursors = new Map<string, number>();
  const promptSubscriptions = new Set<string>();
  const encryptedPromptCursors = new Map<string, number>();
  const encryptedPromptSubscriptions = new Set<string>();
  const encryptedArtifactSubscriptions = new Set<string>();
  const contextSubscriptions = new Set<string>();
  const encryptedContextSubscriptions = new Set<string>();
  const projectKeySubscriptions = new Set<string>();
  const usageSubscriptions = new Set<string>();
  let privateCursor = 0;
  let socket: WebSocket | undefined;
  let flushChain = Promise.resolve(0);
  let usageReport = loadUsageReport(paths.usageReport, connection.deviceId);
  const pendingAgentApprovals = new Map<string, (approved: boolean) => void>();
  const emit = (value: unknown) => output.write(`${JSON.stringify(value)}\n`);
  const emitError = (value: unknown) => errorOutput.write(`${JSON.stringify(value)}\n`);
  const send = (frame: unknown) => {
    if (!socket || socket.readyState !== WebSocket.OPEN) throw new Error("CoCodex Server is offline");
    socket.send(JSON.stringify(frame));
  };
  const encryptedChatFrame = async (
    projectId: string,
    eventId: string,
    content: string,
    requestId: string,
    clientCreatedAt: string,
  ) => {
    if (content.length < 1 || content.length > 32_768) throw new Error("Chat content must be 1-32768 characters");
    const stored = loadProjectKeyForEncryption(paths.projectKeys, projectId);
    if (!stored) throw new Error(`No project encryption key is available for ${projectId}`);
    const envelope = await sealProjectContent({
      projectId,
      keyEpoch: stored.keyEpoch,
      recordType: "chat",
      recordId: eventId,
      plaintext: JSON.stringify({ content }),
      projectKey: stored.projectKey,
      senderDeviceId: connection.deviceId,
      senderPrivateKeyPem: identity.privateKeyPem,
      senderPublicKeyPem: identity.publicKeyPem,
    });
    return {
      version: 1 as const,
      type: "project.chat.send" as const,
      requestId,
      projectId,
      eventId,
      envelope,
      clientCreatedAt,
    };
  };
  const encryptedPromptFrame = async (
    projectId: string,
    updateId: string,
    update: string,
    requestId: string,
  ) => {
    if (update.length < 4 || update.length > 256_000) throw new Error("Prompt update must be 4-256000 characters");
    const stored = loadProjectKeyForEncryption(paths.projectKeys, projectId);
    if (!stored) throw new Error(`No project encryption key is available for ${projectId}`);
    const envelope = await sealProjectContent({
      projectId,
      keyEpoch: stored.keyEpoch,
      recordType: "shared-prompt",
      recordId: updateId,
      plaintext: JSON.stringify({ update }),
      projectKey: stored.projectKey,
      senderDeviceId: connection.deviceId,
      senderPrivateKeyPem: identity.privateKeyPem,
      senderPublicKeyPem: identity.publicKeyPem,
    });
    return {
      version: 1 as const,
      type: "project.prompt.update" as const,
      requestId,
      projectId,
      updateId,
      envelope,
    };
  };
  const encryptedArtifactFrame = async (
    projectId: string,
    artifactId: string,
    taskId: string | null,
    artifactType: string,
    title: string,
    summary: string,
    content: string,
    status: string,
    requestId: string,
  ) => {
    if (title.trim().length < 1 || title.trim().length > 200) throw new Error("Artifact title must be 1-200 characters");
    if (summary.trim().length < 1 || summary.trim().length > 4_000) throw new Error("Artifact summary must be 1-4000 characters");
    if (content.length < 1 || content.length > 256_000) throw new Error("Artifact content must be 1-256000 characters");
    const stored = loadProjectKeyForEncryption(paths.projectKeys, projectId);
    if (!stored) throw new Error(`No project encryption key is available for ${projectId}`);
    const envelope = await sealProjectContent({
      projectId,
      keyEpoch: stored.keyEpoch,
      recordType: "artifact",
      recordId: artifactId,
      plaintext: JSON.stringify({
        id: artifactId,
        projectId,
        taskId,
        type: artifactType,
        title: title.trim(),
        summary: summary.trim(),
        content,
        status,
      }),
      projectKey: stored.projectKey,
      senderDeviceId: connection.deviceId,
      senderPrivateKeyPem: identity.privateKeyPem,
      senderPublicKeyPem: identity.publicKeyPem,
    });
    return {
      version: 1 as const,
      type: "project.artifact.publish" as const,
      requestId,
      artifactId,
      projectId,
      taskId,
      envelope,
    };
  };
  const publishUsage = (changes: Partial<typeof usageReport> = {}) => {
    usageReport = {
      ...usageReport,
      ...changes,
      revision: usageReport.revision + 1,
      updatedAt: new Date().toISOString(),
    };
    saveUsageReport(paths.usageReport, usageReport);
    try {
      send({
        version: 1,
        type: "usage.report",
        requestId: randomUUID(),
        report: usageReport,
        signature: signUsageReport(usageReport, identity),
      });
    } catch {
      // The protected local report is retried on the next connection.
    }
  };
  const flush = () => {
    if (!socket || socket.readyState !== WebSocket.OPEN) return Promise.resolve(0);
    // A connection can disappear while an outbox flush is in flight. Recover
    // the serialization chain so that a transient failure cannot permanently
    // prevent later reconnects from draining durable events.
    flushChain = flushChain.catch(() => 0).then(() => flushDurableOutbox(socket!, paths));
    return flushChain;
  };
  const authorizeAgentTask = (task: AgentTask, signal?: AbortSignal): Promise<boolean> => new Promise(resolve => {
    if (pendingAgentApprovals.has(task.id) || signal?.aborted) return resolve(false);
    const finish = (approved: boolean) => {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", onAbort);
      pendingAgentApprovals.delete(task.id);
      emit({ source: "agent-approval", approvalState: "resolved", taskId: task.id, approved });
      resolve(approved);
    };
    const timeout = setTimeout(() => finish(false), 5 * 60_000);
    const onAbort = () => finish(false);
    pendingAgentApprovals.set(task.id, finish);
    signal?.addEventListener("abort", onAbort, { once: true });
    emit({
      source: "agent-approval",
      approvalState: "pending",
      task: {
        id: task.id,
        projectId: task.projectId,
        agentId: task.agentId,
        requesterDeviceId: task.requesterDeviceId,
        prompt: task.prompt,
      },
    });
  });
  const openPrivateEnvelope = (message: {
    messageId: string;
    senderDeviceId: string;
    recipientDeviceId: string;
    clientCreatedAt: string;
    ciphertext: string;
    sequence?: number;
  }) => {
    if (message.recipientDeviceId !== connection.deviceId) return;
    const trusted = loadTrustedDevices(paths.trustedDevices)[message.senderDeviceId];
    if (!trusted) {
      emitError({
        source: "private",
        error: `Private-message sender ${message.senderDeviceId} is not an approved device`,
      });
      return;
    }
    void openSignedPrivateMessage(
      message.ciphertext,
      identity.messagingPrivateKeyPem,
      identity.messagingPublicKeyPem,
      message,
      trusted,
    ).then(opened => emit({
      source: "private",
      message: { ...message, ciphertext: undefined, text: opened.text },
    })).catch(error => emitError({
      source: "private",
      error: error instanceof Error ? error.message : String(error),
    }));
  };

  const trustedProjectSenderKey = (deviceId: string, senderPublicKeyPem: string): string => {
    const expectedFingerprint = deviceId === connection.deviceId
      ? publicKeyFingerprint(identity.publicKeyPem)
      : loadTrustedDevices(paths.trustedDevices)[deviceId];
    if (!expectedFingerprint) throw new Error(`Project content sender ${deviceId} is not trusted`);
    if (publicKeyFingerprint(senderPublicKeyPem) !== expectedFingerprint) {
      throw new Error(`Project content sender ${deviceId} does not match its trusted fingerprint`);
    }
    return senderPublicKeyPem;
  };

  const decodeProjectContext = (plaintext: Buffer): { finalGoal: string; context: Record<string, unknown> } => {
    if (plaintext.byteLength > PROJECT_CONTEXT_MAX_BYTES) throw new Error("Encrypted project context is too large");
    let value: unknown;
    try { value = JSON.parse(plaintext.toString("utf8")); }
    catch { throw new Error("Encrypted project context is not valid JSON"); }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Encrypted project context is invalid");
    const record = value as Record<string, unknown>;
    if (typeof record.finalGoal !== "string" || record.finalGoal.length > 32_768
      || !record.context || typeof record.context !== "object" || Array.isArray(record.context)) {
      throw new Error("Encrypted project context is invalid");
    }
    return { finalGoal: record.finalGoal, context: record.context as Record<string, unknown> };
  };

  const openEncryptedChatEvent = async (rawEvent: Record<string, any>): Promise<ChatEvent> => {
    const projectId = String(rawEvent.projectId);
    const eventId = String(rawEvent.eventId);
    const parsedEnvelope = projectContentEnvelopeSchema.parse(rawEvent.envelope);
    const key = loadProjectKey(paths.projectKeys, projectId, parsedEnvelope.keyEpoch);
    if (!key) throw new Error(`No project key is available for ${projectId} epoch ${parsedEnvelope.keyEpoch}`);
    const senderPublicKeyPem = trustedProjectSenderKey(parsedEnvelope.senderDeviceId, parsedEnvelope.senderPublicKeyPem);
    const plaintext = await openProjectContent({
      envelope: parsedEnvelope,
      projectKey: key.projectKey,
      expectedProjectId: projectId,
      expectedKeyEpoch: key.keyEpoch,
      expectedRecordType: "chat",
      expectedRecordId: eventId,
      expectedSenderDeviceId: parsedEnvelope.senderDeviceId,
      expectedSenderPublicKeyPem: senderPublicKeyPem,
    });
    if (plaintext.byteLength > 32_768) throw new Error("Encrypted chat content is too large");
    let decoded: unknown;
    try { decoded = JSON.parse(plaintext.toString("utf8")); }
    catch { throw new Error("Encrypted chat content is not valid JSON"); }
    const content = decoded && typeof decoded === "object" && !Array.isArray(decoded)
      ? (decoded as Record<string, unknown>).content
      : undefined;
    if (typeof content !== "string" || content.length < 1 || content.length > 32_768) {
      throw new Error("Encrypted chat content is invalid");
    }
    return {
      sequence: Number(rawEvent.sequence),
      projectId,
      eventId,
      senderDeviceId: String(rawEvent.senderDeviceId),
      content,
      clientCreatedAt: String(rawEvent.clientCreatedAt),
      acceptedAt: String(rawEvent.acceptedAt),
    };
  };

  const openEncryptedChatFrame = async (frame: Record<string, any>): Promise<void> => {
    try {
      const projectId = String(frame.projectId ?? frame.event?.projectId);
      if (frame.type === "project.chat.snapshot") {
        const rawEvents = Array.isArray(frame.events) ? frame.events : [];
        const events: ChatEvent[] = [];
        for (const rawEvent of rawEvents) events.push(await openEncryptedChatEvent(rawEvent));
        const latest = events.at(-1)?.sequence;
        if (typeof latest === "number") {
          encryptedChatCursors.set(projectId, Math.max(encryptedChatCursors.get(projectId) ?? 0, latest));
        }
        emit({ source: "server", frame: {
          version: 1,
          type: "chat.snapshot",
          ...(frame.requestId ? { requestId: frame.requestId } : {}),
          projectId,
          events,
        } });
        if (rawEvents.length === SNAPSHOT_PAGE_SIZE && typeof latest === "number") {
          send({ version: 1, type: "project.chat.subscribe", requestId: randomUUID(), projectId, afterSequence: latest });
        }
        return;
      }
      if (frame.type === "project.chat.event" || frame.type === "project.chat.accepted") {
        const event = await openEncryptedChatEvent(frame.event);
        encryptedChatCursors.set(projectId, Math.max(encryptedChatCursors.get(projectId) ?? 0, event.sequence));
        emit({ source: "server", frame: {
          version: 1,
          type: frame.type === "project.chat.event" ? "chat.event" : "chat.accepted",
          ...(frame.requestId ? { requestId: frame.requestId } : {}),
          projectId,
          event,
        } });
      }
    } catch (error) {
      emitError({ source: "project-encryption", error: error instanceof Error ? error.message : String(error) });
    }
  };

  const openEncryptedPromptUpdate = async (rawUpdate: Record<string, any>): Promise<{ updateId: string; projectId: string; senderDeviceId: string; update: string; sequence: number }> => {
    const projectId = String(rawUpdate.projectId);
    const updateId = String(rawUpdate.updateId);
    const parsedEnvelope = projectContentEnvelopeSchema.parse(rawUpdate.envelope);
    const key = loadProjectKey(paths.projectKeys, projectId, parsedEnvelope.keyEpoch);
    if (!key) throw new Error(`No project key is available for ${projectId} epoch ${parsedEnvelope.keyEpoch}`);
    const senderPublicKeyPem = trustedProjectSenderKey(parsedEnvelope.senderDeviceId, parsedEnvelope.senderPublicKeyPem);
    const plaintext = await openProjectContent({
      envelope: parsedEnvelope,
      projectKey: key.projectKey,
      expectedProjectId: projectId,
      expectedKeyEpoch: key.keyEpoch,
      expectedRecordType: "shared-prompt",
      expectedRecordId: updateId,
      expectedSenderDeviceId: parsedEnvelope.senderDeviceId,
      expectedSenderPublicKeyPem: senderPublicKeyPem,
    });
    if (plaintext.byteLength > 256_000) throw new Error("Encrypted prompt update is too large");
    let decoded: unknown;
    try { decoded = JSON.parse(plaintext.toString("utf8")); }
    catch { throw new Error("Encrypted prompt update is not valid JSON"); }
    const update = decoded && typeof decoded === "object" && !Array.isArray(decoded)
      ? (decoded as Record<string, unknown>).update
      : undefined;
    if (typeof update !== "string" || update.length < 4 || update.length > 256_000) {
      throw new Error("Encrypted prompt update is invalid");
    }
    return {
      updateId,
      projectId,
      senderDeviceId: String(rawUpdate.senderDeviceId),
      update,
      sequence: Number(rawUpdate.sequence),
    };
  };

  const openEncryptedPromptFrame = async (frame: Record<string, any>): Promise<void> => {
    try {
      const projectId = String(frame.projectId ?? frame.update?.projectId);
      if (frame.type === "project.prompt.snapshot") {
        const rawUpdates = Array.isArray(frame.updates) ? frame.updates : [];
        const updates = [];
        for (const rawUpdate of rawUpdates) updates.push(await openEncryptedPromptUpdate(rawUpdate));
        const latest = updates.at(-1)?.sequence;
        if (typeof latest === "number") {
          encryptedPromptCursors.set(projectId, Math.max(encryptedPromptCursors.get(projectId) ?? 0, latest));
        }
        emit({ source: "server", frame: {
          version: 1,
          type: "prompt.snapshot",
          ...(frame.requestId ? { requestId: frame.requestId } : {}),
          projectId,
          updates,
        } });
        if (rawUpdates.length === SNAPSHOT_PAGE_SIZE && typeof latest === "number") {
          send({ version: 1, type: "project.prompt.subscribe", requestId: randomUUID(), projectId, afterSequence: latest });
        }
        return;
      }
      if (frame.type === "project.prompt.changed" || frame.type === "project.prompt.accepted") {
        const update = await openEncryptedPromptUpdate(frame.update);
        encryptedPromptCursors.set(projectId, Math.max(encryptedPromptCursors.get(projectId) ?? 0, update.sequence));
        emit({ source: "server", frame: {
          version: 1,
          type: "prompt.update",
          ...(frame.requestId ? { requestId: frame.requestId } : {}),
          projectId,
          updateId: update.updateId,
          senderDeviceId: update.senderDeviceId,
          update: update.update,
        } });
      }
    } catch (error) {
      emitError({ source: "project-encryption", error: error instanceof Error ? error.message : String(error) });
    }
  };

  const openEncryptedArtifact = async (rawArtifact: Record<string, any>): Promise<Artifact> => {
    const projectId = String(rawArtifact.projectId);
    const artifactId = String(rawArtifact.artifactId);
    const parsedEnvelope = projectContentEnvelopeSchema.parse(rawArtifact.envelope);
    const key = loadProjectKey(paths.projectKeys, projectId, parsedEnvelope.keyEpoch);
    if (!key) throw new Error(`No project key is available for ${projectId} epoch ${parsedEnvelope.keyEpoch}`);
    const senderPublicKeyPem = trustedProjectSenderKey(parsedEnvelope.senderDeviceId, parsedEnvelope.senderPublicKeyPem);
    const plaintext = await openProjectContent({
      envelope: parsedEnvelope,
      projectKey: key.projectKey,
      expectedProjectId: projectId,
      expectedKeyEpoch: key.keyEpoch,
      expectedRecordType: "artifact",
      expectedRecordId: artifactId,
      expectedSenderDeviceId: parsedEnvelope.senderDeviceId,
      expectedSenderPublicKeyPem: senderPublicKeyPem,
    });
    if (plaintext.byteLength > 300_000) throw new Error("Encrypted artifact is too large");
    let decoded: unknown;
    try { decoded = JSON.parse(plaintext.toString("utf8")); }
    catch { throw new Error("Encrypted artifact is not valid JSON"); }
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error("Encrypted artifact is invalid");
    const record = decoded as Record<string, unknown>;
    const allowedTypes = new Set(["finding", "plan", "decision", "api-contract", "schema", "code-change", "commit", "diff", "test-result", "review", "handoff", "documentation", "failure-report", "browser-result", "final-result"]);
    const allowedStatuses = new Set(["draft", "ready", "accepted", "rejected", "superseded", "integrated"]);
    if (record.id !== artifactId || record.projectId !== projectId
      || (record.taskId !== null && typeof record.taskId !== "string")
      || typeof record.type !== "string" || !allowedTypes.has(record.type)
      || typeof record.title !== "string" || record.title.trim().length < 1 || record.title.length > 200
      || typeof record.summary !== "string" || record.summary.trim().length < 1 || record.summary.length > 4_000
      || typeof record.content !== "string" || record.content.length < 1 || record.content.length > 256_000
      || typeof record.status !== "string" || !allowedStatuses.has(record.status)) {
      throw new Error("Encrypted artifact is invalid");
    }
    if (record.taskId !== rawArtifact.taskId || parsedEnvelope.senderDeviceId !== rawArtifact.authorDeviceId) {
      throw new Error("Encrypted artifact metadata does not match its envelope");
    }
    return {
      id: artifactId,
      projectId,
      taskId: record.taskId as string | null,
      authorDeviceId: String(rawArtifact.authorDeviceId),
      type: record.type as Artifact["type"],
      title: record.title,
      summary: record.summary,
      content: record.content,
      status: record.status as Artifact["status"],
      createdAt: String(rawArtifact.createdAt),
      updatedAt: String(rawArtifact.updatedAt),
    };
  };

  const openEncryptedArtifactFrame = async (frame: Record<string, any>): Promise<void> => {
    try {
      const projectId = String(frame.projectId ?? frame.artifact?.projectId);
      if (frame.type === "project.artifact.list.result") {
        const rawArtifacts = Array.isArray(frame.artifacts) ? frame.artifacts : [];
        const artifacts: Artifact[] = [];
        for (const rawArtifact of rawArtifacts) artifacts.push(await openEncryptedArtifact(rawArtifact));
        emit({ source: "server", frame: {
          version: 1,
          type: "artifact.list.result",
          ...(frame.requestId ? { requestId: frame.requestId } : {}),
          projectId,
          artifacts,
        } });
        return;
      }
      if (frame.type === "project.artifact.accepted" || frame.type === "project.artifact.published") {
        const artifact = await openEncryptedArtifact(frame.artifact);
        emit({ source: "server", frame: {
          version: 1,
          type: frame.type === "project.artifact.accepted" ? "artifact.accepted" : "artifact.published",
          ...(frame.requestId ? { requestId: frame.requestId } : {}),
          projectId,
          artifact,
        } });
      }
    } catch (error) {
      emitError({ source: "project-encryption", error: error instanceof Error ? error.message : String(error) });
    }
  };

  const openProjectKeyEnvelopeFromServer = (envelope: Record<string, any>): void => {
    if (envelope.recipientDeviceId !== connection.deviceId) return;
    if (!identity.projectWrapPrivateKeyPem || !identity.projectWrapPublicKeyPem) {
      emitError({ source: "project-encryption", error: "This client has no project-wrap key" });
      return;
    }
    try {
      const parsedEnvelope = projectKeyEnvelopeSchema.parse(envelope);
      const senderPublicKeyPem = trustedProjectSenderKey(parsedEnvelope.senderDeviceId, parsedEnvelope.senderPublicKeyPem);
      void openProjectKeyEnvelope({
        envelope: parsedEnvelope,
        recipientDeviceId: connection.deviceId,
        recipientProjectWrapPrivateKeyPem: identity.projectWrapPrivateKeyPem,
        recipientProjectWrapPublicKeyPem: identity.projectWrapPublicKeyPem,
        expectedProjectId: parsedEnvelope.projectId,
        expectedKeyEpoch: parsedEnvelope.keyEpoch,
        expectedSenderPublicKeyPem: senderPublicKeyPem,
      }).then(projectKey => {
        storeProjectKey(paths.projectKeys, parsedEnvelope.projectId, parsedEnvelope.keyEpoch, projectKey);
        emit({ source: "project-encryption", state: "key-available", projectId: parsedEnvelope.projectId, keyEpoch: parsedEnvelope.keyEpoch });
      }).catch(error => emitError({
        source: "project-encryption",
        error: error instanceof Error ? error.message : String(error),
      }));
    } catch (error) {
      emitError({ source: "project-encryption", error: error instanceof Error ? error.message : String(error) });
    }
  };

  const openEncryptedProjectContext = (frame: Record<string, any>): void => {
    const envelope = frame.envelope as Record<string, any> | null;
    const projectId = String(frame.projectId);
    if (!envelope) {
      emit({ source: "server", frame: {
        version: 1,
        type: frame.type === "project.context.result" ? "context.result" : "context.changed",
        ...(frame.requestId ? { requestId: frame.requestId } : {}),
        projectId,
        context: { projectId, finalGoal: "", context: {}, revision: frame.revision ?? 0, updatedByDeviceId: null, updatedAt: null },
      } });
      return;
    }
    const key = loadProjectKey(paths.projectKeys, projectId, Number(envelope.keyEpoch));
    if (!key) {
      emitError({ source: "project-encryption", error: `No project key is available for ${projectId} epoch ${envelope.keyEpoch}` });
      return;
    }
    try {
      const parsedEnvelope = projectContentEnvelopeSchema.parse(envelope);
      const senderPublicKeyPem = trustedProjectSenderKey(parsedEnvelope.senderDeviceId, parsedEnvelope.senderPublicKeyPem);
      void openProjectContent({
        envelope: parsedEnvelope,
        projectKey: key.projectKey,
        expectedProjectId: projectId,
        expectedKeyEpoch: key.keyEpoch,
        expectedRecordType: "shared-context",
        expectedRecordId: parsedEnvelope.recordId,
        expectedSenderDeviceId: parsedEnvelope.senderDeviceId,
        expectedSenderPublicKeyPem: senderPublicKeyPem,
      }).then(plaintext => {
        const decoded = decodeProjectContext(plaintext);
        emit({ source: "server", frame: {
          version: 1,
          type: frame.type === "project.context.result" ? "context.result"
            : frame.type === "project.context.updated" ? "context.updated" : "context.changed",
          ...(frame.requestId ? { requestId: frame.requestId } : {}),
          projectId,
          context: {
            projectId,
            finalGoal: decoded.finalGoal,
            context: decoded.context,
            revision: frame.revision,
            updatedByDeviceId: envelope.senderDeviceId,
            updatedAt: frame.updatedAt ?? null,
          },
        } });
      }).catch(error => emitError({
        source: "project-encryption",
        error: error instanceof Error ? error.message : String(error),
      }));
    } catch (error) {
      emitError({ source: "project-encryption", error: error instanceof Error ? error.message : String(error) });
    }
  };

  const session = maintainAuthenticatedClient(paths, async connected => {
    socket = connected;
    const listener = (event: MessageEvent) => {
      let frame: Record<string, any>;
      try { frame = JSON.parse(String(event.data)) as Record<string, any>; }
      catch { return; }
      if (frame.type === "project.chat.snapshot" || frame.type === "project.chat.event" || frame.type === "project.chat.accepted") {
        void openEncryptedChatFrame(frame);
        return;
      }
      if (frame.type === "project.prompt.snapshot" || frame.type === "project.prompt.changed" || frame.type === "project.prompt.accepted") {
        void openEncryptedPromptFrame(frame);
        return;
      }
      if (frame.type === "project.artifact.accepted" || frame.type === "project.artifact.published" || frame.type === "project.artifact.list.result") {
        void openEncryptedArtifactFrame(frame);
        return;
      }
      if (frame.type === "chat.snapshot") {
        const events = Array.isArray(frame.events) ? frame.events : [];
        const latest = events.at(-1)?.sequence;
        if (typeof latest === "number") chatCursors.set(frame.projectId, latest);
        if (events.length === SNAPSHOT_PAGE_SIZE && typeof latest === "number") {
          send({
            version: 1,
            type: "chat.subscribe",
            requestId: randomUUID(),
            projectId: frame.projectId,
            afterSequence: latest,
          });
        }
      } else if (frame.type === "chat.event" || frame.type === "agent.result") {
        const item = frame.event;
        if (item?.projectId && typeof item.sequence === "number") {
          chatCursors.set(item.projectId, Math.max(chatCursors.get(item.projectId) ?? 0, item.sequence));
        }
      } else if (frame.type === "private.snapshot") {
        const messages = Array.isArray(frame.messages) ? frame.messages : [];
        for (const message of messages) openPrivateEnvelope(message);
        const latest = messages.at(-1)?.sequence;
        if (typeof latest === "number") privateCursor = Math.max(privateCursor, latest);
        if (messages.length === SNAPSHOT_PAGE_SIZE && typeof latest === "number") {
          send({
            version: 1,
            type: "private.subscribe",
            requestId: randomUUID(),
            afterSequence: latest,
          });
        }
      } else if (frame.type === "private.message" && typeof frame.message?.sequence === "number") {
        privateCursor = Math.max(privateCursor, frame.message.sequence);
        openPrivateEnvelope(frame.message);
      } else if (frame.type === "project.key.result") {
        const envelopes = Array.isArray(frame.envelopes) ? frame.envelopes : [];
        for (const envelope of envelopes) openProjectKeyEnvelopeFromServer(envelope);
      } else if (frame.type === "project.key.changed") {
        openProjectKeyEnvelopeFromServer(frame.envelope);
      } else if (frame.type === "project.key.rotated") {
        const envelopes = Array.isArray(frame.envelopes) ? frame.envelopes : [];
        for (const envelope of envelopes) openProjectKeyEnvelopeFromServer(envelope);
      } else if (frame.type === "project.member.removed") {
        if (frame.deviceId === connection.deviceId) {
          try {
            revokeProjectKey(paths.projectKeys, String(frame.projectId));
            emit({ source: "project-encryption", state: "revoked", projectId: String(frame.projectId) });
          } catch (error) {
            emitError({ source: "project-encryption", error: error instanceof Error ? error.message : String(error) });
          }
        }
      } else if (frame.type === "project.context.result"
        || frame.type === "project.context.updated"
        || frame.type === "project.context.changed") {
        openEncryptedProjectContext(frame);
      }
      emit({ source: "server", frame });
    };
    connected.addEventListener("message", listener);
    const flushedEvents = await flush();
    for (const [projectId, afterSequence] of chatCursors) {
      send({ version: 1, type: "chat.subscribe", requestId: randomUUID(), projectId, afterSequence });
    }
    for (const [projectId, afterSequence] of encryptedChatCursors) {
      send({ version: 1, type: "project.chat.subscribe", requestId: randomUUID(), projectId, afterSequence });
    }
    for (const projectId of encryptedPromptSubscriptions) {
      send({
        version: 1,
        type: "project.prompt.subscribe",
        requestId: randomUUID(),
        projectId,
        afterSequence: encryptedPromptCursors.get(projectId) ?? 0,
      });
    }
    for (const projectId of encryptedArtifactSubscriptions) {
      send({ version: 1, type: "project.artifact.list", requestId: randomUUID(), projectId });
    }
    for (const projectId of promptSubscriptions) {
      send({ version: 1, type: "prompt.subscribe", requestId: randomUUID(), projectId });
    }
    for (const projectId of contextSubscriptions) {
      send({ version: 1, type: "context.get", requestId: randomUUID(), projectId });
    }
    for (const projectId of projectKeySubscriptions) {
      send({ version: 1, type: "project.key.get", requestId: randomUUID(), projectId });
    }
    for (const projectId of encryptedContextSubscriptions) {
      send({ version: 1, type: "project.context.get", requestId: randomUUID(), projectId });
    }
    for (const projectId of usageSubscriptions) {
      send({ version: 1, type: "usage.get", requestId: randomUUID(), projectId });
    }
    try {
      send({
        version: 1,
        type: "usage.report",
        requestId: randomUUID(),
        report: usageReport,
        signature: signUsageReport(usageReport, identity),
      });
    } catch {
      // The session will retry the persisted report on its next reconnect.
    }
    send({ version: 1, type: "private.subscribe", requestId: randomUUID(), afterSequence: privateCursor });
    let detachAgent: (() => void | Promise<void>) | undefined;
    if (existsSync(paths.agentPolicy)) {
      const policy = loadLocalAgentPolicy(paths.agentPolicy);
      const onUsage = (usage: CodexUsage) => {
        emit({ source: "local-usage", deviceId: connection.deviceId, usage });
        publishUsage({
          requests: usageReport.requests + 1,
          inputTokens: usageReport.inputTokens + (usage.inputTokens ?? 0),
          cachedInputTokens: usageReport.cachedInputTokens + (usage.cachedInputTokens ?? 0),
          outputTokens: usageReport.outputTokens + (usage.outputTokens ?? 0),
          reasoningOutputTokens: usageReport.reasoningOutputTokens + (usage.reasoningOutputTokens ?? 0),
        });
      };
      detachAgent = attachLocalAgentBridge(connected, new CodexAgentAdapter({
        projectId: policy.projectId,
        agentId: policy.agentId,
        workspaceRoot: policy.workspaceRoot,
        sandbox: policy.sandbox,
        onUsage,
        authorizeTask: policy.approvalMode === "always" ? authorizeAgentTask : () => true,
      }), {
        localDeviceId: connection.deviceId,
        serverPublicKeyPem: connection.serverIdentityPublicKeyPem,
        trustedRequesterFingerprints: new Map(Object.entries(policy.trustedRequesterFingerprints)),
        journalPath: paths.agentJournal,
        onActiveAgents: activeAgents => publishUsage({ activeAgents }),
      });
    }
    emit({ source: "session", state: "connected", deviceId: connection.deviceId, flushedEvents });
    return async () => {
      connected.removeEventListener("message", listener);
      await detachAgent?.();
      if (socket === connected) socket = undefined;
      emit({ source: "session", state: "disconnected", deviceId: connection.deviceId });
    };
  }, {
    signal: controller.signal,
    onConnectionError: error => emitError({ source: "session", state: "retrying", error: error.message }),
  });

  const lines = createInterface({
    input: options.input ?? process.stdin,
    crlfDelay: Infinity,
    terminal: false,
  });
  try {
    for await (const raw of lines) {
      let command: ControlCommand | undefined;
      try {
        command = JSON.parse(raw) as ControlCommand;
        if (!command || typeof command.type !== "string") throw new Error("Command type is required");
        if (command.type === "shutdown") {
          emit({ source: "control", id: command.id, ok: true });
          controller.abort();
          socket?.close();
          break;
        }
        if (command.type === "project.list") {
          send({ version: 1, type: "project.list", requestId: controlRequestId(command.id) });
        } else if (command.type === "project.key.get") {
          const projectId = String(command.projectId);
          projectKeySubscriptions.add(projectId);
          send({
            version: 1,
            type: "project.key.get",
            requestId: controlRequestId(command.id),
            projectId,
            ...(command.keyEpoch === undefined ? {} : { keyEpoch: Number(command.keyEpoch) }),
          });
          emit({ source: "control", id: command.id, ok: true, projectId });
        } else if (command.type === "project.key.share") {
          const projectId = String(command.projectId);
          send({
            version: 1,
            type: "project.key.share",
            requestId: controlRequestId(command.id),
            projectId,
            envelope: command.envelope,
          });
          emit({ source: "control", id: command.id, ok: true, projectId });
        } else if (command.type === "project.key.initialize") {
          if (!identity.projectWrapPublicKeyPem) throw new Error("This client has no project-wrap public key");
          const projectId = String(command.projectId);
          const keyEpoch = Number(command.keyEpoch ?? 1);
          if (loadProjectKey(paths.projectKeys, projectId, keyEpoch)) {
            throw new Error(`Project key epoch ${keyEpoch} already exists locally`);
          }
          if (!Array.isArray(command.recipients) || command.recipients.length < 1 || command.recipients.length > 128) {
            throw new Error("Project key initialization requires 1-128 recipients");
          }
          const projectKey = createProjectKey();
          storeProjectKey(paths.projectKeys, projectId, keyEpoch, projectKey);
          let shared = 0;
          for (const recipient of command.recipients) {
            if (!recipient || typeof recipient !== "object") throw new Error("Project key recipient is invalid");
            const recipientRecord = recipient as Record<string, unknown>;
            const envelope = await sealProjectKeyEnvelope({
              projectId,
              keyEpoch,
              recipientDeviceId: String(recipientRecord.deviceId),
              senderDeviceId: connection.deviceId,
              projectKey,
              recipientProjectWrapPublicKeyPem: String(recipientRecord.projectWrapPublicKeyPem),
              senderPrivateKeyPem: identity.privateKeyPem,
              senderPublicKeyPem: identity.publicKeyPem,
            });
            send({ version: 1, type: "project.key.share", requestId: randomUUID(), projectId, envelope });
            shared += 1;
          }
          projectKeySubscriptions.add(projectId);
          emit({ source: "control", id: command.id, ok: true, projectId, keyEpoch, sharedRecipients: shared });
        } else if (command.type === "project.key.rotate") {
          if (!identity.projectWrapPublicKeyPem) throw new Error("This client has no project-wrap public key");
          const projectId = String(command.projectId);
          const current = loadProjectKeyForEncryption(paths.projectKeys, projectId);
          if (!current) throw new Error(`No project encryption key is available for ${projectId}`);
          const nextEpoch = current.keyEpoch + 1;
          if (!Array.isArray(command.recipients) || command.recipients.length < 1 || command.recipients.length > 128) {
            throw new Error("Project key rotation requires 1-128 recipients");
          }
          const projectKey = createProjectKey();
          const envelopes = [];
          for (const recipient of command.recipients) {
            if (!recipient || typeof recipient !== "object") throw new Error("Project key recipient is invalid");
            const recipientRecord = recipient as Record<string, unknown>;
            envelopes.push(await sealProjectKeyEnvelope({
              projectId,
              keyEpoch: nextEpoch,
              recipientDeviceId: String(recipientRecord.deviceId),
              senderDeviceId: connection.deviceId,
              projectKey,
              recipientProjectWrapPublicKeyPem: String(recipientRecord.projectWrapPublicKeyPem),
              senderPrivateKeyPem: identity.privateKeyPem,
              senderPublicKeyPem: identity.publicKeyPem,
            }));
          }
          const requestId = controlRequestId(command.id);
          send({ version: 1, type: "project.key.rotate", requestId, projectId, expectedEpoch: current.keyEpoch, envelopes });
          projectKeySubscriptions.add(projectId);
          emit({ source: "control", id: command.id, ok: true, projectId, keyEpoch: nextEpoch, recipients: envelopes.length });
        } else if (command.type === "project.member.remove") {
          const projectId = String(command.projectId);
          const deviceId = String(command.deviceId);
          send({ version: 1, type: "project.member.remove", requestId: controlRequestId(command.id), projectId, deviceId });
          emit({ source: "control", id: command.id, ok: true, projectId, deviceId });
        } else if (command.type === "chat.subscribe") {
          const projectId = String(command.projectId);
          const stored = loadProjectKey(paths.projectKeys, projectId);
          if (stored) {
            const afterSequence = Number(command.afterSequence ?? encryptedChatCursors.get(projectId) ?? 0);
            encryptedChatCursors.set(projectId, afterSequence);
            send({
              version: 1,
              type: "project.chat.subscribe",
              requestId: controlRequestId(command.id),
              projectId,
              afterSequence,
            });
          } else {
            const afterSequence = Number(command.afterSequence ?? chatCursors.get(projectId) ?? 0);
            chatCursors.set(projectId, afterSequence);
            send({
              version: 1,
              type: "chat.subscribe",
              requestId: controlRequestId(command.id),
              projectId,
              afterSequence,
            });
          }
        } else if (command.type === "project.chat.subscribe") {
          const projectId = String(command.projectId);
          const afterSequence = Number(command.afterSequence ?? encryptedChatCursors.get(projectId) ?? 0);
          encryptedChatCursors.set(projectId, afterSequence);
          send({
            version: 1,
            type: "project.chat.subscribe",
            requestId: controlRequestId(command.id),
            projectId,
            afterSequence,
          });
        } else if (command.type === "prompt.subscribe") {
          const projectId = String(command.projectId);
          const stored = loadProjectKey(paths.projectKeys, projectId);
          if (stored) {
            const afterSequence = Number(command.afterSequence ?? encryptedPromptCursors.get(projectId) ?? 0);
            encryptedPromptCursors.set(projectId, afterSequence);
            encryptedPromptSubscriptions.add(projectId);
            send({ version: 1, type: "project.prompt.subscribe", requestId: controlRequestId(command.id), projectId, afterSequence });
          } else {
            promptSubscriptions.add(projectId);
            send({
              version: 1,
              type: "prompt.subscribe",
              requestId: controlRequestId(command.id),
              projectId,
            });
          }
        } else if (command.type === "project.prompt.subscribe") {
          const projectId = String(command.projectId);
          const afterSequence = Number(command.afterSequence ?? encryptedPromptCursors.get(projectId) ?? 0);
          encryptedPromptCursors.set(projectId, afterSequence);
          encryptedPromptSubscriptions.add(projectId);
          send({ version: 1, type: "project.prompt.subscribe", requestId: controlRequestId(command.id), projectId, afterSequence });
        } else if (command.type === "context.get") {
          const projectId = String(command.projectId);
          contextSubscriptions.add(projectId);
          send({
            version: 1,
            type: "context.get",
            requestId: controlRequestId(command.id),
            projectId,
          });
        } else if (command.type === "project.context.get") {
          const projectId = String(command.projectId);
          encryptedContextSubscriptions.add(projectId);
          send({ version: 1, type: "project.context.get", requestId: controlRequestId(command.id), projectId });
        } else if (command.type === "project.context.update") {
          const projectId = String(command.projectId);
          const expectedRevision = Number(command.expectedRevision ?? 0);
          const stored = loadProjectKeyForEncryption(paths.projectKeys, projectId, command.keyEpoch === undefined ? undefined : Number(command.keyEpoch));
          if (!stored) throw new Error(`No project encryption key is available for ${projectId}`);
          const payload = {
            finalGoal: String(command.finalGoal ?? ""),
            context: command.context ?? {},
          };
          const serialized = JSON.stringify(payload);
          if (Buffer.byteLength(serialized, "utf8") > PROJECT_CONTEXT_MAX_BYTES) throw new Error("Encrypted project context is too large");
          const envelope = await sealProjectContent({
            projectId,
            keyEpoch: stored.keyEpoch,
            recordType: "shared-context",
            recordId: String(command.recordId ?? randomUUID()),
            plaintext: serialized,
            projectKey: stored.projectKey,
            senderDeviceId: connection.deviceId,
            senderPrivateKeyPem: identity.privateKeyPem,
            senderPublicKeyPem: identity.publicKeyPem,
          });
          encryptedContextSubscriptions.add(projectId);
          enqueueDurableEvent(paths, {
            version: 1,
            type: "project.context.update",
            requestId: controlRequestId(command.id),
            projectId,
            expectedRevision,
            envelope,
          });
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, projectId, revision: expectedRevision + 1 });
        } else if (command.type === "usage.get") {
          const projectId = String(command.projectId);
          usageSubscriptions.add(projectId);
          send({
            version: 1,
            type: "usage.get",
            requestId: controlRequestId(command.id),
            projectId,
          });
        } else if (command.type === "context.update") {
          const projectId = String(command.projectId);
          contextSubscriptions.add(projectId);
          enqueueDurableEvent(paths, {
            version: 1,
            type: "context.update",
            requestId: controlRequestId(command.id),
            projectId,
            expectedRevision: Number(command.expectedRevision ?? 0),
            finalGoal: String(command.finalGoal ?? ""),
            context: command.context ?? {},
          });
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, projectId });
        } else if (command.type === "prompt.update") {
          const updateId = String(command.updateId ?? randomUUID());
          const projectId = String(command.projectId);
          const requestId = controlRequestId(command.id);
          const update = String(command.update);
          const stored = loadProjectKeyForEncryption(paths.projectKeys, projectId);
          if (stored) {
            const frame = await encryptedPromptFrame(projectId, updateId, update, requestId);
            encryptedPromptCursors.set(projectId, encryptedPromptCursors.get(projectId) ?? 0);
            encryptedPromptSubscriptions.add(projectId);
            enqueueDurableEvent(paths, frame);
          } else {
            enqueueDurableEvent(paths, {
              version: 1,
              type: "prompt.update",
              requestId,
              projectId,
              updateId,
              update,
            });
          }
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, updateId, encrypted: Boolean(stored) });
        } else if (command.type === "project.prompt.update") {
          const updateId = String(command.updateId ?? randomUUID());
          const projectId = String(command.projectId);
          const requestId = controlRequestId(command.id);
          const frame = await encryptedPromptFrame(projectId, updateId, String(command.update), requestId);
          encryptedPromptCursors.set(projectId, encryptedPromptCursors.get(projectId) ?? 0);
          encryptedPromptSubscriptions.add(projectId);
          enqueueDurableEvent(paths, frame);
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, updateId, encrypted: true });
        } else if (command.type === "project.chat.send") {
          const projectId = String(command.projectId);
          const eventId = String(command.eventId ?? randomUUID());
          const requestId = controlRequestId(command.id);
          const clientCreatedAt = String(command.clientCreatedAt ?? new Date().toISOString());
          const frame = await encryptedChatFrame(projectId, eventId, String(command.content), requestId, clientCreatedAt);
          encryptedChatCursors.set(projectId, encryptedChatCursors.get(projectId) ?? 0);
          enqueueDurableEvent(paths, frame);
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, eventId, encrypted: true });
        } else if (command.type === "chat.send") {
          const eventId = String(command.eventId ?? randomUUID());
          const projectId = String(command.projectId);
          const requestId = controlRequestId(command.id);
          const clientCreatedAt = String(command.clientCreatedAt ?? new Date().toISOString());
          const stored = loadProjectKeyForEncryption(paths.projectKeys, projectId);
          if (stored) {
            const frame = await encryptedChatFrame(projectId, eventId, String(command.content), requestId, clientCreatedAt);
            encryptedChatCursors.set(projectId, encryptedChatCursors.get(projectId) ?? 0);
            enqueueDurableEvent(paths, frame);
          } else {
            enqueueDurableEvent(paths, {
              version: 1,
              type: "chat.send",
              requestId,
              projectId,
              eventId,
              content: String(command.content),
              clientCreatedAt,
            });
          }
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, eventId, encrypted: Boolean(stored) });
        } else if (command.type === "project.artifact.publish") {
          const projectId = String(command.projectId);
          const artifactId = String(command.artifactId ?? randomUUID());
          const taskId = command.taskId === null || command.taskId === undefined ? null : String(command.taskId);
          const frame = await encryptedArtifactFrame(
            projectId,
            artifactId,
            taskId,
            String(command.artifactType),
            String(command.title),
            String(command.summary),
            String(command.content),
            String(command.status),
            controlRequestId(command.id),
          );
          encryptedArtifactSubscriptions.add(projectId);
          enqueueDurableEvent(paths, frame);
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, artifactId, encrypted: true });
        } else if (command.type === "artifact.publish") {
          const projectId = String(command.projectId);
          const artifactId = String(command.artifactId ?? randomUUID());
          const taskId = command.taskId === null || command.taskId === undefined ? null : String(command.taskId);
          const stored = loadProjectKeyForEncryption(paths.projectKeys, projectId);
          if (stored) {
            const frame = await encryptedArtifactFrame(
              projectId,
              artifactId,
              taskId,
              String(command.artifactType),
              String(command.title),
              String(command.summary),
              String(command.content),
              String(command.status),
              controlRequestId(command.id),
            );
            encryptedArtifactSubscriptions.add(projectId);
            enqueueDurableEvent(paths, frame);
          } else {
            enqueueDurableEvent(paths, {
              version: 1,
              type: "artifact.publish",
              requestId: controlRequestId(command.id),
              artifactId,
              projectId,
              taskId,
              artifactType: String(command.artifactType) as any,
              title: String(command.title),
              summary: String(command.summary),
              content: String(command.content),
              status: String(command.status) as any,
            });
          }
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, artifactId, encrypted: Boolean(stored) });
        } else if (command.type === "project.artifact.list") {
          const projectId = String(command.projectId);
          encryptedArtifactSubscriptions.add(projectId);
          send({ version: 1, type: "project.artifact.list", requestId: controlRequestId(command.id), projectId });
        } else if (command.type === "artifact.list") {
          const projectId = String(command.projectId);
          const stored = loadProjectKeyForEncryption(paths.projectKeys, projectId);
          if (stored) {
            encryptedArtifactSubscriptions.add(projectId);
            send({ version: 1, type: "project.artifact.list", requestId: controlRequestId(command.id), projectId });
          } else {
            send({ version: 1, type: "artifact.list", requestId: controlRequestId(command.id), projectId });
          }
        } else if (command.type === "agent.request") {
          const request = createAgentRequest(
            String(command.projectId),
            String(command.agentId),
            String(command.prompt),
            paths,
            Array.isArray(command.dependencies) ? command.dependencies.map(String) : [],
          );
          enqueueDurableEvent(paths, {
            ...request,
          });
          const delivered = await flush();
          emit({
            source: "control",
            id: command.id,
            ok: true,
            queued: delivered === 0,
            taskId: request.taskId,
          });
        } else if (command.type === "agent.approval") {
          const taskId = String(command.taskId);
          const pending = pendingAgentApprovals.get(taskId);
          if (!pending) throw new Error("Agent task is not awaiting local approval");
          pending(command.approved === true);
          emit({ source: "control", id: command.id, ok: true, taskId, approved: command.approved === true });
        } else if (command.type === "agent.cancel") {
          send({
            version: 1,
            type: "agent.cancel",
            requestId: controlRequestId(command.id),
            taskId: String(command.taskId),
            reason: String(command.reason ?? "Cancelled by the host user."),
          });
          emit({ source: "control", id: command.id, ok: true, taskId: String(command.taskId) });
        } else if (command.type === "presence.update") {
          send({
            version: 1,
            type: "presence.update",
            requestId: controlRequestId(command.id),
            projectId: String(command.projectId),
            cursor: command.cursor ?? null,
            caret: command.caret ?? null,
          });
          emit({ source: "control", id: command.id, ok: true });
        } else if (command.type === "device.trust") {
          const deviceId = String(command.deviceId);
          const fingerprint = String(command.fingerprint);
          trustDevice(paths.trustedDevices, deviceId, fingerprint);
          emit({ source: "control", id: command.id, ok: true, deviceId });
        } else if (command.type === "private.send") {
          const messageId = String(command.messageId ?? randomUUID());
          const clientCreatedAt = String(command.clientCreatedAt ?? new Date().toISOString());
          const recipientDeviceId = String(command.recipientDeviceId);
          const certificate = verifyDeviceKeyCertificate(String(command.recipientKeyCertificate), recipientDeviceId);
          const trustedFingerprint = loadTrustedDevices(paths.trustedDevices)[recipientDeviceId];
          if (!trustedFingerprint || trustedFingerprint !== certificate.fingerprint) {
            throw new Error("Recipient device key certificate does not match the trusted fingerprint");
          }
          const ciphertext = await sealSignedPrivateMessage({
            messageId,
            senderDeviceId: connection.deviceId,
            recipientDeviceId,
            text: String(command.text),
            clientCreatedAt,
          }, identity.privateKeyPem, identity.publicKeyPem, certificate.messagingPublicKeyPem);
          enqueueDurableEvent(paths, {
            version: 1,
            type: "private.send",
            requestId: controlRequestId(command.id),
            messageId,
            recipientDeviceId,
            ciphertext,
            clientCreatedAt,
          });
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, messageId });
        } else {
          throw new Error(`Unknown control command: ${command.type}`);
        }
      } catch (error) {
        emit({
          source: "control",
          id: command?.id,
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  } finally {
    for (const finish of pendingAgentApprovals.values()) finish(false);
    controller.abort();
    socket?.close();
    lines.close();
    await session;
  }
}
