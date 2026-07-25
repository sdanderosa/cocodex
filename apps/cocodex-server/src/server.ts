import { createPublicKey, randomBytes, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import type { ServerWebSocket } from "bun";
import type { Database } from "bun:sqlite";
import {
  clientFrameSchema,
  decodeInvitation,
  enrollmentClaimSchema,
  websocketAuthTranscript,
} from "@cocodex/protocol";
import { appendAgentResult, cancelAgentTask, createAgentTask, expireQueuedAgentTasks, pendingAgentTasks } from "./agent-routing";
import {
  appendEncryptedAgentResult,
  cancelEncryptedAgentTask,
  createEncryptedAgentTask,
  isEncryptedAgentTask,
  pendingEncryptedAgentTasks,
} from "./encrypted-agent-routing";
import { verifyAdminToken, type ServerConfig } from "./config";
import { createEnrollmentChallenge, enrollDevice } from "./enrollment";
import type { ServerIdentity } from "./identity";
import {
  appendChatEventResult,
  chatEventsAfter,
  listProjects,
  requireProjectMembership,
} from "./shared-state";
import { tlsCertificateFingerprint } from "./tls";
import { appendPrivateMessage, privateMessagesAfter } from "./private-messages";
import { appendEncryptedChatEventResult, encryptedChatEventsAfter } from "./encrypted-chat";
import { appendEncryptedPromptUpdateResult, encryptedPromptUpdatesAfter } from "./encrypted-prompt";
import { listEncryptedArtifacts, publishEncryptedArtifact } from "./encrypted-artifacts";
import { applySharedPromptUpdate, sharedPromptSnapshot } from "./shared-prompts";
import { initializeServerAuthority, requireActiveServerAuthority, serverEpoch, serverIdentityFingerprint } from "./server-state";
import { listArtifacts, publishArtifact } from "./artifacts";
import { getSharedProjectContext, updateSharedProjectContext } from "./shared-context";
import { acceptUsageReport, listUsageReports, usageReportProjectIds } from "./usage";
import {
  getEncryptedProjectContext,
  listProjectKeyEnvelopes,
  removeProjectMemberAndInvalidateKeys,
  rotateProjectKeyEpoch,
  shareProjectKeyEnvelope,
  updateEncryptedProjectContext,
} from "./project-encryption-storage";

const MAX_HTTP_BODY_BYTES = 64 * 1024;
const MAX_UNAUTHENTICATED_SOCKETS = 64;
const MAX_UNAUTHENTICATED_SOCKETS_PER_IP = 8;
const MAX_CONNECTION_ATTEMPTS_PER_IP_PER_MINUTE = 30;
const AUTHENTICATION_TIMEOUT_MS = 10_000;
const MAX_PRESENCE_UPDATES_PER_SECOND = 40;

interface SocketData {
  challenge: string;
  authenticatedDeviceId?: string;
  authTimer?: ReturnType<typeof setTimeout>;
  preAuthCounted: boolean;
  remoteAddress: string;
  subscribedProjects: Set<string>;
  subscribedEncryptedChats: Set<string>;
  subscribedPresenceProjects: Set<string>;
  subscribedEncryptedPrompts: Set<string>;
  subscribedEncryptedArtifacts: Set<string>;
  subscribedPrompts: Set<string>;
  subscribedContexts: Set<string>;
  subscribedEncryptedContexts: Set<string>;
  subscribedUsages: Set<string>;
  agentReady: boolean;
}

interface DeviceAuthRow {
  id: string;
  publicKeyPem: string;
  displayName: string;
  status: "pending" | "approved" | "revoked";
}

interface PresenceState {
  deviceId: string;
  displayName: string;
  cursor: { x: number; y: number } | null;
  caret: { anchor: number; head: number } | null;
  typing: boolean;
  updatedAt: string;
}

export interface RunningCoCodexServer {
  hostname: string;
  port: number;
  stop: (closeActiveConnections?: boolean) => Promise<void>;
}

function json(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'",
      "x-content-type-options": "nosniff",
    },
  });
}

function safeErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed";
}

function adminToken(request: Request): string | undefined {
  const value = request.headers.get("authorization");
  if (!value?.startsWith("Bearer ")) return undefined;
  const token = value.slice("Bearer ".length).trim();
  return token || undefined;
}

async function readJsonBody(request: Request): Promise<unknown> {
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > MAX_HTTP_BODY_BYTES) throw new Error("Request body is too large");
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > MAX_HTTP_BODY_BYTES) throw new Error("Request body is too large");
  return JSON.parse(new TextDecoder().decode(bytes));
}

function deviceForAuthentication(db: Database, deviceId: string): DeviceAuthRow | null {
  return db.query(`
    SELECT id, public_key_pem AS publicKeyPem, display_name AS displayName, status
    FROM devices WHERE id = ?
  `).get(deviceId) as DeviceAuthRow | null;
}

export function startCoCodexServer(
  config: ServerConfig,
  db: Database,
  identity: ServerIdentity,
): RunningCoCodexServer {
  const recordedIdentity = serverIdentityFingerprint(db);
  if (recordedIdentity && recordedIdentity !== identity.fingerprint) {
    throw new Error("CoCodex Server identity does not match the active database authority");
  }
  if (!recordedIdentity) initializeServerAuthority(db, identity.fingerprint, "active");
  requireActiveServerAuthority(db);
  const certificateFingerprint = tlsCertificateFingerprint(config.tlsCertificate);
  const sockets = new Set<ServerWebSocket<SocketData>>();
  const presenceByProject = new Map<string, Map<string, PresenceState>>();
  const presenceUpdateTimes = new Map<string, number[]>();
  let unauthenticatedSocketCount = 0;
  const unauthenticatedByIp = new Map<string, number>();
  const connectionAttemptsByIp = new Map<string, number[]>();

  function clearPreAuth(socket: ServerWebSocket<SocketData>): void {
    if (socket.data.authTimer) {
      clearTimeout(socket.data.authTimer);
      socket.data.authTimer = undefined;
    }
    if (socket.data.preAuthCounted) {
      socket.data.preAuthCounted = false;
      unauthenticatedSocketCount -= 1;
      const remaining = (unauthenticatedByIp.get(socket.data.remoteAddress) ?? 1) - 1;
      if (remaining > 0) unauthenticatedByIp.set(socket.data.remoteAddress, remaining);
      else unauthenticatedByIp.delete(socket.data.remoteAddress);
    }
  }

  function sendToDevice(deviceId: string, frame: unknown, requireAgentReady = false): void {
    const device = deviceForAuthentication(db, deviceId);
    if (!device || device.status !== "approved") return;
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      if (socket.data.authenticatedDeviceId === deviceId && (!requireAgentReady || socket.data.agentReady)) {
        socket.send(encoded);
      }
    }
  }

  function sendToProject(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedProjects.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedProjects.delete(projectId);
      }
    }
  }

  function sendToEncryptedChat(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedEncryptedChats.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedEncryptedChats.delete(projectId);
      }
    }
  }

  function sendToEncryptedPrompt(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedEncryptedPrompts.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedEncryptedPrompts.delete(projectId);
      }
    }
  }

  function sendToEncryptedArtifact(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedEncryptedArtifacts.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedEncryptedArtifacts.delete(projectId);
      }
    }
  }

  function sendToPrompt(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedPrompts.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedPrompts.delete(projectId);
      }
    }
  }

  function sendToContext(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedContexts.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedContexts.delete(projectId);
      }
    }
  }

  function sendToEncryptedContext(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedEncryptedContexts.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedEncryptedContexts.delete(projectId);
      }
    }
  }

  function sendToUsage(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedUsages.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedUsages.delete(projectId);
      }
    }
  }

  function sendPresence(projectId: string, frame: unknown): void {
    const encoded = JSON.stringify(frame);
    for (const socket of sockets) {
      const deviceId = socket.data.authenticatedDeviceId;
      if (!deviceId || !socket.data.subscribedPresenceProjects.has(projectId)) continue;
      const device = deviceForAuthentication(db, deviceId);
      if (!device || device.status !== "approved") {
        socket.close(1008, "Device authorization was revoked");
        continue;
      }
      try {
        requireProjectMembership(db, projectId, deviceId);
        socket.send(encoded);
      } catch {
        socket.data.subscribedPresenceProjects.delete(projectId);
      }
    }
  }

  function sendPresenceSnapshot(socket: ServerWebSocket<SocketData>, projectId: string, requestId: string, deviceId: string): void {
    requireProjectMembership(db, projectId, deviceId);
    socket.data.subscribedPresenceProjects.add(projectId);
    socket.send(JSON.stringify({
      version: 1,
      type: "presence.snapshot",
      requestId,
      projectId,
      members: [...(presenceByProject.get(projectId)?.values() ?? [])]
        .filter(member => member.deviceId !== deviceId),
    }));
  }

  function clearPresence(deviceId: string): void {
    presenceUpdateTimes.delete(deviceId);
    for (const projectId of presenceByProject.keys()) clearProjectPresence(projectId, deviceId);
  }

  function clearProjectPresence(projectId: string, deviceId: string): void {
    const members = presenceByProject.get(projectId);
    if (!members?.delete(deviceId)) return;
    sendPresence(projectId, { version: 1, type: "presence.leave", projectId, deviceId });
    if (members.size === 0) presenceByProject.delete(projectId);
  }

  const server = Bun.serve<SocketData>({
    hostname: config.hostname,
    port: config.port,
    tls: {
      cert: readFileSync(config.tlsCertificate),
      key: readFileSync(config.tlsPrivateKey),
    },
    async fetch(request, bunServer) {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/healthz") {
        return json({ ok: true, service: "cocodex-server", protocol: 1 });
      }
      if (request.method === "GET" && url.pathname === "/v1/server-info") {
        return json({
          protocol: 1,
          identityFingerprint: identity.fingerprint,
          certificateFingerprint,
          serverEpoch: serverEpoch(db),
        });
      }
      if (request.method === "GET" && url.pathname === "/v1/admin/status") {
        if (!verifyAdminToken(adminToken(request) ?? "", config.adminTokenHash)) {
          return json({ error: "Admin authentication required" }, 401);
        }
        return json({
          service: "cocodex-server",
          epoch: serverEpoch(db),
          connectedDevices: [...sockets].filter(socket => socket.data.authenticatedDeviceId).length,
          certificateFingerprint,
        });
      }
      if (request.method === "POST" && url.pathname === "/v1/enrollment/challenge") {
        try {
          const body = (await readJsonBody(request)) as Record<string, unknown>;
          if (typeof body.invitationCode !== "string" || typeof body.devicePublicKeyPem !== "string") {
            return json({ error: "Invalid enrollment challenge request" }, 400);
          }
          const invitation = decodeInvitation(body.invitationCode);
          const challenge = createEnrollmentChallenge(
            db,
            invitation,
            body.devicePublicKeyPem,
            certificateFingerprint,
          );
          return json(challenge, 201);
        } catch (error) {
          return json({ error: safeErrorMessage(error) }, 400);
        }
      }
      if (request.method === "POST" && url.pathname === "/v1/enroll") {
        try {
          const body = enrollmentClaimSchema.parse(await readJsonBody(request));
          const invitation = decodeInvitation(body.invitationCode);
          if (invitation.serverFingerprint !== certificateFingerprint) {
            return json({ error: "Invitation does not belong to this server" }, 400);
          }
          const device = enrollDevice(db, {
            invitation,
            challengeId: body.challengeId,
            challenge: body.challenge,
            displayName: body.displayName,
            devicePublicKeyPem: body.devicePublicKeyPem,
            messagingPublicKeyPem: body.messagingPublicKeyPem,
            projectWrapPublicKeyPem: body.projectWrapPublicKeyPem,
            signature: body.signature,
          });
          return json({ device, approvalRequired: true, serverIdentityPublicKeyPem: identity.publicKeyPem, serverEpoch: serverEpoch(db) }, 202);
        } catch (error) {
          return json({ error: safeErrorMessage(error) }, 400);
        }
      }
      if (url.pathname === "/v1/connect") {
        const remoteAddress = bunServer.requestIP(request)?.address ?? "unknown";
        const cutoff = Date.now() - 60_000;
        const attempts = (connectionAttemptsByIp.get(remoteAddress) ?? [])
          .filter(timestamp => timestamp > cutoff);
        if (attempts.length >= MAX_CONNECTION_ATTEMPTS_PER_IP_PER_MINUTE) {
          return json({ error: "Connection rate limit exceeded" }, 429);
        }
        attempts.push(Date.now());
        connectionAttemptsByIp.set(remoteAddress, attempts);
        if (unauthenticatedSocketCount >= MAX_UNAUTHENTICATED_SOCKETS) {
          return json({ error: "Too many unauthenticated connections" }, 503);
        }
        if ((unauthenticatedByIp.get(remoteAddress) ?? 0) >= MAX_UNAUTHENTICATED_SOCKETS_PER_IP) {
          return json({ error: "Too many unauthenticated connections from this address" }, 429);
        }
        const challenge = randomBytes(32).toString("base64url");
        unauthenticatedSocketCount += 1;
        unauthenticatedByIp.set(remoteAddress, (unauthenticatedByIp.get(remoteAddress) ?? 0) + 1);
        const data: SocketData = {
          challenge,
          preAuthCounted: true,
          remoteAddress,
          subscribedProjects: new Set(),
          subscribedEncryptedChats: new Set(),
          subscribedPresenceProjects: new Set(),
          subscribedEncryptedPrompts: new Set(),
          subscribedEncryptedArtifacts: new Set(),
          subscribedPrompts: new Set(),
          subscribedContexts: new Set(),
          subscribedEncryptedContexts: new Set(),
          subscribedUsages: new Set(),
          agentReady: false,
        };
        if (bunServer.upgrade(request, { data })) return;
        unauthenticatedSocketCount -= 1;
        const remaining = (unauthenticatedByIp.get(remoteAddress) ?? 1) - 1;
        if (remaining > 0) unauthenticatedByIp.set(remoteAddress, remaining);
        else unauthenticatedByIp.delete(remoteAddress);
        return json({ error: "WebSocket upgrade failed" }, 400);
      }
      return json({ error: "Not found" }, 404);
    },
    websocket: {
      maxPayloadLength: MAX_HTTP_BODY_BYTES,
      open(socket) {
        sockets.add(socket);
        socket.data.authTimer = setTimeout(() => {
          clearPreAuth(socket);
          socket.close(1008, "Authentication timed out");
        }, AUTHENTICATION_TIMEOUT_MS);
        socket.send(JSON.stringify({
          type: "auth.challenge",
          protocol: 1,
          challenge: socket.data.challenge,
        }));
      },
      message(socket, rawMessage) {
        let requestId: string | undefined;
        try {
          const message = clientFrameSchema.parse(JSON.parse(String(rawMessage)));
          requestId = message.requestId;
          if (!socket.data.authenticatedDeviceId) {
            if (message.type !== "auth.response") throw new Error("Authentication is required");
            const device = deviceForAuthentication(db, message.deviceId);
            if (!device || device.status !== "approved") throw new Error("Device is not approved");
            const publicKey = createPublicKey(device.publicKeyPem);
            const valid = verify(
              null,
              websocketAuthTranscript({
                serverFingerprint: certificateFingerprint,
                deviceId: device.id,
                requestId: message.requestId,
                challenge: socket.data.challenge,
              }),
              publicKey,
              Buffer.from(message.signature, "base64url"),
            );
            if (!valid) throw new Error("Invalid device proof");
            socket.data.authenticatedDeviceId = device.id;
            clearPreAuth(socket);
            socket.send(JSON.stringify({
              version: 1,
              type: "auth.ok",
              requestId,
              deviceId: device.id,
              serverIdentityPublicKeyPem: identity.publicKeyPem,
              serverEpoch: serverEpoch(db),
            }));
            return;
          }
          if (message.type === "auth.response") throw new Error("Device is already authenticated");
          const deviceId = socket.data.authenticatedDeviceId;
          const currentDevice = deviceForAuthentication(db, deviceId);
          if (!currentDevice || currentDevice.status !== "approved") {
            socket.close(1008, "Device authorization was revoked");
            return;
          }
          for (const expired of expireQueuedAgentTasks(db)) {
            sendToProject(expired.task.projectId, {
              version: 1,
              type: "agent.result",
              taskId: expired.task.id,
              final: true,
              status: "failed",
              event: expired.event,
            });
          }
          if (message.type === "agent.ready") {
            socket.data.agentReady = true;
            for (const task of pendingAgentTasks(db, deviceId)) {
              socket.send(JSON.stringify({ version: 1, type: "agent.task", task }));
            }
            for (const task of pendingEncryptedAgentTasks(db, deviceId)) {
              socket.send(JSON.stringify({ version: 1, type: "project.agent.task", task }));
            }
            socket.send(JSON.stringify({
              version: 1,
              type: "agent.ready.accepted",
              requestId,
            }));
            return;
          }
          if (message.type === "project.list") {
            socket.send(JSON.stringify({
              version: 1,
              type: "project.list.result",
              requestId,
              projects: listProjects(db, deviceId),
            }));
            return;
          }
          if (message.type === "project.chat.subscribe") {
            const events = encryptedChatEventsAfter(db, message.projectId, deviceId, message.afterSequence);
            socket.data.subscribedEncryptedChats.add(message.projectId);
            sendPresenceSnapshot(socket, message.projectId, requestId, deviceId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.chat.snapshot",
              requestId,
              projectId: message.projectId,
              events,
            }));
            return;
          }
          if (message.type === "project.chat.send") {
            const appended = appendEncryptedChatEventResult(db, {
              projectId: message.projectId,
              eventId: message.eventId,
              senderDeviceId: deviceId,
              envelope: message.envelope,
              clientCreatedAt: message.clientCreatedAt,
            });
            socket.data.subscribedEncryptedChats.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.chat.accepted",
              requestId,
              projectId: message.projectId,
              event: appended.event,
            }));
            if (appended.created) {
              sendToEncryptedChat(message.projectId, {
                version: 1,
                type: "project.chat.event",
                event: appended.event,
              });
            }
            return;
          }
          if (message.type === "project.prompt.subscribe") {
            const updates = encryptedPromptUpdatesAfter(db, message.projectId, deviceId, message.afterSequence);
            socket.data.subscribedEncryptedPrompts.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.prompt.snapshot",
              requestId,
              projectId: message.projectId,
              updates,
            }));
            return;
          }
          if (message.type === "project.prompt.update") {
            const appended = appendEncryptedPromptUpdateResult(db, {
              projectId: message.projectId,
              updateId: message.updateId,
              senderDeviceId: deviceId,
              envelope: message.envelope,
            });
            socket.data.subscribedEncryptedPrompts.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.prompt.accepted",
              requestId,
              projectId: message.projectId,
              update: appended.update,
            }));
            if (appended.created) {
              sendToEncryptedPrompt(message.projectId, {
                version: 1,
                type: "project.prompt.changed",
                update: appended.update,
              });
            }
            return;
          }
          if (message.type === "project.artifact.publish") {
            const published = publishEncryptedArtifact(db, {
              artifactId: message.artifactId,
              projectId: message.projectId,
              taskId: message.taskId,
              authorDeviceId: deviceId,
              envelope: message.envelope,
            });
            socket.data.subscribedEncryptedArtifacts.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.artifact.accepted",
              requestId,
              projectId: message.projectId,
              artifact: published.artifact,
            }));
            if (published.created) {
              sendToEncryptedArtifact(message.projectId, {
                version: 1,
                type: "project.artifact.published",
                artifact: published.artifact,
              });
            }
            return;
          }
          if (message.type === "project.artifact.list") {
            socket.data.subscribedEncryptedArtifacts.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.artifact.list.result",
              requestId,
              projectId: message.projectId,
              artifacts: listEncryptedArtifacts(db, message.projectId, deviceId),
            }));
            return;
          }
          if (message.type === "chat.subscribe") {
            const events = chatEventsAfter(db, message.projectId, deviceId, message.afterSequence);
            socket.data.subscribedProjects.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "chat.snapshot",
              requestId,
              projectId: message.projectId,
              events,
            }));
            sendPresenceSnapshot(socket, message.projectId, requestId, deviceId);
            return;
          }
          if (message.type === "agent.cancel") {
            if (isEncryptedAgentTask(db, message.taskId)) {
              const cancelled = cancelEncryptedAgentTask(db, deviceId, message.taskId);
              sendToDevice(cancelled.task.targetDeviceId, {
                version: 1,
                type: "agent.cancel",
                taskId: cancelled.task.id,
                reason: message.reason,
              });
              socket.send(JSON.stringify({
                version: 1,
                type: "agent.cancelled",
                requestId,
                taskId: cancelled.task.id,
              }));
              return;
            }
            const cancelled = cancelAgentTask(db, deviceId, message.taskId, message.reason);
            if (cancelled.created) {
              sendToDevice(cancelled.task.targetDeviceId, {
                version: 1,
                type: "agent.cancel",
                taskId: cancelled.task.id,
                reason: message.reason,
              }, true);
              sendToProject(cancelled.task.projectId, {
                version: 1,
                type: "agent.result",
                taskId: cancelled.task.id,
                final: true,
                status: "failed",
                event: cancelled.event,
              });
            }
            socket.send(JSON.stringify({
              version: 1,
              type: "agent.cancelled",
              requestId,
              taskId: cancelled.task.id,
              sequence: cancelled.event.sequence,
            }));
            return;
          }
          if (message.type === "presence.update") {
            requireProjectMembership(db, message.projectId, deviceId);
            const now = Date.now();
            const recentUpdates = (presenceUpdateTimes.get(deviceId) ?? [])
              .filter(timestamp => timestamp > now - 1_000);
            if (recentUpdates.length >= MAX_PRESENCE_UPDATES_PER_SECOND) {
              presenceUpdateTimes.set(deviceId, recentUpdates);
              socket.send(JSON.stringify({
                version: 1,
                type: "error",
                requestId,
                error: "Presence update rate limit exceeded",
              }));
              return;
            }
            recentUpdates.push(now);
            presenceUpdateTimes.set(deviceId, recentUpdates);
            const member = {
              deviceId,
              displayName: currentDevice.displayName,
              cursor: message.cursor,
              caret: message.caret,
              typing: message.typing,
              updatedAt: new Date().toISOString(),
            } satisfies PresenceState;
            const members = presenceByProject.get(message.projectId) ?? new Map<string, PresenceState>();
            const active = Boolean(message.cursor || message.caret || message.typing);
            if (!active) members.delete(deviceId);
            else members.set(deviceId, member);
            if (members.size === 0) presenceByProject.delete(message.projectId);
            else presenceByProject.set(message.projectId, members);
            sendPresence(message.projectId, {
              version: 1,
              type: active ? "presence.update" : "presence.leave",
              projectId: message.projectId,
              ...member,
            });
            socket.send(JSON.stringify({ version: 1, type: "presence.accepted", requestId, projectId: message.projectId }));
            return;
          }
          if (message.type === "prompt.subscribe") {
            requireProjectMembership(db, message.projectId, deviceId);
            socket.data.subscribedPrompts.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "prompt.snapshot",
              requestId,
              projectId: message.projectId,
              update: sharedPromptSnapshot(db, message.projectId, deviceId),
            }));
            return;
          }
          if (message.type === "prompt.update") {
            const applied = applySharedPromptUpdate(
              db, message.projectId, deviceId, message.updateId, message.update,
            );
            socket.send(JSON.stringify({
              version: 1,
              type: "prompt.accepted",
              requestId,
              projectId: message.projectId,
              updateId: message.updateId,
            }));
            if (applied.created) {
              sendToPrompt(message.projectId, {
                version: 1,
                type: "prompt.update",
                projectId: message.projectId,
                updateId: message.updateId,
                senderDeviceId: deviceId,
                update: message.update,
              });
            }
            return;
          }
          if (message.type === "private.subscribe") {
            socket.send(JSON.stringify({
              version: 1,
              type: "private.snapshot",
              requestId,
              messages: privateMessagesAfter(db, deviceId, message.afterSequence),
            }));
            return;
          }
          if (message.type === "private.send") {
            const appended = appendPrivateMessage(db, {
              messageId: message.messageId,
              senderDeviceId: deviceId,
              recipientDeviceId: message.recipientDeviceId,
              ciphertext: message.ciphertext,
              clientCreatedAt: message.clientCreatedAt,
            });
            socket.send(JSON.stringify({
              version: 1,
              type: "private.accepted",
              requestId,
              message: appended.envelope,
            }));
            if (appended.created) {
              sendToDevice(appended.envelope.recipientDeviceId, {
                version: 1,
                type: "private.message",
                message: appended.envelope,
              });
            }
            return;
          }
          if (message.type === "artifact.publish") {
            const published = publishArtifact(db, {
              id: message.artifactId,
              projectId: message.projectId,
              taskId: message.taskId,
              authorDeviceId: deviceId,
              type: message.artifactType,
              title: message.title,
              summary: message.summary,
              content: message.content,
              status: message.status,
            });
            socket.send(JSON.stringify({ version: 1, type: "artifact.accepted", requestId, artifact: published.artifact }));
            if (published.created) sendToProject(message.projectId, { version: 1, type: "artifact.published", artifact: published.artifact });
            return;
          }
          if (message.type === "project.key.get") {
            socket.send(JSON.stringify({
              version: 1,
              type: "project.key.result",
              requestId,
              projectId: message.projectId,
              envelopes: listProjectKeyEnvelopes(db, message.projectId, deviceId, message.keyEpoch),
            }));
            return;
          }
          if (message.type === "project.key.share") {
            const shared = shareProjectKeyEnvelope(db, message.projectId, deviceId, message.envelope);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.key.accepted",
              requestId,
              projectId: message.projectId,
              envelope: shared.envelope,
              created: shared.created,
            }));
            if (shared.created) {
              sendToDevice(shared.envelope.recipientDeviceId, {
                version: 1,
                type: "project.key.changed",
                projectId: message.projectId,
                envelope: shared.envelope,
              });
            }
            return;
          }
          if (message.type === "project.key.rotate") {
            const rotated = rotateProjectKeyEpoch(
              db,
              message.projectId,
              deviceId,
              message.expectedEpoch,
              message.requestId,
              message.envelopes,
            );
            socket.send(JSON.stringify({
              version: 1,
              type: "project.key.rotated",
              requestId,
              projectId: message.projectId,
              keyEpoch: rotated.keyEpoch,
              envelopes: rotated.envelopes,
              created: rotated.created,
            }));
            if (rotated.created) {
              for (const envelope of rotated.envelopes) {
                sendToDevice(envelope.recipientDeviceId, {
                  version: 1,
                  type: "project.key.changed",
                  projectId: message.projectId,
                  envelope,
                });
              }
            }
            return;
          }
          if (message.type === "project.member.remove") {
            removeProjectMemberAndInvalidateKeys(db, message.projectId, deviceId, message.deviceId);
            clearProjectPresence(message.projectId, message.deviceId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.member.removed",
              requestId,
              projectId: message.projectId,
              deviceId: message.deviceId,
            }));
            sendToDevice(message.deviceId, {
              version: 1,
              type: "project.member.removed",
              projectId: message.projectId,
              deviceId: message.deviceId,
            });
            return;
          }
          if (message.type === "project.context.get") {
            const record = getEncryptedProjectContext(db, message.projectId, deviceId);
            socket.data.subscribedEncryptedContexts.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.context.result",
              requestId,
              projectId: message.projectId,
              envelope: record?.envelope ?? null,
              revision: record?.revision ?? 0,
              updatedAt: record?.updatedAt ?? null,
            }));
            return;
          }
          if (message.type === "project.context.update") {
            const updated = updateEncryptedProjectContext(
              db,
              message.projectId,
              deviceId,
              message.expectedRevision,
              message.envelope,
            );
            socket.data.subscribedEncryptedContexts.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "project.context.updated",
              requestId,
              projectId: message.projectId,
              envelope: updated.envelope,
              revision: updated.revision,
              created: updated.created,
              updatedAt: updated.updatedAt,
            }));
            if (updated.created) {
              sendToEncryptedContext(message.projectId, {
                version: 1,
                type: "project.context.changed",
                projectId: message.projectId,
                envelope: updated.envelope,
                revision: updated.revision,
                updatedAt: updated.updatedAt,
              });
            }
            return;
          }
          if (message.type === "context.get") {
            requireProjectMembership(db, message.projectId, deviceId);
            socket.data.subscribedContexts.add(message.projectId);
            socket.send(JSON.stringify({ version: 1, type: "context.result", requestId, context: getSharedProjectContext(db, message.projectId, deviceId) }));
            return;
          }
          if (message.type === "context.update") {
            const context = updateSharedProjectContext(db, message.projectId, deviceId, message.expectedRevision, message.finalGoal, message.context);
            socket.data.subscribedContexts.add(message.projectId);
            socket.send(JSON.stringify({ version: 1, type: "context.updated", requestId, context }));
            sendToContext(message.projectId, { version: 1, type: "context.changed", context });
            return;
          }
          if (message.type === "usage.get") {
            socket.data.subscribedUsages.add(message.projectId);
            socket.send(JSON.stringify({
              version: 1,
              type: "usage.result",
              requestId,
              projectId: message.projectId,
              reports: listUsageReports(db, message.projectId, deviceId),
            }));
            return;
          }
          if (message.type === "usage.report") {
            const accepted = acceptUsageReport(db, deviceId, {
              report: message.report,
              signature: message.signature,
            });
            socket.send(JSON.stringify({
              version: 1,
              type: "usage.accepted",
              requestId,
              report: accepted.view,
            }));
            if (accepted.created) {
              for (const projectId of usageReportProjectIds(db, deviceId)) {
                sendToUsage(projectId, {
                  version: 1,
                  type: "usage.changed",
                  report: accepted.view,
                });
              }
            }
            return;
          }
          if (message.type === "artifact.list") {
            socket.send(JSON.stringify({ version: 1, type: "artifact.list.result", requestId, projectId: message.projectId, artifacts: listArtifacts(db, message.projectId, deviceId) }));
            return;
          }
          if (message.type === "agent.request") {
            const { task, created } = createAgentTask(db, identity, {
              id: message.taskId,
              projectId: message.projectId,
              requesterDeviceId: deviceId,
              agentId: message.agentId,
              prompt: message.prompt,
              nonce: message.nonce,
              issuedAt: message.issuedAt,
              expiresAt: message.expiresAt,
              dependencies: message.dependencies,
              requesterSignature: message.signature,
            });
            if (created && pendingAgentTasks(db, task.targetDeviceId).some(ready => ready.id === task.id)) {
              sendToDevice(task.targetDeviceId, {
                version: 1,
                type: "agent.task",
                task,
              }, true);
            }
            socket.send(JSON.stringify({
              version: 1,
              type: "agent.accepted",
              requestId,
              task,
            }));
            return;
          }
          if (message.type === "project.agent.request") {
            const { task, created } = createEncryptedAgentTask(db, identity, {
              id: message.taskId,
              projectId: message.projectId,
              requesterDeviceId: deviceId,
              agentId: message.agentId,
              nonce: message.nonce,
              issuedAt: message.issuedAt,
              expiresAt: message.expiresAt,
              dependencies: message.dependencies,
              envelope: message.envelope,
            });
            if (created && pendingEncryptedAgentTasks(db, task.targetDeviceId).some(ready => ready.id === task.id)) {
              sendToDevice(task.targetDeviceId, { version: 1, type: "project.agent.task", task }, true);
            }
            socket.send(JSON.stringify({ version: 1, type: "project.agent.accepted", requestId, task }));
            return;
          }
          if (message.type === "agent.result") {
            const result = appendAgentResult(
              db,
              deviceId,
              message.taskId,
              message.eventId,
              message.content,
              message.final,
              message.status,
            );
            if (result.created) {
              sendToProject(result.task.projectId, {
                version: 1,
                type: "agent.result",
                taskId: result.task.id,
                final: message.final,
                status: message.status,
                event: result.event,
              });
              if (message.final) {
                for (const ready of pendingAgentTasks(db, result.task.targetDeviceId)) {
                  sendToDevice(ready.targetDeviceId, { version: 1, type: "agent.task", task: ready }, true);
                }
              }
            }
            socket.send(JSON.stringify({
              version: 1,
              type: "agent.result.accepted",
              requestId,
              taskId: result.task.id,
              sequence: result.event.sequence,
            }));
            return;
          }
          if (message.type === "project.agent.result") {
            const result = appendEncryptedAgentResult(db, {
              taskId: message.taskId,
              eventId: message.eventId,
              targetDeviceId: deviceId,
              envelope: message.envelope,
              final: message.final,
              status: message.status,
            });
            if (result.created) {
              sendToEncryptedChat(result.task.projectId, {
                version: 1,
                type: "project.agent.result",
                taskId: result.task.id,
                final: message.final,
                status: message.status,
                event: result.event,
              });
              if (message.final) {
                for (const ready of pendingEncryptedAgentTasks(db, result.task.targetDeviceId)) {
                  sendToDevice(ready.targetDeviceId, { version: 1, type: "project.agent.task", task: ready }, true);
                }
              }
            }
            socket.send(JSON.stringify({
              version: 1,
              type: "project.agent.result.accepted",
              requestId,
              taskId: result.task.id,
              sequence: result.event.sequence,
            }));
            return;
          }
          const appended = appendChatEventResult(db, {
            projectId: message.projectId,
            eventId: message.eventId,
            senderDeviceId: deviceId,
            content: message.content,
            clientCreatedAt: message.clientCreatedAt,
          });
          socket.send(JSON.stringify({
            version: 1,
            type: "chat.accepted",
            requestId,
            event: appended.event,
          }));
          if (appended.created) {
            sendToProject(message.projectId, {
              version: 1,
              type: "chat.event",
              event: appended.event,
            });
          }
        } catch (error) {
          const authenticated = Boolean(socket.data.authenticatedDeviceId);
          socket.send(JSON.stringify({
            version: 1,
            type: authenticated ? "error" : "auth.error",
            requestId,
            error: safeErrorMessage(error),
          }));
          if (!authenticated) {
            clearPreAuth(socket);
            socket.close(1008, "Authentication failed");
          }
        }
      },
      close(socket) {
        clearPreAuth(socket);
        sockets.delete(socket);
        const deviceId = socket.data.authenticatedDeviceId;
        if (deviceId && ![...sockets].some(other => other.data.authenticatedDeviceId === deviceId)) {
          clearPresence(deviceId);
        }
      },
    },
  });
  return {
    hostname: server.hostname ?? config.hostname,
    port: server.port ?? config.port,
    stop: async (closeActiveConnections = false) => {
      if (closeActiveConnections) {
        for (const socket of sockets) socket.close(1001, "Server shutting down");
        sockets.clear();
      }
      const stopping = server.stop(closeActiveConnections);
      if (!closeActiveConnections) {
        await stopping;
        return;
      }
      await Promise.race([stopping, Bun.sleep(1_000)]);
      server.unref();
    },
  };
}
