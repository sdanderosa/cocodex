import { createPublicKey, randomBytes, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Database } from "bun:sqlite";
import { clientFrameSchema, decodeInvitation, enrollmentClaimSchema } from "@cocodex/protocol";
import type { ServerConfig } from "./config";
import { createEnrollmentChallenge, enrollDevice } from "./enrollment";
import type { ServerIdentity } from "./identity";
import { appendChatEvent, chatEventsAfter, listProjects } from "./shared-state";
import { tlsCertificateFingerprint } from "./tls";

const MAX_HTTP_BODY_BYTES = 64 * 1024;
const AUTH_CONTEXT = "cocodex-websocket-auth-v1";

interface SocketData {
  challenge: string;
  authenticatedDeviceId?: string;
}

interface DeviceAuthRow {
  id: string;
  publicKeyPem: string;
  status: "pending" | "approved" | "revoked";
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

async function readJsonBody(request: Request): Promise<unknown> {
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > MAX_HTTP_BODY_BYTES) throw new Error("Request body is too large");
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > MAX_HTTP_BODY_BYTES) throw new Error("Request body is too large");
  return JSON.parse(new TextDecoder().decode(bytes));
}

function deviceForAuthentication(db: Database, deviceId: string): DeviceAuthRow | null {
  return db.query(`
    SELECT id, public_key_pem AS publicKeyPem, status
    FROM devices WHERE id = ?
  `).get(deviceId) as DeviceAuthRow | null;
}

export function websocketAuthMessage(challenge: string): string {
  return `${AUTH_CONTEXT}\n${challenge}`;
}

export function startCoCodexServer(
  config: ServerConfig,
  db: Database,
  identity: ServerIdentity,
): RunningCoCodexServer {
  const certificateFingerprint = tlsCertificateFingerprint(config.tlsCertificate);
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
            signature: body.signature,
          });
          return json({ device, approvalRequired: true }, 202);
        } catch (error) {
          return json({ error: safeErrorMessage(error) }, 400);
        }
      }
      if (url.pathname === "/v1/connect") {
        const challenge = randomBytes(32).toString("base64url");
        if (bunServer.upgrade(request, { data: { challenge } })) return;
        return json({ error: "WebSocket upgrade failed" }, 400);
      }
      return json({ error: "Not found" }, 404);
    },
    websocket: {
      maxPayloadLength: MAX_HTTP_BODY_BYTES,
      open(socket) {
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
              Buffer.from(websocketAuthMessage(socket.data.challenge), "utf8"),
              publicKey,
              Buffer.from(message.signature, "base64url"),
            );
            if (!valid) throw new Error("Invalid device proof");
            socket.data.authenticatedDeviceId = device.id;
            socket.send(JSON.stringify({
              version: 1,
              type: "auth.ok",
              requestId,
              deviceId: device.id,
            }));
            return;
          }
          if (message.type === "auth.response") throw new Error("Device is already authenticated");
          const deviceId = socket.data.authenticatedDeviceId;
          if (message.type === "project.list") {
            socket.send(JSON.stringify({
              version: 1,
              type: "project.list.result",
              requestId,
              projects: listProjects(db, deviceId),
            }));
            return;
          }
          if (message.type === "chat.subscribe") {
            const events = chatEventsAfter(db, message.projectId, deviceId, message.afterSequence);
            socket.subscribe(`project:${message.projectId}`);
            socket.send(JSON.stringify({
              version: 1,
              type: "chat.snapshot",
              requestId,
              projectId: message.projectId,
              events,
            }));
            return;
          }
          const event = appendChatEvent(db, {
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
            event,
          }));
          server.publish(`project:${message.projectId}`, JSON.stringify({
            version: 1,
            type: "chat.event",
            event,
          }));
        } catch (error) {
          const authenticated = Boolean(socket.data.authenticatedDeviceId);
          socket.send(JSON.stringify({
            version: 1,
            type: authenticated ? "error" : "auth.error",
            requestId,
            error: safeErrorMessage(error),
          }));
          if (!authenticated) socket.close(1008, "Authentication failed");
        }
      },
    },
  });
  return {
    hostname: server.hostname ?? config.hostname,
    port: server.port ?? config.port,
    stop: (closeActiveConnections = false) => server.stop(closeActiveConnections),
  };
}
