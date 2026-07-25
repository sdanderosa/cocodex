import { randomUUID, sign } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  decodeInvitation,
  enrollmentSigningTranscript,
  type InvitationPayload,
} from "@cocodex/protocol";
import { loadOrCreateClientIdentity } from "./identity";
import { clientPaths, type ClientPaths } from "./paths";
import { readAndVerifyServerCertificate } from "./tls-pin";

export interface ClientConnection {
  version: 1;
  host: string;
  port: number;
  serverFingerprint: string;
  serverCertificatePem: string;
  deviceId: string;
  displayName: string;
}

function serverOrigin(invitation: InvitationPayload): string {
  const host = invitation.host.includes(":") ? `[${invitation.host}]` : invitation.host;
  return `https://${host}:${invitation.port}`;
}

async function postPinned(
  invitation: InvitationPayload,
  certificatePem: string,
  path: string,
  body: unknown,
): Promise<any> {
  const response = await fetch(`${serverOrigin(invitation)}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    tls: { ca: certificatePem, rejectUnauthorized: true },
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value?.error || `CoCodex Server returned HTTP ${response.status}`);
  return value;
}

export async function enrollClient(
  invitationCode: string,
  displayName: string,
  paths: ClientPaths = clientPaths(),
): Promise<ClientConnection> {
  if (existsSync(paths.connection)) throw new Error("This CoCodex Client is already enrolled");
  const invitation = decodeInvitation(invitationCode);
  const certificate = await readAndVerifyServerCertificate(
    invitation.host,
    invitation.port,
    invitation.serverFingerprint,
  );
  const identity = loadOrCreateClientIdentity(paths);
  const challenge = await postPinned(invitation, certificate.pem, "/v1/enrollment/challenge", {
    invitationCode,
    devicePublicKeyPem: identity.publicKeyPem,
  }) as { id: string; challenge: string };
  const signature = sign(null, enrollmentSigningTranscript({
    serverFingerprint: invitation.serverFingerprint,
    invitationId: invitation.invitationId,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: identity.publicKeyPem,
  }), identity.privateKeyPem).toString("base64url");
  const enrolled = await postPinned(invitation, certificate.pem, "/v1/enroll", {
    version: 1,
    invitationCode,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: identity.publicKeyPem,
    signature,
  }) as { device: { id: string } };
  const connection: ClientConnection = {
    version: 1,
    host: invitation.host,
    port: invitation.port,
    serverFingerprint: invitation.serverFingerprint,
    serverCertificatePem: certificate.pem,
    deviceId: enrolled.device.id,
    displayName: displayName.trim(),
  };
  writeFileSync(paths.connection, `${JSON.stringify(connection, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  return connection;
}

export function loadClientConnection(paths: ClientPaths = clientPaths()): ClientConnection {
  return JSON.parse(readFileSync(paths.connection, "utf8")) as ClientConnection;
}

export async function connectAuthenticatedClient(paths: ClientPaths = clientPaths()): Promise<WebSocket> {
  const connection = loadClientConnection(paths);
  const identity = loadOrCreateClientIdentity(paths);
  const host = connection.host.includes(":") ? `[${connection.host}]` : connection.host;
  const socket = new WebSocket(`wss://${host}:${connection.port}/v1/connect`, {
    tls: { ca: connection.serverCertificatePem, rejectUnauthorized: true },
  } as never);
  return await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error("Timed out while authenticating with CoCodex Server"));
    }, 10_000);
    socket.addEventListener("message", event => {
      try {
        const frame = JSON.parse(String(event.data)) as Record<string, unknown>;
        if (frame.type === "auth.challenge") {
          socket.send(JSON.stringify({
            version: 1,
            type: "auth.response",
            requestId: randomUUID(),
            deviceId: connection.deviceId,
            signature: sign(
              null,
              Buffer.from(`cocodex-websocket-auth-v1\n${String(frame.challenge)}`),
              identity.privateKeyPem,
            ).toString("base64url"),
          }));
        } else if (frame.type === "auth.ok") {
          clearTimeout(timeout);
          resolve(socket);
        } else if (frame.type === "auth.error") {
          throw new Error(String(frame.error));
        }
      } catch (error) {
        clearTimeout(timeout);
        socket.close();
        reject(error);
      }
    });
    socket.addEventListener("error", () => {
      clearTimeout(timeout);
      reject(new Error("CoCodex Server connection failed"));
    }, { once: true });
  });
}
