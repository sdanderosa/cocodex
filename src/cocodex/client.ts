import { createHash, createPublicKey, randomBytes, randomUUID, sign, verify, X509Certificate } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import {
  agentRequestSigningTranscript,
  decodeInvitation,
  enrollmentSigningTranscript,
  websocketAuthTranscript,
  canonicalEd25519PublicKey,
  decodeServerAuthorityCertificate,
  publicKeyFingerprint,
  serverAuthorityCertificateSigningTranscript,
  type InvitationPayload,
} from "@cocodex/protocol";
import { loadOrCreateClientIdentity } from "./identity";
import { clientPaths, type ClientPaths } from "./paths";
import { readAndVerifyServerCertificate } from "./tls-pin";
import { hardenSecretPath } from "../lib/windows-secret-acl";

export interface ClientConnection {
  version: 1;
  host: string;
  port: number;
  serverFingerprint: string;
  serverCertificatePem: string;
  serverIdentityPublicKeyPem: string;
  deviceId: string;
  displayName: string;
  serverEpoch: number;
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
    messagingPublicKeyPem: identity.messagingPublicKeyPem,
    projectWrapPublicKeyPem: identity.projectWrapPublicKeyPem,
  }) as { id: string; challenge: string };
  const signature = sign(null, enrollmentSigningTranscript({
    serverFingerprint: invitation.serverFingerprint,
    invitationId: invitation.invitationId,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: identity.publicKeyPem,
    messagingPublicKeyPem: identity.messagingPublicKeyPem,
    projectWrapPublicKeyPem: identity.projectWrapPublicKeyPem,
  }), identity.privateKeyPem).toString("base64url");
  const enrolled = await postPinned(invitation, certificate.pem, "/v1/enroll", {
    version: 1 as const,
    invitationCode,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: identity.publicKeyPem,
    messagingPublicKeyPem: identity.messagingPublicKeyPem,
    projectWrapPublicKeyPem: identity.projectWrapPublicKeyPem,
    signature,
  }) as { device: { id: string }; serverIdentityPublicKeyPem: string; serverEpoch: number };
  if (!Number.isSafeInteger(enrolled.serverEpoch) || enrolled.serverEpoch < 1) {
    throw new Error("CoCodex Server returned an invalid authority epoch during enrollment");
  }
  const connection: ClientConnection = {
    version: 1,
    host: invitation.host,
    port: invitation.port,
    serverFingerprint: invitation.serverFingerprint,
    serverCertificatePem: certificate.pem,
    serverIdentityPublicKeyPem: enrolled.serverIdentityPublicKeyPem,
    deviceId: enrolled.device.id,
    displayName: displayName.trim(),
    serverEpoch: enrolled.serverEpoch,
  };
  saveClientConnection(paths, connection, "wx");
  return connection;
}

function saveClientConnection(paths: ClientPaths, connection: ClientConnection, flag: "w" | "wx" = "w"): void {
  writeFileSync(paths.connection, `${JSON.stringify(connection, null, 2)}\n`, {
    encoding: "utf8", flag, mode: 0o600,
  });
  hardenSecretPath(paths.connection, { required: true });
}

function certificateFingerprint(certificatePem: string): string {
  const certificate = new X509Certificate(certificatePem);
  return createHash("sha256").update(certificate.raw).digest("hex").toUpperCase().match(/.{1,4}/g)?.join("-") ?? "";
}

export function loadClientConnection(paths: ClientPaths = clientPaths()): ClientConnection {
  hardenSecretPath(paths.connection, { required: true });
  const connection = JSON.parse(readFileSync(paths.connection, "utf8")) as ClientConnection;
  const epoch = connection.serverEpoch ?? 1;
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error("Invalid CoCodex Server epoch in client connection");
  return { ...connection, serverEpoch: epoch };
}

/** Accept a source-signed authority handoff and atomically retarget this client. */
export function acceptServerAuthorityTransfer(
  code: string,
  paths: ClientPaths = clientPaths(),
): ClientConnection {
  const current = loadClientConnection(paths);
  const certificate = decodeServerAuthorityCertificate(code.trim());
  const sourceKey = canonicalEd25519PublicKey(certificate.sourceIdentityPublicKeyPem);
  if (sourceKey !== canonicalEd25519PublicKey(current.serverIdentityPublicKeyPem)
    || publicKeyFingerprint(sourceKey) !== certificate.sourceIdentityFingerprint) {
    throw new Error("Server-transfer certificate is not signed by the currently trusted server");
  }
  const targetKey = canonicalEd25519PublicKey(certificate.targetIdentityPublicKeyPem);
  if (publicKeyFingerprint(targetKey) !== certificate.targetIdentityFingerprint) {
    throw new Error("Server-transfer target identity fingerprint is invalid");
  }
  const targetTlsFingerprint = certificateFingerprint(certificate.targetTlsCertificatePem);
  if (targetTlsFingerprint !== certificate.targetTlsFingerprint) {
    throw new Error("Server-transfer target TLS fingerprint is invalid");
  }
  const { signature: _signature, ...unsigned } = certificate;
  if (!verify(null, serverAuthorityCertificateSigningTranscript(unsigned), createPublicKey(sourceKey), Buffer.from(certificate.signature, "base64url"))) {
    throw new Error("Server-transfer certificate signature is invalid");
  }
  if (certificate.serverEpoch <= current.serverEpoch) {
    throw new Error("Server-transfer certificate is not newer than the current authority");
  }
  try {
    const targetCertificate = new X509Certificate(certificate.targetTlsCertificatePem);
    const matchedHost = isIP(certificate.targetHost)
      ? targetCertificate.checkIP(certificate.targetHost)
      : targetCertificate.checkHost(certificate.targetHost);
    if (!matchedHost) throw new Error("certificate name mismatch");
  } catch { throw new Error("Server-transfer TLS certificate does not cover the target host"); }
  const next: ClientConnection = {
    ...current,
    host: certificate.targetHost,
    port: certificate.targetPort,
    serverFingerprint: certificate.targetTlsFingerprint,
    serverCertificatePem: certificate.targetTlsCertificatePem,
    serverIdentityPublicKeyPem: targetKey,
    serverEpoch: certificate.serverEpoch,
  };
  saveClientConnection(paths, next);
  return next;
}

export type ClientWebSocketFactory = (url: string, options: unknown) => WebSocket;

export async function connectAuthenticatedClient(
  paths: ClientPaths = clientPaths(),
  createSocket: ClientWebSocketFactory = (url, options) => new WebSocket(url, options as never),
): Promise<WebSocket> {
  const connection = loadClientConnection(paths);
  const identity = loadOrCreateClientIdentity(paths);
  const host = connection.host.includes(":") ? `[${connection.host}]` : connection.host;
  const socket = createSocket(`wss://${host}:${connection.port}/v1/connect`, {
    tls: { ca: connection.serverCertificatePem, rejectUnauthorized: true },
  });
  return await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error("Timed out while authenticating with CoCodex Server"));
    }, 10_000);
    socket.addEventListener("message", event => {
      try {
        const frame = JSON.parse(String(event.data)) as Record<string, unknown>;
        if (frame.type === "auth.challenge") {
          const requestId = randomUUID();
          socket.send(JSON.stringify({
            version: 1,
            type: "auth.response",
            requestId,
            deviceId: connection.deviceId,
            signature: sign(
              null,
              websocketAuthTranscript({
                serverFingerprint: connection.serverFingerprint,
                deviceId: connection.deviceId,
                requestId,
                challenge: String(frame.challenge),
              }),
              identity.privateKeyPem,
            ).toString("base64url"),
          }));
        } else if (frame.type === "auth.ok") {
          const remoteEpoch = Number(frame.serverEpoch);
          if (!Number.isSafeInteger(remoteEpoch) || remoteEpoch < 1) {
            throw new Error("CoCodex Server returned an invalid authority epoch");
          }
          if (remoteEpoch < connection.serverEpoch) {
            throw new Error(`Rejected stale CoCodex Server epoch ${remoteEpoch}; expected at least ${connection.serverEpoch}`);
          }
          if (String(frame.serverIdentityPublicKeyPem) !== connection.serverIdentityPublicKeyPem) {
            throw new Error("CoCodex Server identity changed unexpectedly");
          }
          if (remoteEpoch > connection.serverEpoch) {
            connection.serverEpoch = remoteEpoch;
            saveClientConnection(paths, connection);
          }
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

export interface ReconnectingClientOptions {
  signal?: AbortSignal;
  retryDelayMs?: number;
  connect?: (paths: ClientPaths) => Promise<WebSocket>;
  onConnectionError?: (error: Error) => void;
}

export async function maintainAuthenticatedClient(
  paths: ClientPaths,
  onConnected: (socket: WebSocket) => void | (() => void | Promise<void>)
    | Promise<void | (() => void | Promise<void>)>,
  options: ReconnectingClientOptions = {},
): Promise<void> {
  const connect = options.connect ?? connectAuthenticatedClient;
  const retryDelayMs = Math.max(100, options.retryDelayMs ?? 1_000);
  while (!options.signal?.aborted) {
    let socket: WebSocket | undefined;
    let cleanup: void | (() => void | Promise<void>) = undefined;
    try {
      socket = await connect(paths);
      cleanup = await onConnected(socket);
      await new Promise<void>(resolve => {
        if (socket!.readyState === WebSocket.CLOSED) resolve();
        else socket!.addEventListener("close", () => resolve(), { once: true });
      });
    } catch (error) {
      options.onConnectionError?.(error instanceof Error ? error : new Error(String(error)));
    } finally {
      await cleanup?.();
      if (socket && socket.readyState !== WebSocket.CLOSED) socket.close();
    }
    if (options.signal?.aborted) break;
    await new Promise<void>(resolve => {
      const timeout = setTimeout(resolve, retryDelayMs);
      options.signal?.addEventListener("abort", () => {
        clearTimeout(timeout);
        resolve();
      }, { once: true });
    });
  }
}

export function sendAgentRequest(
  socket: WebSocket,
  projectId: string,
  agentId: string,
  prompt: string,
  paths: ClientPaths = clientPaths(),
  dependencies: string[] = [],
  privateShareMessageId?: string,
  inputArtifactIds: string[] = [],
): string {
  const frame = createAgentRequest(projectId, agentId, prompt, paths, dependencies, privateShareMessageId, inputArtifactIds);
  socket.send(JSON.stringify(frame));
  return frame.taskId;
}

export function createAgentRequest(
  projectId: string,
  agentId: string,
  prompt: string,
  paths: ClientPaths = clientPaths(),
  dependencies: string[] = [],
  privateShareMessageId?: string,
  inputArtifactIds: string[] = [],
) {
  const identity = loadOrCreateClientIdentity(paths);
  const taskId = randomUUID();
  const nonce = randomBytes(32).toString("base64url");
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
  const signature = sign(null, agentRequestSigningTranscript({
    taskId, projectId, agentId, prompt, nonce, issuedAt, expiresAt, dependencies, inputArtifactIds, privateShareMessageId,
  }), identity.privateKeyPem).toString("base64url");
  return {
    version: 1,
    type: "agent.request" as const,
    requestId: randomUUID(),
    taskId,
    projectId,
    agentId,
    prompt,
    nonce,
    issuedAt,
    expiresAt,
    dependencies,
    inputArtifactIds,
    signature,
    ...(privateShareMessageId ? { privateShareMessageId } : {}),
  };
}
