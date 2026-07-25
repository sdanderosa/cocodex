import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Database } from "bun:sqlite";
import { decodeInvitation } from "@cocodex/protocol";
import { createEncryptedAuthorityServerTransfer, restoreEncryptedAuthorityServerTransfer } from "../apps/cocodex-server/src/backup";
import { createDefaultConfig } from "../apps/cocodex-server/src/config";
import { openDatabase } from "../apps/cocodex-server/src/database";
import { approveDevice } from "../apps/cocodex-server/src/enrollment";
import { createServerIdentity } from "../apps/cocodex-server/src/identity";
import { createInvitation } from "../apps/cocodex-server/src/invitations";
import { serverPaths } from "../apps/cocodex-server/src/paths";
import { initializeServerAuthority } from "../apps/cocodex-server/src/server-state";
import { startCoCodexServer } from "../apps/cocodex-server/src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../apps/cocodex-server/src/tls";
import {
  connectAuthenticatedClient,
  enrollClient,
  acceptServerAuthorityTransfer,
  loadClientConnection,
  maintainAuthenticatedClient,
} from "../src/cocodex/client";
import { clientPaths } from "../src/cocodex/paths";
import { loadOrCreateClientIdentity } from "../src/cocodex/identity";

const roots: string[] = [];
const servers: Array<{ stop(force?: boolean): Promise<void> }> = [];
const databases: Database[] = [];
const sockets: WebSocket[] = [];

afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.close();
  await Promise.all(servers.splice(0).map(server => server.stop(true)));
  for (const database of databases.splice(0)) database.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("CoCodex Client direct enrollment", () => {
  test("reconnects a resident client session after transport closure", async () => {
    const controller = new AbortController();
    const connected: number[] = [];
    let attempts = 0;
    const fakeSocket = (): WebSocket => {
      const target = new EventTarget() as WebSocket;
      Object.defineProperty(target, "readyState", { value: WebSocket.OPEN, writable: true });
      target.close = (() => {
        Object.defineProperty(target, "readyState", { value: WebSocket.CLOSED });
        target.dispatchEvent(new CloseEvent("close"));
      }) as WebSocket["close"];
      return target;
    };
    await maintainAuthenticatedClient(clientPaths("unused"), socket => {
      connected.push(++attempts);
      if (attempts === 1) queueMicrotask(() => socket.close());
      else {
        controller.abort();
        queueMicrotask(() => socket.close());
      }
    }, {
      signal: controller.signal,
      retryDelayMs: 100,
      connect: async () => fakeSocket(),
    });
    expect(connected).toEqual([1, 2]);
  });

  test("remembers a newer authenticated server epoch and rejects a stale authority", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-client-epoch-"));
    roots.push(root);
    const paths = clientPaths(root);
    loadOrCreateClientIdentity(paths);
    writeFileSync(paths.connection, JSON.stringify({
      version: 1,
      host: "server.example",
      port: 19463,
      serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
      serverCertificatePem: "certificate",
      serverIdentityPublicKeyPem: "server-identity",
      deviceId: crypto.randomUUID(),
      displayName: "Kai",
      serverEpoch: 1,
    }));
    const factory = (epoch: number) => () => {
      const socket = new EventTarget() as WebSocket;
      Object.defineProperty(socket, "readyState", { value: WebSocket.OPEN, writable: true });
      socket.close = (() => Object.defineProperty(socket, "readyState", { value: WebSocket.CLOSED })) as WebSocket["close"];
      socket.send = ((data: string) => {
        const frame = JSON.parse(data);
        if (frame.type !== "auth.response") return;
        queueMicrotask(() => socket.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({
          version: 1,
          type: "auth.ok",
          requestId: frame.requestId,
          deviceId: frame.deviceId,
          serverIdentityPublicKeyPem: "server-identity",
          serverEpoch: epoch,
        }) })));
      }) as WebSocket["send"];
      queueMicrotask(() => socket.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({
        type: "auth.challenge", protocol: 1, challenge: "challenge",
      }) })));
      return socket;
    };

    const advanced = await connectAuthenticatedClient(paths, factory(2));
    expect(loadClientConnection(paths).serverEpoch).toBe(2);
    advanced.close();
    await expect(connectAuthenticatedClient(paths, factory(1))).rejects.toThrow(
      "Rejected stale CoCodex Server epoch 1; expected at least 2",
    );
  });
  test("pins TLS before enrollment, reconnects after approval, and rejects a wrong pin without consuming it", async () => {
    const serverRoot = mkdtempSync(join(tmpdir(), "cocodex-client-server-"));
    const clientRoot = mkdtempSync(join(tmpdir(), "cocodex-client-device-"));
    const wrongPinRoot = mkdtempSync(join(tmpdir(), "cocodex-client-wrong-pin-"));
    roots.push(serverRoot, clientRoot, wrongPinRoot);
    const paths = serverPaths(serverRoot);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths, "127.0.0.1");
    const database = openDatabase(paths.database);
    databases.push(database);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, database, identity);
    servers.push(server);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);

    const invitation = createInvitation(database, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint,
    });
    const connection = await enrollClient(invitation, "Kai", clientPaths(clientRoot));
    const pending = database.query(
      "SELECT fingerprint, status FROM devices WHERE id = ?",
    ).get(connection.deviceId) as { fingerprint: string; status: string };
    expect(pending.status).toBe("pending");
    expect(approveDevice(database, pending.fingerprint)).toBeTrue();
    const socket = await connectAuthenticatedClient(clientPaths(clientRoot));
    sockets.push(socket);
    expect(socket.readyState).toBe(WebSocket.OPEN);

    const wrongCode = createInvitation(database, {
      host: "127.0.0.1",
      port: server.port,
      serverFingerprint: fingerprint.replace(/^....-/, "FFFF-"),
    });
    const wrongInvite = decodeInvitation(wrongCode);
    await expect(enrollClient(wrongCode, "Mallory", clientPaths(wrongPinRoot))).rejects.toThrow(
      "fingerprint does not match",
    );
    const wrongRow = database.query(
      "SELECT consumed_at AS consumedAt FROM invitations WHERE id = ?",
    ).get(wrongInvite.invitationId) as { consumedAt: string | null };
    expect(wrongRow.consumedAt).toBeNull();

  }, 15_000);

  test("accepts a source-signed server transfer and persists the new endpoint and TLS pin", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "cocodex-client-transfer-source-"));
    const destinationRoot = mkdtempSync(join(tmpdir(), "cocodex-client-transfer-destination-"));
    const clientRoot = mkdtempSync(join(tmpdir(), "cocodex-client-transfer-device-"));
    roots.push(sourceRoot, destinationRoot, clientRoot);
    const sourcePaths = serverPaths(sourceRoot);
    const sourceIdentity = createServerIdentity(sourcePaths);
    await createTlsIdentity(sourcePaths, "127.0.0.1");
    const sourceDb = openDatabase(sourcePaths.database);
    initializeServerAuthority(sourceDb, sourceIdentity.fingerprint, "active");
    sourceDb.close();

    const destinationPaths = serverPaths(destinationRoot);
    const destinationIdentity = createServerIdentity(destinationPaths);
    await createTlsIdentity(destinationPaths, "localhost");
    const destinationDb = openDatabase(destinationPaths.database);
    initializeServerAuthority(destinationDb, destinationIdentity.fingerprint, "prepared");
    destinationDb.close();
    const target = {
      version: 1 as const,
      requestId: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
      targetHost: "localhost",
      targetPort: 19464,
      targetIdentityPublicKeyPem: destinationIdentity.publicKeyPem,
      targetIdentityFingerprint: destinationIdentity.fingerprint,
      targetTlsCertificatePem: readFileSync(destinationPaths.tlsCertificate, "utf8"),
      targetTlsFingerprint: tlsCertificateFingerprint(destinationPaths.tlsCertificate),
    };
    const transfer = createEncryptedAuthorityServerTransfer(
      sourcePaths, sourceIdentity, join(sourceRoot, "authority-transfer.json"),
      "correct horse battery staple", target,
    );
    const restored = restoreEncryptedAuthorityServerTransfer(
      destinationPaths, destinationIdentity, join(sourceRoot, "authority-transfer.json"),
      "correct horse battery staple",
    );
    expect(transfer.authorityCertificate.serverEpoch).toBe(2);

    const paths = clientPaths(clientRoot);
    loadOrCreateClientIdentity(paths);
    writeFileSync(paths.connection, JSON.stringify({
      version: 1,
      host: "127.0.0.1",
      port: 19463,
      serverFingerprint: tlsCertificateFingerprint(sourcePaths.tlsCertificate),
      serverCertificatePem: readFileSync(sourcePaths.tlsCertificate, "utf8"),
      serverIdentityPublicKeyPem: sourceIdentity.publicKeyPem,
      deviceId: crypto.randomUUID(),
      displayName: "Kai",
      serverEpoch: 1,
    }));
    const accepted = acceptServerAuthorityTransfer(restored.authorityCode, paths);
    expect(accepted.host).toBe("localhost");
    expect(accepted.port).toBe(19464);
    expect(accepted.serverEpoch).toBe(2);
    expect(accepted.serverIdentityPublicKeyPem).toBe(destinationIdentity.publicKeyPem);
    await expect(Promise.resolve().then(() => acceptServerAuthorityTransfer(restored.authorityCode, paths))).rejects.toThrow("not signed");
  });
});
