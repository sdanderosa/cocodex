import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Database } from "bun:sqlite";
import { decodeInvitation } from "@cocodex/protocol";
import { createDefaultConfig } from "../apps/cocodex-server/src/config";
import { openDatabase } from "../apps/cocodex-server/src/database";
import { approveDevice } from "../apps/cocodex-server/src/enrollment";
import { createServerIdentity } from "../apps/cocodex-server/src/identity";
import { createInvitation } from "../apps/cocodex-server/src/invitations";
import { serverPaths } from "../apps/cocodex-server/src/paths";
import { startCoCodexServer } from "../apps/cocodex-server/src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../apps/cocodex-server/src/tls";
import {
  connectAuthenticatedClient,
  enrollClient,
  maintainAuthenticatedClient,
} from "../src/cocodex/client";
import { clientPaths } from "../src/cocodex/paths";

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
});
