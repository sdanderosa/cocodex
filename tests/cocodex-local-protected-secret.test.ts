import { afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  dpapiChildEnvironment,
  protectedSecretStorageKind,
  readProtectedSecret,
  writeProtectedSecret,
} from "../src/lib/local-protected-secret";
import { clientPaths } from "../src/cocodex/paths";
import { loadOrCreateClientIdentity } from "../src/cocodex/identity";
import { serverPaths } from "../apps/cocodex-server/src/paths";
import { createServerIdentity, loadServerIdentity } from "../apps/cocodex-server/src/identity";
import { createTlsIdentity, readTlsPrivateKey } from "../apps/cocodex-server/src/tls";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function temporaryRoot(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  roots.push(root);
  return root;
}

describe("CoCodex local private-key custody", () => {
  test("restores the real Windows profile only for the fixed DPAPI child", () => {
    const child = dpapiChildEnvironment({
      SystemRoot: "C:\\Windows",
      USERPROFILE: "C:\\isolated-test-home",
      HOME: "C:\\isolated-test-home",
      OCX_TEST_ISOLATED_ENV: "1",
      OCX_TEST_DPAPI_USERPROFILE: "C:\\Users\\runneradmin",
    });
    expect(child).toMatchObject({
      USERPROFILE: "C:\\Users\\runneradmin",
      HOME: "C:\\Users\\runneradmin",
      HOMEDRIVE: "C:",
      HOMEPATH: "\\Users\\runneradmin",
    });
    expect(dpapiChildEnvironment({
      USERPROFILE: "C:\\production-profile",
      OCX_TEST_DPAPI_USERPROFILE: "C:\\Users\\ignored-test-profile",
    }).USERPROFILE).toBe("C:\\production-profile");
    expect(() => dpapiChildEnvironment({
      OCX_TEST_ISOLATED_ENV: "1",
      OCX_TEST_DPAPI_USERPROFILE: "..\\relative-profile",
    })).toThrow("DPAPI test profile bridge is invalid");
  });

  test("round-trips a purpose-bound secret without plaintext on Windows disk", () => {
    const root = temporaryRoot("cocodex-protected-secret-");
    const path = join(root, "secret.json");
    writeProtectedSecret(path, "cocodex.test.private-key", "PRIVATE-KEY-CANARY");

    const stored = readFileSync(path, "utf8");
    expect(stored).not.toContain("PRIVATE-KEY-CANARY");
    expect(readProtectedSecret(path, "cocodex.test.private-key").toString("utf8"))
      .toBe("PRIVATE-KEY-CANARY");
    expect(() => readProtectedSecret(path, "cocodex.test.other-key"))
      .toThrow("Protected-secret envelope validation failed");
    expect(protectedSecretStorageKind()).toBe(
      process.platform === "win32" ? "windows-dpapi-current-user" : "filesystem-user-only",
    );
  });

  test("rejects a modified Windows DPAPI payload", () => {
    if (process.platform !== "win32") return;
    const root = temporaryRoot("cocodex-protected-tamper-");
    const path = join(root, "secret.json");
    writeProtectedSecret(path, "cocodex.test.tamper-key", "tamper-canary");
    const envelope = JSON.parse(readFileSync(path, "utf8")) as { payload: string };
    const bytes = Buffer.from(envelope.payload, "base64");
    bytes[Math.floor(bytes.length / 2)] ^= 1;
    envelope.payload = bytes.toString("base64");
    writeFileSync(path, `${JSON.stringify(envelope)}\n`, "utf8");
    expect(() => readProtectedSecret(path, "cocodex.test.tamper-key"))
      .toThrow("Windows user-bound secret unprotection failed");
  });

  test("rejects oversized files and ciphertext before invoking key unprotection", () => {
    const root = temporaryRoot("cocodex-protected-bounds-");
    const filePath = join(root, "oversized-file.json");
    writeFileSync(filePath, Buffer.alloc(1_600_001, 0x41));
    expect(() => readProtectedSecret(filePath, "cocodex.test.bounded-key"))
      .toThrow("Protected-secret file is outside the supported bounds");

    const payloadPath = join(root, "oversized-payload.json");
    writeFileSync(payloadPath, JSON.stringify({
      version: 1,
      protection: process.platform === "win32"
        ? "windows-dpapi-current-user"
        : "filesystem-user-only",
      purpose: "cocodex.test.bounded-key",
      payload: Buffer.alloc(1_114_113, 0x42).toString("base64"),
      digest: "A".repeat(43),
    }));
    expect(() => readProtectedSecret(payloadPath, "cocodex.test.bounded-key"))
      .toThrow("Protected-secret ciphertext is outside the supported bounds");
  });

  test("migrates legacy private PEM files without changing the device identity", () => {
    const root = temporaryRoot("cocodex-protected-migrate-");
    const path = join(root, "legacy-private.pem");
    const pair = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    writeFileSync(path, pair.privateKey, { encoding: "utf8", mode: 0o600 });

    expect(readProtectedSecret(path, "cocodex.test.legacy-key").toString("utf8"))
      .toBe(pair.privateKey);
    const migrated = readFileSync(path, "utf8");
    expect(migrated).not.toContain("BEGIN PRIVATE KEY");
    expect(readProtectedSecret(path, "cocodex.test.legacy-key").toString("utf8"))
      .toBe(pair.privateKey);
  });

  test("stores all Client and Server private keys as protected envelopes", async () => {
    const client = clientPaths(join(temporaryRoot("cocodex-protected-client-"), "client"));
    const firstClientIdentity = loadOrCreateClientIdentity(client);
    const secondClientIdentity = loadOrCreateClientIdentity(client);
    expect(secondClientIdentity).toEqual(firstClientIdentity);
    for (const path of [
      client.identityPrivateKey,
      client.messagingPrivateKey,
      client.projectWrapPrivateKey,
    ]) {
      expect(readFileSync(path, "utf8")).not.toContain("BEGIN PRIVATE KEY");
    }

    const server = serverPaths(join(temporaryRoot("cocodex-protected-server-"), "server"));
    const firstServerIdentity = createServerIdentity(server);
    await createTlsIdentity(server, "localhost");
    expect(loadServerIdentity(server)).toEqual(firstServerIdentity);
    expect(readFileSync(server.identityPrivateKey, "utf8")).not.toContain("BEGIN PRIVATE KEY");
    expect(readFileSync(server.tlsPrivateKey, "utf8")).not.toContain("BEGIN PRIVATE KEY");
    expect(readTlsPrivateKey(server.tlsPrivateKey)).toContain("BEGIN PRIVATE KEY");
  });

  test("rejects a protected private key paired with a different public identity", () => {
    const first = clientPaths(join(temporaryRoot("cocodex-protected-pair-a-"), "client"));
    const second = clientPaths(join(temporaryRoot("cocodex-protected-pair-b-"), "client"));
    loadOrCreateClientIdentity(first);
    loadOrCreateClientIdentity(second);
    writeFileSync(first.identityPublicKey, readFileSync(second.identityPublicKey, "utf8"), "utf8");
    expect(() => loadOrCreateClientIdentity(first))
      .toThrow("CoCodex device-signing keypair does not match");
  });
});
