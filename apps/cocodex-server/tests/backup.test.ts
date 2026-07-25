import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createEncryptedAuthorityServerTransfer,
  createEncryptedServerTransfer,
  createServerBackup,
  restoreEncryptedAuthorityServerTransfer,
  restoreEncryptedServerTransfer,
  restoreServerBackup,
} from "../src/backup";
import { openDatabase } from "../src/database";
import { createServerIdentity } from "../src/identity";
import { serverPaths } from "../src/paths";
import { initializeServerAuthority, serverAuthorityStatus, serverEpoch } from "../src/server-state";
import { createTlsIdentity, tlsCertificateFingerprint } from "../src/tls";
import { serverTransferTargetSchema } from "@cocodex/protocol";

describe("CoCodex Server backups", () => {
  test("creates an identity-bound snapshot and rejects tampering", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-backup-"));
    try {
      const paths = serverPaths(root);
      openDatabase(paths.database).close();
      const identity = createServerIdentity(paths);
      const backupPath = join(root, "state.cocodex-backup.json");
      const backup = createServerBackup(paths, identity, backupPath);
      expect(backup.databaseSha256.length).toBe(64);
      expect(backup.serverEpoch).toBe(1);
      expect(existsSync(backupPath)).toBeTrue();

      const decoded = JSON.parse(readFileSync(backupPath, "utf8"));
      decoded.databaseBase64 = Buffer.from("tampered").toString("base64");
      const tamperedPath = join(root, "tampered.json");
      writeFileSync(tamperedPath, JSON.stringify(decoded));
      expect(() => restoreServerBackup(paths, identity, tamperedPath)).toThrow("checksum mismatch");

      const restored = restoreServerBackup(paths, identity, backupPath);
      expect(restored.serverFingerprint).toBe(identity.fingerprint);
      const restoredDb = openDatabase(paths.database);
      expect(restoredDb).toBeDefined();
      restoredDb.close();
    } finally {
      for (let attempt = 0; attempt < 40; attempt += 1) {
        try { rmSync(root, { recursive: true, force: true }); break; }
        catch (error) { if (attempt === 39) throw error; await Bun.sleep(25); }
      }
    }
  });

  test("encrypts server transfers and rejects wrong passphrases", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-transfer-"));
    try {
      const paths = serverPaths(root);
      openDatabase(paths.database).close();
      const identity = createServerIdentity(paths);
      const transferPath = join(root, "transfer.json");
      const transfer = createEncryptedServerTransfer(paths, identity, transferPath, "correct horse battery staple");
      expect(transfer.ciphertext).not.toContain("CREATE TABLE");
      expect(() => restoreEncryptedServerTransfer(paths, identity, transferPath, "wrong passphrase")).toThrow("passphrase");
      const restored = restoreEncryptedServerTransfer(paths, identity, transferPath, "correct horse battery staple");
      expect(restored.serverEpoch).toBe(1);
    } finally {
      for (let attempt = 0; attempt < 40; attempt += 1) {
        try { rmSync(root, { recursive: true, force: true }); break; }
        catch (error) { if (attempt === 39) throw error; await Bun.sleep(25); }
      }
    }
  });

  test("hands authority to a prepared destination, advances the epoch, and retires the source", async () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-source-"));
    const destinationRoot = mkdtempSync(join(tmpdir(), "cocodex-transfer-destination-"));
    try {
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
      const target = serverTransferTargetSchema.parse({
        version: 1,
        requestId: crypto.randomUUID(),
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
        targetHost: "localhost",
        targetPort: 19464,
        targetIdentityPublicKeyPem: destinationIdentity.publicKeyPem,
        targetIdentityFingerprint: destinationIdentity.fingerprint,
        targetTlsCertificatePem: readFileSync(destinationPaths.tlsCertificate, "utf8"),
        targetTlsFingerprint: tlsCertificateFingerprint(destinationPaths.tlsCertificate),
      });
      const transferPath = join(sourceRoot, "authority-transfer.json");
      const transfer = createEncryptedAuthorityServerTransfer(
        sourcePaths, sourceIdentity, transferPath, "correct horse battery staple", target,
      );
      const retired = openDatabase(sourcePaths.database);
      expect(serverAuthorityStatus(retired)).toBe("retired");
      retired.close();

      const restored = restoreEncryptedAuthorityServerTransfer(
        destinationPaths, destinationIdentity, transferPath, "correct horse battery staple",
      );
      expect(restored.authorityCode).toMatch(/^ccx-transfer1\./);
      const active = openDatabase(destinationPaths.database);
      expect(serverAuthorityStatus(active)).toBe("active");
      expect(serverEpoch(active)).toBe(transfer.sourceServerEpoch + 1);
      active.close();
      expect(() => {
        const check = openDatabase(sourcePaths.database);
        try {
          if (serverAuthorityStatus(check) !== "active") throw new Error("source retired");
        } finally { check.close(); }
      }).toThrow("source retired");
    } finally {
      for (const root of [sourceRoot, destinationRoot]) {
        for (let attempt = 0; attempt < 40; attempt += 1) {
          try { rmSync(root, { recursive: true, force: true }); break; }
          catch (error) { if (attempt === 39) throw error; await Bun.sleep(25); }
        }
      }
    }
  });
});
