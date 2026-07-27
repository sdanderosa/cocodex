import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createEncryptedAuthorityServerTransfer,
  createEncryptedServerTransfer,
  restoreEncryptedAuthorityServerTransfer,
  restoreEncryptedServerTransfer,
} from "../src/backup";
import {
  createEncryptedServerRecoveryBackup,
  restoreEncryptedServerRecoveryBackup,
} from "../src/recovery-backup";
import { createDefaultConfig, loadConfig, saveConfig } from "../src/config";
import { openDatabase } from "../src/database";
import { createServerIdentity, loadServerIdentity } from "../src/identity";
import { serverPaths } from "../src/paths";
import { initializeServerAuthority, serverAuthorityStatus, serverEpoch } from "../src/server-state";
import { createTlsIdentity, tlsCertificateFingerprint } from "../src/tls";
import { serverTransferTargetSchema } from "@cocodex/protocol";

describe("CoCodex Server backups", () => {
  test("encrypts complete Server state and restores it atomically with rollback", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-recovery-"));
    try {
      const sourcePaths = serverPaths(join(root, "source"));
      const sourceConfig = createDefaultConfig(
        sourcePaths,
        "recovery.example.test",
        19463,
        "RECOVERY-ADMIN-CANARY",
      );
      const adminHashCanary = "ab".repeat(32);
      sourceConfig.adminTokenHash = adminHashCanary;
      saveConfig(sourcePaths, sourceConfig);
      const identity = createServerIdentity(sourcePaths);
      await createTlsIdentity(sourcePaths, "recovery.example.test");
      const sourceDb = openDatabase(sourcePaths.database);
      initializeServerAuthority(sourceDb, identity.fingerprint, "active");
      sourceDb.query(`INSERT INTO audit_events
        (event_type, actor_device_id, subject_id, occurred_at, details_json)
        VALUES ('recovery-canary', NULL, NULL, ?, ?)`)
        .run(new Date().toISOString(), '{"value":"RECOVERY-DATABASE-CANARY"}');
      sourceDb.close();

      const backupPath = join(root, "state.cocodex-recovery.json");
      const backup = createEncryptedServerRecoveryBackup(
        sourcePaths,
        identity,
        backupPath,
        "correct horse battery staple",
      );
      expect(backup.payloadSha256.length).toBe(64);
      expect(backup.serverEpoch).toBe(1);
      expect(existsSync(backupPath)).toBeTrue();
      const encoded = readFileSync(backupPath, "utf8");
      expect(encoded).not.toContain("PRIVATE KEY");
      expect(encoded).not.toContain("RECOVERY-DATABASE-CANARY");
      expect(encoded).not.toContain("RECOVERY-ADMIN-CANARY");
      expect(encoded).not.toContain(adminHashCanary);

      const wrongDestination = serverPaths(join(root, "wrong-passphrase"));
      expect(() => restoreEncryptedServerRecoveryBackup(
        wrongDestination,
        backupPath,
        "wrong passphrase",
      )).toThrow("passphrase");
      expect(existsSync(wrongDestination.root)).toBeFalse();

      const decoded = JSON.parse(encoded);
      decoded.ciphertext = `${decoded.ciphertext[0] === "A" ? "B" : "A"}${decoded.ciphertext.slice(1)}`;
      const tamperedPath = join(root, "tampered.json");
      writeFileSync(tamperedPath, JSON.stringify(decoded));
      expect(() => restoreEncryptedServerRecoveryBackup(
        serverPaths(join(root, "tampered-destination")),
        tamperedPath,
        "correct horse battery staple",
      )).toThrow("damaged");

      const destinationPaths = serverPaths(join(root, "destination"));
      const restored = restoreEncryptedServerRecoveryBackup(
        destinationPaths,
        backupPath,
        "correct horse battery staple",
      );
      expect(restored.rollbackPath).toBeNull();
      expect(loadServerIdentity(destinationPaths).fingerprint).toBe(identity.fingerprint);
      expect(tlsCertificateFingerprint(destinationPaths.tlsCertificate))
        .toBe(tlsCertificateFingerprint(sourcePaths.tlsCertificate));
      expect(loadConfig(destinationPaths)).toMatchObject({
        publicHost: "recovery.example.test",
        port: 19463,
        tlsCertificate: destinationPaths.tlsCertificate,
        tlsPrivateKey: destinationPaths.tlsPrivateKey,
        adminTokenHash: adminHashCanary,
      });
      const restoredDb = openDatabase(destinationPaths.database);
      expect(serverAuthorityStatus(restoredDb)).toBe("active");
      expect(serverEpoch(restoredDb)).toBe(1);
      expect(restoredDb.query(
        "SELECT details_json AS details FROM audit_events WHERE event_type = 'recovery-canary'",
      ).get()).toEqual({ details: '{"value":"RECOVERY-DATABASE-CANARY"}' });
      restoredDb.close();

      const replacementPaths = serverPaths(join(root, "replacement"));
      saveConfig(replacementPaths, createDefaultConfig(replacementPaths, "localhost", 20463));
      const replacedIdentity = createServerIdentity(replacementPaths);
      await createTlsIdentity(replacementPaths, "localhost");
      const replacementDb = openDatabase(replacementPaths.database);
      initializeServerAuthority(replacementDb, replacedIdentity.fingerprint, "active");
      replacementDb.close();
      const replaced = restoreEncryptedServerRecoveryBackup(
        replacementPaths,
        backupPath,
        "correct horse battery staple",
      );
      expect(replaced.rollbackPath).not.toBeNull();
      expect(existsSync(replaced.rollbackPath!)).toBeTrue();
      expect(loadServerIdentity(replacementPaths).fingerprint).toBe(identity.fingerprint);
      expect(loadServerIdentity(serverPaths(replaced.rollbackPath!)).fingerprint)
        .toBe(replacedIdentity.fingerprint);

      const rogueTlsPaths = serverPaths(join(root, "rogue-tls"));
      await createTlsIdentity(rogueTlsPaths, "recovery.example.test");
      writeFileSync(
        sourcePaths.tlsPrivateKey,
        readFileSync(rogueTlsPaths.tlsPrivateKey),
        { mode: 0o600 },
      );
      const invalidBackupPath = join(root, "invalid-key-pair.json");
      expect(() => createEncryptedServerRecoveryBackup(
        sourcePaths,
        identity,
        invalidBackupPath,
        "correct horse battery staple",
      )).toThrow("TLS private key does not match");
      expect(existsSync(invalidBackupPath)).toBeFalse();
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
