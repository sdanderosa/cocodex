import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServerBackup, restoreServerBackup } from "../src/backup";
import { openDatabase } from "../src/database";
import { createServerIdentity } from "../src/identity";
import { serverPaths } from "../src/paths";

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
});
