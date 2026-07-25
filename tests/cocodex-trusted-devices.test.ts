import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadTrustedDevices, trustDevice } from "../src/cocodex/trusted-devices";

describe("CoCodex trusted devices", () => {
  test("validates a trust record before creating or replacing the protected file", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-trusted-devices-"));
    const path = join(root, "trusted-devices.json");
    try {
      expect(() => trustDevice(path, "not-a-device-id", "AAAA-BBBB-CCCC-DDDD")).toThrow();
      expect(existsSync(path)).toBeFalse();
      const deviceId = crypto.randomUUID();
      trustDevice(path, deviceId, "AAAA-BBBB-CCCC-DDDD");
      expect(loadTrustedDevices(path)).toEqual({ [deviceId]: "AAAA-BBBB-CCCC-DDDD" });
      expect(() => trustDevice(path, crypto.randomUUID(), "short")).toThrow();
      expect(loadTrustedDevices(path)).toEqual({ [deviceId]: "AAAA-BBBB-CCCC-DDDD" });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});