import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

const schema = z.object({
  version: z.literal(1),
  fingerprints: z.record(z.uuid(), z.string().min(16).max(256)),
}).strict();

export function loadTrustedDevices(path: string): Record<string, string> {
  if (!existsSync(path)) return {};
  hardenSecretPath(path, { required: true });
  return schema.parse(JSON.parse(readFileSync(path, "utf8"))).fingerprints;
}

export function trustDevice(path: string, deviceId: string, fingerprint: string): void {
  const fingerprints = loadTrustedDevices(path);
  fingerprints[deviceId] = fingerprint;
  mkdirSync(dirname(path), { recursive: true });
  hardenSecretDir(dirname(path), { required: true });
  writeFileSync(path, `${JSON.stringify({ version: 1, fingerprints }, null, 2)}\n`, {
    encoding: "utf8", mode: 0o600,
  });
  hardenSecretPath(path, { required: true });
}
