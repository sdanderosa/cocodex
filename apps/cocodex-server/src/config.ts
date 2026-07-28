import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { hardenSecretDir, hardenSecretPath } from "../../../src/lib/windows-secret-acl";
import { assertSunshinePortsUntouched } from "./protected-host-services";
import type { ServerPaths } from "./paths";

export interface ServerConfig {
  version: 1;
  hostname: string;
  port: number;
  publicHost: string;
  tlsCertificate: string;
  tlsPrivateKey: string;
  adminTokenHash?: string;
}

export function createDefaultConfig(paths: ServerPaths, publicHost: string, port: number, adminToken = randomBytes(32).toString("base64url")): ServerConfig {
  if (!publicHost.trim()) throw new Error("Public host is required");
  assertSunshinePortsUntouched(port, "bind CoCodex Server to");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Port must be between 1 and 65535");
  return {
    version: 1,
    hostname: "0.0.0.0",
    port,
    publicHost: publicHost.trim(),
    tlsCertificate: paths.tlsCertificate,
    tlsPrivateKey: paths.tlsPrivateKey,
    adminTokenHash: hashAdminToken(adminToken),
  };
}

export function hashAdminToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function verifyAdminToken(token: string, expectedHash: string | undefined): boolean {
  if (!expectedHash || !/^[0-9a-f]{64}$/i.test(expectedHash)) return false;
  const actual = Buffer.from(hashAdminToken(token), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function saveConfig(paths: ServerPaths, config: ServerConfig): void {
  if (existsSync(paths.config)) throw new Error("Server configuration already exists");
  mkdirSync(paths.root, { recursive: true });
  hardenSecretDir(paths.root, { required: true });
  writeFileSync(paths.config, `${JSON.stringify(config, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  hardenSecretPath(paths.config, { required: true });
}

export function loadConfig(paths: ServerPaths): ServerConfig {
  hardenSecretDir(paths.root, { required: true });
  hardenSecretPath(paths.config, { required: true });
  const value = JSON.parse(readFileSync(paths.config, "utf8")) as Partial<ServerConfig>;
  if (
    value.version !== 1 ||
    typeof value.hostname !== "string" ||
    typeof value.publicHost !== "string" ||
    typeof value.port !== "number" ||
    typeof value.tlsCertificate !== "string" ||
    typeof value.tlsPrivateKey !== "string"
  ) {
    throw new Error("Invalid CoCodex Server configuration");
  }
  assertSunshinePortsUntouched(value.port, "load CoCodex Server on");
  return value as ServerConfig;
}
