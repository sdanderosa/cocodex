import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { hardenSecretDir, hardenSecretPath } from "../../../src/lib/windows-secret-acl";
import type { ServerPaths } from "./paths";

export interface ServerConfig {
  version: 1;
  hostname: string;
  port: number;
  publicHost: string;
  tlsCertificate: string;
  tlsPrivateKey: string;
}

export function createDefaultConfig(paths: ServerPaths, publicHost: string, port: number): ServerConfig {
  if (!publicHost.trim()) throw new Error("Public host is required");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Port must be between 1 and 65535");
  return {
    version: 1,
    hostname: "0.0.0.0",
    port,
    publicHost: publicHost.trim(),
    tlsCertificate: paths.tlsCertificate,
    tlsPrivateKey: paths.tlsPrivateKey,
  };
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
  return value as ServerConfig;
}
