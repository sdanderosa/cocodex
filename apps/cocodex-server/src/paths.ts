import { homedir } from "node:os";
import { resolve } from "node:path";

export interface ServerPaths {
  root: string;
  config: string;
  database: string;
  identityPrivateKey: string;
  identityPublicKey: string;
  tlsPrivateKey: string;
  tlsCertificate: string;
  pid: string;
  serviceDirectory: string;
  serviceExecutable: string;
  serviceConfig: string;
  serviceLogs: string;
}

export function defaultStateRoot(): string {
  const override = process.env.COCODEX_SERVER_HOME?.trim();
  return resolve(override || `${homedir()}/.cocodex-server`);
}

export function serverPaths(root = defaultStateRoot()): ServerPaths {
  const absoluteRoot = resolve(root);
  const serviceDirectory = resolve(absoluteRoot, "windows-service");
  return {
    root: absoluteRoot,
    config: resolve(absoluteRoot, "config.json"),
    database: resolve(absoluteRoot, "server.sqlite3"),
    identityPrivateKey: resolve(absoluteRoot, "identity-ed25519-private.pem"),
    identityPublicKey: resolve(absoluteRoot, "identity-ed25519-public.pem"),
    tlsPrivateKey: resolve(absoluteRoot, "tls-private-key.pem"),
    tlsCertificate: resolve(absoluteRoot, "tls-certificate.pem"),
    pid: resolve(absoluteRoot, "server.pid"),
    serviceDirectory,
    serviceExecutable: resolve(serviceDirectory, "cocodex-server.exe"),
    serviceConfig: resolve(serviceDirectory, "cocodex-server.xml"),
    serviceLogs: resolve(serviceDirectory, "logs"),
  };
}
