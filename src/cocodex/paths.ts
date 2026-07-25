import { homedir } from "node:os";
import { resolve } from "node:path";

export interface ClientPaths {
  root: string;
  identityPrivateKey: string;
  identityPublicKey: string;
  connection: string;
}

export function defaultClientStateRoot(): string {
  return resolve(process.env.COCODEX_HOME?.trim() || `${homedir()}/.cocodex`);
}

export function clientPaths(root = defaultClientStateRoot()): ClientPaths {
  const absoluteRoot = resolve(root);
  return {
    root: absoluteRoot,
    identityPrivateKey: resolve(absoluteRoot, "device-ed25519-private.pem"),
    identityPublicKey: resolve(absoluteRoot, "device-ed25519-public.pem"),
    connection: resolve(absoluteRoot, "connection.json"),
  };
}
