import { homedir } from "node:os";
import { resolve } from "node:path";

export interface ClientPaths {
  root: string;
  identityPrivateKey: string;
  identityPublicKey: string;
  messagingPrivateKey: string;
  messagingPublicKey: string;
  connection: string;
  agentPolicy: string;
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
    messagingPrivateKey: resolve(absoluteRoot, "messaging-x25519-private.pem"),
    messagingPublicKey: resolve(absoluteRoot, "messaging-x25519-public.pem"),
    connection: resolve(absoluteRoot, "connection.json"),
    agentPolicy: resolve(absoluteRoot, "local-agent-policy.json"),
  };
}
