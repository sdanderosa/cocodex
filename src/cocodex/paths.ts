import { homedir } from "node:os";
import { resolve } from "node:path";

export interface ClientPaths {
  root: string;
  identityPrivateKey: string;
  identityPublicKey: string;
  messagingPrivateKey: string;
  messagingPublicKey: string;
  projectWrapPrivateKey: string;
  projectWrapPublicKey: string;
  projectKeys: string;
  connection: string;
  agentPolicy: string;
  agentSafety: string;
  agentJournal: string;
  trustedDevices: string;
  privateMailbox: string;
  outbox: string;
  usageReport: string;
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
    projectWrapPrivateKey: resolve(absoluteRoot, "project-wrap-x25519-private.pem"),
    projectWrapPublicKey: resolve(absoluteRoot, "project-wrap-x25519-public.pem"),
    projectKeys: resolve(absoluteRoot, "project-keys.json"),
    connection: resolve(absoluteRoot, "connection.json"),
    agentPolicy: resolve(absoluteRoot, "local-agent-policy.json"),
    agentSafety: resolve(absoluteRoot, "local-agent-safety.json"),
    agentJournal: resolve(absoluteRoot, "agent-execution-journal.json"),
    trustedDevices: resolve(absoluteRoot, "trusted-devices.json"),
    privateMailbox: resolve(absoluteRoot, "private-mailbox.json"),
    outbox: resolve(absoluteRoot, "outbox.json"),
    usageReport: resolve(absoluteRoot, "usage-report.json"),
  };
}
