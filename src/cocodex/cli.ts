#!/usr/bin/env bun
import { connectAuthenticatedClient, enrollClient, loadClientConnection } from "./client";
import { clientPaths } from "./paths";

function option(name: string): string | undefined {
  const index = Bun.argv.indexOf(name);
  return index >= 0 ? Bun.argv[index + 1] : undefined;
}

function required(name: string): string {
  const value = option(name);
  if (!value) throw new Error(`Missing required option ${name}`);
  return value;
}

async function run(): Promise<void> {
  const paths = clientPaths(option("--state-root"));
  switch (Bun.argv[2] ?? "help") {
    case "enroll": {
      const connection = await enrollClient(required("--invite"), required("--name"), paths);
      console.log(JSON.stringify({
        enrolled: true,
        deviceId: connection.deviceId,
        approvalRequired: true,
      }));
      return;
    }
    case "status":
      console.log(JSON.stringify(loadClientConnection(paths), null, 2));
      return;
    case "connect": {
      const socket = await connectAuthenticatedClient(paths);
      console.log(JSON.stringify({ connected: true, deviceId: loadClientConnection(paths).deviceId }));
      await new Promise<void>(resolve => socket.addEventListener("close", () => resolve(), { once: true }));
      return;
    }
    default:
      console.log(`CoCodex Client

Usage:
  cocodex-client enroll --invite CODE --name NAME [--state-root PATH]
  cocodex-client status [--state-root PATH]
  cocodex-client connect [--state-root PATH]`);
  }
}

run().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
