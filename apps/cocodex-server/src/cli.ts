#!/usr/bin/env bun
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createEncryptedServerTransfer, createServerBackup, restoreEncryptedServerTransfer, restoreServerBackup } from "./backup";
import { createDefaultConfig, loadConfig, saveConfig } from "./config";
import { openDatabase } from "./database";
import { approveDevice, devicePublicKeys, listDevices, revokeDevice } from "./enrollment";
import { createServerIdentity, loadServerIdentity } from "./identity";
import { createInvitation } from "./invitations";
import { tryAutomaticPortMapping } from "./port-mapping";
import { registerAgent } from "./agent-routing";
import { addProjectMember, createProject } from "./shared-state";
import { serverPaths } from "./paths";
import { startCoCodexServer } from "./server";
import { createTlsIdentity, tlsCertificateFingerprint } from "./tls";
import { advanceServerEpoch } from "./server-state";

function option(name: string): string | undefined {
  const index = Bun.argv.indexOf(name);
  return index >= 0 ? Bun.argv[index + 1] : undefined;
}

function requiredOption(name: string): string {
  const value = option(name);
  if (!value) throw new Error(`Missing required option ${name}`);
  return value;
}

function configureWindowsFirewall(port: number): "created" | "manual-required" | "not-windows" {
  if (process.platform !== "win32") return "not-windows";
  const result = Bun.spawnSync([
    "netsh", "advfirewall", "firewall", "add", "rule",
    `name=CoCodex Server TCP ${port}`, "dir=in", "action=allow", "protocol=TCP",
    `localport=${port}`,
  ], { stdout: "ignore", stderr: "ignore" });
  return result.exitCode === 0 ? "created" : "manual-required";
}

function requiredPassphrase(): string {
  return requiredOption("--passphrase");
}

function runningPid(paths: ReturnType<typeof serverPaths>): number | undefined {
  if (!existsSync(paths.pid)) return undefined;
  const pid = Number(readFileSync(paths.pid, "utf8").trim());
  if (!Number.isInteger(pid) || pid <= 0) return undefined;
  try { process.kill(pid, 0); return pid; }
  catch { return undefined; }
}

function requireStopped(paths: ReturnType<typeof serverPaths>): void {
  const pid = runningPid(paths);
  if (pid) throw new Error(`CoCodex Server is running with PID ${pid}; stop it first`);
}

function usage(): void {
  console.log(`CoCodex Server

Usage:
  cocodex-server init --public-host HOST [--port PORT] [--state-root PATH]
  cocodex-server start [--state-root PATH]
  cocodex-server stop [--state-root PATH]
  cocodex-server restart [--state-root PATH]
  cocodex-server status [--state-root PATH]
  cocodex-server backup --output FILE [--state-root PATH]
  cocodex-server restore --input FILE [--state-root PATH]
  cocodex-server transfer-export --output FILE --passphrase PASS [--state-root PATH]
  cocodex-server transfer-import --input FILE --passphrase PASS [--state-root PATH]
  cocodex-server migrate [--state-root PATH]
  cocodex-server invite [--ttl SECONDS] [--state-root PATH]
  cocodex-server devices [--state-root PATH]
  cocodex-server device-keys --device ID [--state-root PATH]
  cocodex-server approve --fingerprint FINGERPRINT [--state-root PATH]
  cocodex-server revoke --fingerprint FINGERPRINT [--state-root PATH]
  cocodex-server project-create --name NAME --owner-device ID [--state-root PATH]
  cocodex-server project-add-member --project ID --owner-device ID --member-device ID [--state-root PATH]
  cocodex-server agent-add --id ID --project ID --host-device ID --name NAME [--state-root PATH]`);
}

async function run(): Promise<void> {
  const paths = serverPaths(option("--state-root"));
  switch (Bun.argv[2] ?? "help") {
    case "init": {
      const publicHost = requiredOption("--public-host");
      const port = Number(option("--port") ?? "19463");
      saveConfig(paths, createDefaultConfig(paths, publicHost, port));
      createServerIdentity(paths);
      await createTlsIdentity(paths, publicHost);
      openDatabase(paths.database).close();
      const firewall = configureWindowsFirewall(port);
      const portMapping = await tryAutomaticPortMapping(port);
      console.log(JSON.stringify({
        initialized: true,
        stateRoot: paths.root,
        publicHost,
        port,
        serverFingerprint: tlsCertificateFingerprint(paths.tlsCertificate),
        firewall,
        portMapping,
        manualPortForwarding: {
          protocol: "TCP",
          externalPort: port,
          internalPort: port,
          internalHost: "This PC's LAN IPv4 address",
          steps: [
            `Forward one TCP port from your router's public address to this PC: ${port} -> ${port}.`,
            `Allow inbound TCP ${port} in Windows Firewall (the server attempted this automatically).`,
            "Use the public hostname or address in the generated invitation; do not expose any other port.",
          ],
        },
      }));
      return;
    }
    case "invite": {
      const config = loadConfig(paths);
      const db = openDatabase(paths.database);
      const code = createInvitation(db, {
        host: config.publicHost,
        port: config.port,
        serverFingerprint: tlsCertificateFingerprint(config.tlsCertificate),
        ttlSeconds: Number(option("--ttl") ?? "900"),
      });
      db.close();
      console.log(code);
      return;
    }
    case "status": {
      const config = existsSync(paths.config) ? loadConfig(paths) : undefined;
      console.log(JSON.stringify({
        initialized: Boolean(config),
        stateRoot: paths.root,
        running: runningPid(paths) !== undefined,
        pid: runningPid(paths) ?? null,
        publicHost: config?.publicHost ?? null,
        port: config?.port ?? null,
        serverFingerprint: config && existsSync(config.tlsCertificate)
          ? tlsCertificateFingerprint(config.tlsCertificate) : null,
      }));
      return;
    }
    case "stop": {
      const pid = runningPid(paths);
      if (!pid) {
        if (existsSync(paths.pid)) rmSync(paths.pid, { force: true });
        console.log(JSON.stringify({ stopped: false, running: false }));
        return;
      }
      process.kill(pid, "SIGTERM");
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline && runningPid(paths) !== undefined) await Bun.sleep(100);
      if (runningPid(paths) !== undefined) throw new Error(`CoCodex Server PID ${pid} did not stop`);
      if (existsSync(paths.pid)) rmSync(paths.pid, { force: true });
      console.log(JSON.stringify({ stopped: true, pid }));
      return;
    }
    case "restart": {
      const pid = runningPid(paths);
      if (pid) {
        process.kill(pid, "SIGTERM");
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline && runningPid(paths) !== undefined) await Bun.sleep(100);
        if (runningPid(paths) !== undefined) throw new Error(`CoCodex Server PID ${pid} did not stop`);
      }
      const script = Bun.argv[1];
      const args = script?.endsWith(".ts") ? [script, "start"] : ["start"];
      Bun.spawn([process.execPath, ...args, "--state-root", paths.root], {
        stdin: "ignore", stdout: "ignore", stderr: "ignore", detached: true,
      });
      console.log(JSON.stringify({ restarted: true, stateRoot: paths.root }));
      return;
    }
    case "backup": {
      requireStopped(paths);
      const identity = loadServerIdentity(paths);
      const backup = createServerBackup(paths, identity, requiredOption("--output"));
      console.log(JSON.stringify({ backedUp: true, createdAt: backup.createdAt, databaseSha256: backup.databaseSha256 }));
      return;
    }
    case "restore": {
      requireStopped(paths);
      const identity = loadServerIdentity(paths);
      const backup = restoreServerBackup(paths, identity, requiredOption("--input"));
      openDatabase(paths.database).close();
      console.log(JSON.stringify({ restored: true, createdAt: backup.createdAt, databaseSha256: backup.databaseSha256 }));
      return;
    }
    case "transfer-export": {
      requireStopped(paths);
      const identity = loadServerIdentity(paths);
      const transfer = createEncryptedServerTransfer(paths, identity, requiredOption("--output"), requiredPassphrase());
      console.log(JSON.stringify({ transferred: true, direction: "export", encrypted: true, serverEpoch: transfer.serverEpoch, databaseSha256: transfer.databaseSha256 }));
      return;
    }
    case "transfer-import": {
      requireStopped(paths);
      const identity = loadServerIdentity(paths);
      const transfer = restoreEncryptedServerTransfer(paths, identity, requiredOption("--input"), requiredPassphrase());
      const db = openDatabase(paths.database);
      const epoch = advanceServerEpoch(db);
      db.close();
      console.log(JSON.stringify({ transferred: true, direction: "import", encrypted: true, previousServerEpoch: transfer.serverEpoch, serverEpoch: epoch, databaseSha256: transfer.databaseSha256 }));
      return;
    }
    case "migrate": {
      requireStopped(paths);
      const db = openDatabase(paths.database);
      db.close();
      console.log(JSON.stringify({ migrated: true, database: paths.database }));
      return;
    }
    case "devices": {
      const db = openDatabase(paths.database);
      console.log(JSON.stringify(listDevices(db), null, 2));
      db.close();
      return;
    }
    case "device-keys": {
      const db = openDatabase(paths.database);
      const keys = devicePublicKeys(db, requiredOption("--device"));
      db.close();
      console.log(JSON.stringify(keys, null, 2));
      return;
    }    case "approve": {
      const db = openDatabase(paths.database);
      const approved = approveDevice(db, requiredOption("--fingerprint"));
      db.close();
      if (!approved) throw new Error("No pending device matched that fingerprint");
      console.log(JSON.stringify({ approved: true }));
      return;
    }
    case "revoke": {
      const db = openDatabase(paths.database);
      const revoked = revokeDevice(db, requiredOption("--fingerprint"));
      db.close();
      if (!revoked) throw new Error("No approved device matched that fingerprint");
      console.log(JSON.stringify({ revoked: true }));
      return;
    }
    case "project-create": {
      const db = openDatabase(paths.database);
      const project = createProject(db, requiredOption("--name"), requiredOption("--owner-device"));
      db.close();
      console.log(JSON.stringify(project));
      return;
    }
    case "project-add-member": {
      const db = openDatabase(paths.database);
      addProjectMember(db, requiredOption("--project"), requiredOption("--owner-device"), requiredOption("--member-device"));
      db.close();
      console.log(JSON.stringify({ added: true }));
      return;
    }
    case "agent-add": {
      const db = openDatabase(paths.database);
      const agent = registerAgent(db, {
        id: requiredOption("--id"),
        projectId: requiredOption("--project"),
        hostDeviceId: requiredOption("--host-device"),
        name: requiredOption("--name"),
      });
      db.close();
      console.log(JSON.stringify(agent));
      return;
    }    case "start": {
      const config = loadConfig(paths);
      const identity = loadServerIdentity(paths);
      const db = openDatabase(paths.database);
      if (existsSync(paths.pid)) {
        const existingPid = Number(readFileSync(paths.pid, "utf8").trim());
        let running = Number.isInteger(existingPid) && existingPid > 0;
        if (running) {
          try {
            process.kill(existingPid, 0);
          } catch {
            running = false;
          }
        }
        if (running) throw new Error(`CoCodex Server is already running with PID ${existingPid}`);
        rmSync(paths.pid);
      }
      writeFileSync(paths.pid, `${process.pid}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
      const running = startCoCodexServer(config, db, identity);
      console.log(JSON.stringify({
        ready: true,
        hostname: running.hostname,
        port: running.port,
        pid: process.pid,
        serverFingerprint: tlsCertificateFingerprint(config.tlsCertificate),
      }));
      const shutdown = async () => {
        await running.stop(true);
        db.close();
        if (existsSync(paths.pid) && readFileSync(paths.pid, "utf8").trim() === String(process.pid)) {
          rmSync(paths.pid);
        }
        process.exit(0);
      };
      process.on("SIGINT", () => void shutdown());
      process.on("SIGTERM", () => void shutdown());
      await new Promise(() => {});
      return;
    }
    case "help":
    case "--help":
    case "-h":
      usage();
      return;
    default:
      usage();
      throw new Error(`Unknown command: ${Bun.argv[2]}`);
  }
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
