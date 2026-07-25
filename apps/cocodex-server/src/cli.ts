#!/usr/bin/env bun
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createDefaultConfig, loadConfig, saveConfig } from "./config";
import { openDatabase } from "./database";
import { approveDevice, listDevices } from "./enrollment";
import { createServerIdentity, loadServerIdentity } from "./identity";
import { createInvitation } from "./invitations";
import { serverPaths } from "./paths";
import { startCoCodexServer } from "./server";
import { createTlsIdentity, tlsCertificateFingerprint } from "./tls";

function option(name: string): string | undefined {
  const index = Bun.argv.indexOf(name);
  return index >= 0 ? Bun.argv[index + 1] : undefined;
}

function requiredOption(name: string): string {
  const value = option(name);
  if (!value) throw new Error(`Missing required option ${name}`);
  return value;
}

function usage(): void {
  console.log(`CoCodex Server

Usage:
  cocodex-server init --public-host HOST [--port PORT] [--state-root PATH]
  cocodex-server start [--state-root PATH]
  cocodex-server invite [--ttl SECONDS] [--state-root PATH]
  cocodex-server devices [--state-root PATH]
  cocodex-server approve --fingerprint FINGERPRINT [--state-root PATH]`);
}

async function run(): Promise<void> {
  const paths = serverPaths(option("--state-root"));
  switch (Bun.argv[2] ?? "help") {
    case "init": {
      const publicHost = requiredOption("--public-host");
      const port = Number(option("--port") ?? "19463");
      saveConfig(paths, createDefaultConfig(paths, publicHost, port));
      createServerIdentity(paths);
      await createTlsIdentity(paths);
      openDatabase(paths.database).close();
      console.log(JSON.stringify({
        initialized: true,
        stateRoot: paths.root,
        publicHost,
        port,
        serverFingerprint: tlsCertificateFingerprint(paths.tlsCertificate),
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
    case "devices": {
      const db = openDatabase(paths.database);
      console.log(JSON.stringify(listDevices(db), null, 2));
      db.close();
      return;
    }
    case "approve": {
      const db = openDatabase(paths.database);
      const approved = approveDevice(db, requiredOption("--fingerprint"));
      db.close();
      if (!approved) throw new Error("No pending device matched that fingerprint");
      console.log(JSON.stringify({ approved: true }));
      return;
    }
    case "start": {
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
