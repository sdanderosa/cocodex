#!/usr/bin/env bun
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import {
  createEncryptedAuthorityServerTransfer,
  createEncryptedServerTransfer,
  restoreEncryptedAuthorityServerTransfer,
  restoreEncryptedServerTransfer,
} from "./backup";
import {
  createEncryptedServerRecoveryBackup,
  restoreEncryptedServerRecoveryBackup,
} from "./recovery-backup";
import { createDefaultConfig, loadConfig, saveConfig } from "./config";
import { openDatabase } from "./database";
import { bootstrapApproveDevice, devicePublicKeys, listDevices, revokeDevice } from "./enrollment";
import { createServerIdentity, loadServerIdentity, randomToken } from "./identity";
import { createInvitation } from "./invitations";
import { classifyDirectHosting, tryAutomaticPortMapping } from "./port-mapping";
import { assertSunshinePortsUntouched } from "./protected-host-services";
import { assertDirectServerOwnership } from "./process-ownership";
import { registerAgent } from "./agent-routing";
import { addProjectMember, createProject } from "./shared-state";
import { serverPaths } from "./paths";
import { startCoCodexServer } from "./server";
import { checkServerUpdate } from "./server-update";
import { databaseAdminSummary } from "./admin-status";
import { createTlsIdentity, tlsCertificateFingerprint } from "./tls";
import {
  installWindowsServerService,
  serverServiceEntry,
  startWindowsServerService,
  stopWindowsServerService,
  uninstallWindowsServerService,
  windowsServerServiceStatus,
} from "./windows-service";
import { initializeServerAuthority, prepareServerAuthority, requireActiveServerAuthority, serverAuthorityStatus } from "./server-state";
import { encodeServerAuthorityCertificate, serverTransferTargetSchema, type ServerTransferTarget } from "../../../packages/cocodex-protocol/src/index.ts";

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
  assertSunshinePortsUntouched(port, "create a Windows Firewall rule for");
  const result = Bun.spawnSync([
    "netsh", "advfirewall", "firewall", "add", "rule",
    `name=CoCodex Server TCP ${port}`, "dir=in", "action=allow", "protocol=TCP",
    `localport=${port}`,
  ], { stdout: "ignore", stderr: "ignore" });
  return result.exitCode === 0 ? "created" : "manual-required";
}

function requiredPassphrase(purpose: "backup" | "transfer"): string {
  const file = option("--passphrase-file");
  const environmentValue = purpose === "backup"
    ? process.env.COCODEX_BACKUP_PASSPHRASE?.trim()
    : process.env.COCODEX_TRANSFER_PASSPHRASE?.trim();
  const value = file ? readFileSync(file, "utf8").trim() : environmentValue;
  const variable = purpose === "backup" ? "COCODEX_BACKUP_PASSPHRASE" : "COCODEX_TRANSFER_PASSPHRASE";
  if (!value) throw new Error(`Set ${variable} or provide --passphrase-file`);
  return value;
}

function transferTarget(inputPath: string): ServerTransferTarget {
  try { return serverTransferTargetSchema.parse(JSON.parse(readFileSync(inputPath, "utf8"))); }
  catch { throw new Error("Invalid CoCodex transfer target request"); }
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

function localHealthHost(hostname: string): string {
  if (hostname === "0.0.0.0" || hostname === "::" || hostname === "[::]") return "127.0.0.1";
  return hostname;
}

async function waitForHealthyRestart(
  paths: ReturnType<typeof serverPaths>,
  child: ReturnType<typeof Bun.spawn>,
  timeoutMs = 15_000,
): Promise<void> {
  const config = loadConfig(paths);
  const endpoint = `https://${localHealthHost(config.hostname)}:${config.port}/healthz`;
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    const exitCode = await Promise.race([
      child.exited,
      Bun.sleep(100).then(() => undefined),
    ]);
    if (exitCode !== undefined) {
      throw new Error(`Replacement CoCodex Server exited before becoming healthy (exit ${exitCode})`);
    }
    if (runningPid(paths) !== child.pid) {
      lastError = new Error("Replacement CoCodex Server does not own the Server PID file");
      continue;
    }
    try {
      const response = await fetch(endpoint, {
        signal: AbortSignal.timeout(1_000),
        tls: { rejectUnauthorized: false },
      });
      const body = await response.json() as Record<string, unknown>;
      if (response.ok && body.ok === true && body.service === "cocodex-server" && body.protocol === 1 && body.processId === child.pid) {
        return;
      }
      lastError = new Error(`Replacement health endpoint returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
  }
  try { process.kill(child.pid, "SIGTERM"); } catch { /* child already exited */ }
  await Promise.race([child.exited, Bun.sleep(2_000)]);
  if (runningPid(paths) === child.pid) {
    try { process.kill(child.pid, "SIGKILL"); } catch { /* child already exited */ }
    try { rmSync(paths.pid, { force: true }); } catch { /* report the startup failure below */ }
  }
  const detail = lastError instanceof Error ? `: ${lastError.message}` : "";
  throw new Error(`Replacement CoCodex Server did not become healthy within ${timeoutMs}ms${detail}`);
}

function usage(): void {
  console.log(`CoCodex Server

Usage:
  cocodex-server init --public-host HOST [--port PORT] [--state-root PATH]
  cocodex-server start [--state-root PATH]
  cocodex-server stop [--state-root PATH]
  cocodex-server restart [--state-root PATH]
  cocodex-server status [--state-root PATH]
  cocodex-server update-check --bundle DIRECTORY [--state-root PATH]
  cocodex-server service install|start|stop|status|uninstall [--state-root PATH]
  cocodex-server network-diagnose [--port PORT] [--state-root PATH]
  cocodex-server backup --output FILE [--passphrase-file FILE] [--state-root PATH]
  cocodex-server restore --input FILE [--passphrase-file FILE] [--state-root PATH]
  cocodex-server transfer-export --output FILE [--passphrase-file FILE] [--state-root PATH]
  cocodex-server transfer-prepare --public-host HOST --port PORT --output FILE [--state-root PATH]
  cocodex-server transfer-export --target-request FILE --output FILE [--passphrase-file FILE] [--state-root PATH]
  cocodex-server transfer-import --input FILE [--passphrase-file FILE] [--state-root PATH]
  cocodex-server migrate [--state-root PATH]
  cocodex-server invite [--ttl SECONDS] [--state-root PATH]
  cocodex-server devices [--state-root PATH]
  cocodex-server device-keys --device ID [--state-root PATH]
  cocodex-server bootstrap-approve --fingerprint FINGERPRINT [--state-root PATH]
  cocodex-server revoke --fingerprint FINGERPRINT [--state-root PATH]
  cocodex-server project-create --name NAME --owner-device ID [--state-root PATH]
  cocodex-server project-add-member --project ID --owner-device ID --member-device ID [--state-root PATH]
  cocodex-server agent-add --id ID --project ID --host-device ID --name NAME [--model ID] [--effort LEVEL] [--co-agent-model ID --co-agent-effort LEVEL --max-co-agents 1..8] [--state-root PATH]

Short alias: ccx-server`);
}

async function run(): Promise<void> {
  const paths = serverPaths(option("--state-root"));
  switch (Bun.argv[2] ?? "help") {
    case "init": {
      const publicHost = requiredOption("--public-host");
      const port = Number(option("--port") ?? "19463");
      const adminToken = randomToken();
      saveConfig(paths, createDefaultConfig(paths, publicHost, port, adminToken));
      const identity = createServerIdentity(paths);
      await createTlsIdentity(paths, publicHost);
      openDatabase(paths.database).close();
      const firewall = configureWindowsFirewall(port);
      const portMapping = await tryAutomaticPortMapping(port);
      const networkDiagnostic = classifyDirectHosting(portMapping);
      const db = openDatabase(paths.database);
      initializeServerAuthority(db, identity.fingerprint, "active");
      db.close();
      console.log(JSON.stringify({
        initialized: true,
        stateRoot: paths.root,
        publicHost,
        port,
        serverFingerprint: tlsCertificateFingerprint(paths.tlsCertificate),
        adminToken,
        firewall,
        portMapping,
        networkDiagnostic,
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
    case "update-check": {
      if (["help", "--help", "-h"].includes(Bun.argv[3] ?? "")) {
        console.log("Usage: cocodex-server update-check --bundle DIRECTORY [--state-root PATH]");
        return;
      }
      console.log(JSON.stringify(checkServerUpdate(paths, requiredOption("--bundle")), null, 2));
      return;
    }    case "service": {
      const action = Bun.argv[3] ?? "status";
      if (["help", "--help", "-h"].includes(action)) {
        console.log("Usage: cocodex-server service install|start|stop|status|uninstall [--state-root PATH]");
        return;
      }
      if (action === "install") {
        console.log(JSON.stringify(await installWindowsServerService(paths, serverServiceEntry())));
        return;
      }
      if (action === "start") {
        console.log(JSON.stringify(await startWindowsServerService(paths)));
        return;
      }
      if (action === "stop") {
        console.log(JSON.stringify(await stopWindowsServerService(paths)));
        return;
      }
      if (action === "status") {
        console.log(JSON.stringify(await windowsServerServiceStatus(paths)));
        return;
      }
      if (action === "uninstall") {
        console.log(JSON.stringify(await uninstallWindowsServerService(paths)));
        return;
      }
      throw new Error("Usage: cocodex-server service install|start|stop|status|uninstall [--state-root PATH]");
    }
    case "transfer-prepare": {
      if (existsSync(paths.config)) throw new Error("Destination server state already exists; choose a new state root");
      const publicHost = requiredOption("--public-host");
      const port = Number(requiredOption("--port"));
      const output = requiredOption("--output");
      const adminToken = randomToken();
      saveConfig(paths, createDefaultConfig(paths, publicHost, port, adminToken));
      const identity = createServerIdentity(paths);
      await createTlsIdentity(paths, publicHost);
      const db = openDatabase(paths.database);
      prepareServerAuthority(db, identity.fingerprint);
      db.close();
      const target: ServerTransferTarget = {
        version: 1,
        requestId: randomUUID(),
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
        targetHost: publicHost.trim(),
        targetPort: port,
        targetIdentityPublicKeyPem: identity.publicKeyPem,
        targetIdentityFingerprint: identity.fingerprint,
        targetTlsCertificatePem: readFileSync(paths.tlsCertificate, "utf8"),
        targetTlsFingerprint: tlsCertificateFingerprint(paths.tlsCertificate),
      };
      writeFileSync(output, `${JSON.stringify(target, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
      console.log(JSON.stringify({ prepared: true, stateRoot: paths.root, targetRequest: output, target, adminToken }, null, 2));
      return;
    }
    case "network-diagnose": {
      const port = Number(option("--port") ?? (existsSync(paths.config) ? loadConfig(paths).port : "19463"));
      const mapping = await tryAutomaticPortMapping(port);
      console.log(JSON.stringify(classifyDirectHosting(mapping), null, 2));
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
      let authority: string | null = null;
      let database: ReturnType<typeof databaseAdminSummary> | null = null;
      if (config && existsSync(paths.database)) {
        const db = openDatabase(paths.database);
        try {
          authority = serverAuthorityStatus(db);
          database = databaseAdminSummary(db);
        }
        finally { db.close(); }
      }
      console.log(JSON.stringify({
        initialized: Boolean(config),
        stateRoot: paths.root,
        running: runningPid(paths) !== undefined,
        pid: runningPid(paths) ?? null,
        publicHost: config?.publicHost ?? null,
        port: config?.port ?? null,
        authority,
        database,
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
      await assertDirectServerOwnership(paths, pid);
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
        await assertDirectServerOwnership(paths, pid);
        process.kill(pid, "SIGTERM");
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline && runningPid(paths) !== undefined) await Bun.sleep(100);
        if (runningPid(paths) !== undefined) throw new Error(`CoCodex Server PID ${pid} did not stop`);
      }
      const script = Bun.argv[1];
      const args = script?.endsWith(".ts") ? [script, "start"] : ["start"];
      const child = Bun.spawn([process.execPath, ...args, "--state-root", paths.root], {
        stdin: "ignore", stdout: "ignore", stderr: "ignore", detached: true,
      });
      await waitForHealthyRestart(paths, child);
      child.unref();
      const config = loadConfig(paths);
      console.log(JSON.stringify({
        restarted: true,
        running: true,
        stateRoot: paths.root,
        pid: child.pid,
        endpoint: `https://${config.publicHost}:${config.port}`,
      }));
      return;
    }
    case "backup": {
      requireStopped(paths);
      const identity = loadServerIdentity(paths);
      const backup = createEncryptedServerRecoveryBackup(
        paths,
        identity,
        requiredOption("--output"),
        requiredPassphrase("backup"),
      );
      console.log(JSON.stringify({
        backedUp: true,
        encrypted: true,
        completeServerState: true,
        createdAt: backup.createdAt,
        serverFingerprint: backup.serverFingerprint,
        serverEpoch: backup.serverEpoch,
        payloadSha256: backup.payloadSha256,
      }));
      return;
    }
    case "restore": {
      requireStopped(paths);
      const restored = restoreEncryptedServerRecoveryBackup(
        paths,
        requiredOption("--input"),
        requiredPassphrase("backup"),
      );
      openDatabase(paths.database).close();
      console.log(JSON.stringify({
        restored: true,
        encrypted: true,
        completeServerState: true,
        createdAt: restored.archive.createdAt,
        serverFingerprint: restored.archive.serverFingerprint,
        serverEpoch: restored.archive.serverEpoch,
        payloadSha256: restored.archive.payloadSha256,
        rollbackPath: restored.rollbackPath,
      }));
      return;
    }
    case "transfer-export": {
      requireStopped(paths);
      const identity = loadServerIdentity(paths);
      const targetRequestPath = option("--target-request");
      if (!targetRequestPath) {
        const transfer = createEncryptedServerTransfer(paths, identity, requiredOption("--output"), requiredPassphrase("transfer"));
        console.log(JSON.stringify({ transferred: true, direction: "export", encrypted: true, legacyIdentityBound: true, serverEpoch: transfer.serverEpoch, databaseSha256: transfer.databaseSha256 }));
        return;
      }
      const transfer = createEncryptedAuthorityServerTransfer(paths, identity, requiredOption("--output"), requiredPassphrase("transfer"), transferTarget(targetRequestPath));
      console.log(JSON.stringify({
        transferred: true,
        direction: "export",
        encrypted: true,
        authorityHandoff: true,
        sourceServerEpoch: transfer.sourceServerEpoch,
        targetServerEpoch: transfer.authorityCertificate.serverEpoch,
        targetHost: transfer.target.targetHost,
        targetPort: transfer.target.targetPort,
        authorityCode: encodeServerAuthorityCertificate(transfer.authorityCertificate),
        databaseSha256: transfer.databaseSha256,
      }));
      return;
    }
    case "transfer-import": {
      requireStopped(paths);
      const identity = loadServerIdentity(paths);
      const transfer = restoreEncryptedAuthorityServerTransfer(paths, identity, requiredOption("--input"), requiredPassphrase("transfer"));
      console.log(JSON.stringify({
        transferred: true,
        direction: "import",
        encrypted: true,
        authorityHandoff: true,
        serverEpoch: transfer.transfer.authorityCertificate.serverEpoch,
        authorityCode: transfer.authorityCode,
        databaseSha256: transfer.transfer.databaseSha256,
      }));
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
    }
    case "approve":
    case "bootstrap-approve": {
      const db = openDatabase(paths.database);
      const approved = bootstrapApproveDevice(db, requiredOption("--fingerprint"));
      db.close();
      if (!approved) throw new Error("No unexpired pending device matched that fingerprint");
      console.log(JSON.stringify({ approved: true, bootstrap: true }));
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
        primaryModel: option("--model"),
        primaryEffort: option("--effort") as "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | undefined,
        coAgentModel: option("--co-agent-model") ?? null,
        coAgentEffort: (option("--co-agent-effort") ?? null) as "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | null,
        maxConcurrentCoAgents: Number(option("--max-co-agents") ?? 0),
      });
      db.close();
      console.log(JSON.stringify(agent));
      return;
    }    case "start": {
      const config = loadConfig(paths);
      const identity = loadServerIdentity(paths);
      const db = openDatabase(paths.database);
      requireActiveServerAuthority(db);
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
      let running: ReturnType<typeof startCoCodexServer>;
      try {
        running = startCoCodexServer(config, db, identity);
      } catch (error) {
        db.close();
        if (existsSync(paths.pid) && readFileSync(paths.pid, "utf8").trim() === String(process.pid)) {
          rmSync(paths.pid, { force: true });
        }
        throw error;
      }
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
