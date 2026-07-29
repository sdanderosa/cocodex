import { resolve } from "node:path";
import { buildTauriExternalBinaries } from "./build-tauri-sidecar";

const root = resolve(import.meta.dir, "..");
const frontendRoot = resolve(root, "gui");
let frontend: Bun.Subprocess | undefined;
let stopping = false;

function stopFrontend(): void {
  if (stopping) return;
  stopping = true;
  try { frontend?.kill(); } catch { /* process may already have exited */ }
}

process.on("SIGINT", stopFrontend);
process.on("SIGTERM", stopFrontend);

// Rust owns the bundled sidecar in development exactly as it does in production.
// This hook only builds the external binary and starts Vite; it never probes,
// starts, adopts, or stops the user's home OpenCodex listener on port 10100.
await buildTauriExternalBinaries();

frontend = Bun.spawn(
  [process.execPath, "run", "dev", "--", "--host", "127.0.0.1", "--port", "4179"],
  {
    cwd: frontendRoot,
    stdout: "inherit",
    stderr: "inherit",
    env: {
      ...process.env,
      VITE_API_BASE: process.env.VITE_API_BASE ?? "http://127.0.0.1:10101",
      TAURI_ENV_PLATFORM: process.env.TAURI_ENV_PLATFORM ?? "desktop",
    },
  },
);

process.exitCode = await frontend.exited;
