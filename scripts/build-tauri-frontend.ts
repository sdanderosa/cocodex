import { resolve } from "node:path";
import { buildTauriSidecar } from "./build-tauri-sidecar";

const repoRoot = resolve(import.meta.dir, "..");

await buildTauriSidecar();

const frontend = Bun.spawn([process.execPath, "run", "build"], {
  cwd: resolve(repoRoot, "gui"),
  stdout: "inherit",
  stderr: "inherit",
  env: process.env,
});
process.exitCode = await frontend.exited;
