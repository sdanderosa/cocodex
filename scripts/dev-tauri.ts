import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const bun = process.execPath;
const proxyUrl = process.env.OPENCODEX_PROXY_TARGET ?? "http://127.0.0.1:10100";
const children: Bun.Subprocess[] = [];
let stopping = false;

async function proxyIsReady(): Promise<boolean> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 700);
  try {
    const response = await fetch(`${proxyUrl}/healthz`, { signal: controller.signal });
    return response.status >= 200 && response.status < 500;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

function stopChildren(): void {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    try { child.kill(); } catch { /* the process may already have exited */ }
  }
}

process.on("SIGINT", stopChildren);
process.on("SIGTERM", stopChildren);

if (!(await proxyIsReady())) {
  children.push(Bun.spawn(
    [bun, "run", "src/cli/index.ts", "start"],
    { cwd: root, stdout: "inherit", stderr: "inherit" },
  ));
}

children.push(Bun.spawn(
  [bun, "run", "dev", "--", "--host", "127.0.0.1", "--port", "4179"],
  {
    cwd: resolve(root, "gui"),
    stdout: "inherit",
    stderr: "inherit",
    // Tauri's beforeDevCommand does not consistently propagate its platform
    // marker into the child Vite process. Pass the target explicitly so the
    // desktop bundle never falls back to same-origin `/healthz` (which Vite
    // serves as the SPA shell when no proxy is configured).
    env: {
      ...process.env,
      OPENCODEX_PROXY_TARGET: proxyUrl,
      VITE_API_BASE: process.env.VITE_API_BASE ?? proxyUrl,
      TAURI_ENV_PLATFORM: process.env.TAURI_ENV_PLATFORM ?? "desktop",
    },
  },
));

// The Vite process is the lifecycle owner. If it exits (for example after a
// compile error), stop the proxy too instead of waiting forever for every
// child to exit on its own.
const firstExitStatus = await Promise.race(children.map(child => child.exited));
stopChildren();
process.exitCode = firstExitStatus === 0 ? 0 : 1;
