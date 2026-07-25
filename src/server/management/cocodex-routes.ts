import { getCoCodexGuiBridge } from "../../cocodex/gui-bridge";
import { jsonResponse } from "../auth-cors";
import type { ManagementContext } from "./context";

function routeError(ctx: ManagementContext, error: unknown, status = 400): Response {
  return jsonResponse(
    { error: error instanceof Error ? error.message : String(error) },
    status,
    ctx.req,
    ctx.config,
  );
}

export async function handleCoCodexRoutes(ctx: ManagementContext): Promise<Response | null> {
  const { req, url, config } = ctx;
  if (!url.pathname.startsWith("/api/cocodex/")) return null;
  const bridge = getCoCodexGuiBridge();
  try {
    if (url.pathname === "/api/cocodex/status" && req.method === "GET") {
      return jsonResponse(bridge.status(), 200, req, config);
    }
    if (url.pathname === "/api/cocodex/events" && req.method === "GET") {
      const after = Number(url.searchParams.get("after") ?? "0");
      return jsonResponse(bridge.eventsAfter(after), 200, req, config);
    }
    if (url.pathname === "/api/cocodex/enroll" && req.method === "POST") {
      const body = await req.json() as { invite?: unknown; displayName?: unknown };
      return jsonResponse(await bridge.enroll(String(body.invite ?? ""), String(body.displayName ?? "")), 201, req, config);
    }
    if (url.pathname === "/api/cocodex/session" && req.method === "POST") {
      const body = await req.json() as { action?: unknown };
      if (body.action === "start") return jsonResponse(bridge.start(), 200, req, config);
      if (body.action === "stop") return jsonResponse(bridge.stop(), 200, req, config);
      return routeError(ctx, new Error("Session action must be start or stop"));
    }
    if (url.pathname === "/api/cocodex/command" && req.method === "POST") {
      const body = await req.json();
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return routeError(ctx, new Error("Command must be a JSON object"));
      }
      return jsonResponse(bridge.command(body as Record<string, unknown>), 202, req, config);
    }
    return routeError(ctx, new Error("Unknown CoCodex management endpoint"), 404);
  } catch (error) {
    return routeError(ctx, error);
  }
}
