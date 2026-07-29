import { getCoCodexGuiBridge } from "../../cocodex/gui-bridge";
import { isSameOriginAsRequest, isTrustedTauriOrigin, jsonResponse } from "../auth-cors";
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
  const origin = req.headers.get("Origin");
  const trustedUiOrigin = origin
    ? isSameOriginAsRequest(req, origin) || isTrustedTauriOrigin(origin)
    : req.headers.get("Sec-Fetch-Site") === "same-origin";
  if (url.pathname === "/api/cocodex/capability" && req.method === "GET") {
    if (!trustedUiOrigin) return routeError(ctx, new Error("Trusted CoCodex UI origin required"), 403);
    return jsonResponse({ capability: bridge.issueCapability() }, 200, req, config);
  }
  if ((origin && !isSameOriginAsRequest(req, origin) && !isTrustedTauriOrigin(origin))
    || !bridge.acceptsCapability(req.headers.get("X-CoCodex-Capability"))) {
    return routeError(ctx, new Error("CoCodex GUI capability required"), 403);
  }
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
