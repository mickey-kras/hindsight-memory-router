import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { QuarantineStore } from "./quarantine/quarantineStore.js";

const ROUTER_TOKEN = process.env.MEMORY_ROUTER_TOKEN;
const ADMIN_TOKEN = process.env.MEMORY_ROUTER_ADMIN_TOKEN;

export type AuthRouteGroup = "router" | "admin";

export function isAuthorized(
  req: IncomingMessage,
  routerToken: string | undefined,
  allowAnonymous: boolean,
): boolean {
  const token = routerToken ?? ROUTER_TOKEN;
  if (!token) return allowAnonymous;
  return bearerTokenMatches(req.headers.authorization, token);
}

export function isAdminAuthorized(
  req: IncomingMessage,
  adminToken?: string,
): boolean {
  const token = adminToken ?? ADMIN_TOKEN;
  if (!token) return false;
  return bearerTokenMatches(req.headers.authorization, token);
}

// Both sides are hashed to a fixed length first so the comparison is
// constant-time and does not leak the expected token length.
function bearerTokenMatches(
  authorization: string | undefined,
  token: string,
): boolean {
  if (!authorization) return false;
  const presented = createHash("sha256").update(authorization, "utf8").digest();
  const expected = createHash("sha256")
    .update(`Bearer ${token}`, "utf8")
    .digest();
  return timingSafeEqual(presented, expected);
}

const AUTH_FAILURE_LOG_WINDOW_MS = 60_000;

// Failed authentication is audited with a bounded identity space: one
// deduplicated security_event per route group, plus a structured stderr
// line. Stderr is throttled to one line per kind per route group per
// window so probing cannot flood logs. Token material is never logged
// or stored.
export function createAuthFailureAuditor(
  quarantineStore: QuarantineStore,
  now: () => number = () => Date.now(),
): (routeGroup: AuthRouteGroup) => Promise<void> {
  const lastLoggedAt = new Map<string, number>();
  const logThrottled = (
    channel: "event" | "error",
    routeGroup: AuthRouteGroup,
    line: string,
  ): void => {
    const key = `${channel}:${routeGroup}`;
    const at = now();
    const last = lastLoggedAt.get(key);
    if (last !== undefined && at - last < AUTH_FAILURE_LOG_WINDOW_MS) return;
    lastLoggedAt.set(key, at);
    process.stderr.write(line);
  };
  return async (routeGroup: AuthRouteGroup): Promise<void> => {
    logThrottled(
      "event",
      routeGroup,
      `${JSON.stringify({ event: "auth_failed", route_group: routeGroup })}\n`,
    );
    try {
      await quarantineStore.put({
        timestamp: new Date().toISOString(),
        kind: "security_event",
        reason: "auth_failed",
        source: "http",
        dedupeKey: `auth_failed:${routeGroup}`,
        payload: { action: "auth_failed", route_group: routeGroup },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown error";
      logThrottled(
        "error",
        routeGroup,
        `memory-router could not record an auth_failed security event: ${message}\n`,
      );
    }
  };
}

export function assertNoPrivateKeyEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): void {
  const injected = Object.keys(environment).find((name) =>
    name.startsWith("QUARANTINE_PRIVATE_KEY"),
  );
  if (injected) {
    throw new Error(
      `${injected} must not be available to the memory-router process`,
    );
  }
}

// Router authentication fails closed: without MEMORY_ROUTER_TOKEN every
// retain/recall/version request is rejected unless the explicit dev-only
// opt-in MEMORY_ROUTER_ALLOW_ANONYMOUS=true is set. Both states are
// surfaced loudly at startup instead of silently changing the trust model.
export function assertRouterAuthEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): void {
  if (environment.MEMORY_ROUTER_TOKEN) return;
  if (environment.MEMORY_ROUTER_ALLOW_ANONYMOUS === "true") {
    process.stderr.write(
      "memory-router WARNING: MEMORY_ROUTER_ALLOW_ANONYMOUS=true with no MEMORY_ROUTER_TOKEN; retain/recall/version are anonymously accessible. Development only, never use in production.\n",
    );
    return;
  }
  process.stderr.write(
    "memory-router WARNING: MEMORY_ROUTER_TOKEN is not set; retain/recall/version reject all requests (fail-closed). Set MEMORY_ROUTER_TOKEN, or set MEMORY_ROUTER_ALLOW_ANONYMOUS=true for local development only.\n",
  );
  if (!environment.MEMORY_ROUTER_ADMIN_TOKEN) {
    process.stderr.write(
      "memory-router WARNING: MEMORY_ROUTER_ADMIN_TOKEN is not set; /admin/* routes reject all requests (fail-closed).\n",
    );
  }
}
