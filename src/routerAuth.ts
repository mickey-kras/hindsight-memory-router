import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { QuarantineStore } from "./quarantine/quarantineStore.js";

const ROUTER_TOKEN = process.env.MEMORY_ROUTER_TOKEN;
const ADMIN_TOKEN = process.env.MEMORY_ROUTER_ADMIN_TOKEN;
const AUTH_FAILURE_LOG_WINDOW_MS = 60_000;

export type AuthRouteGroup = "router" | "admin";

export function isAuthorized(
  req: IncomingMessage,
  routerToken: string | undefined,
  allowAnonymous: boolean,
): boolean {
  const token = routerToken ?? ROUTER_TOKEN;
  return token
    ? bearerTokenMatches(req.headers.authorization, token)
    : allowAnonymous;
}

export function isAdminAuthorized(
  req: IncomingMessage,
  adminToken?: string,
): boolean {
  const token = adminToken ?? ADMIN_TOKEN;
  return token ? bearerTokenMatches(req.headers.authorization, token) : false;
}

function bearerTokenMatches(
  authorization: string | undefined,
  token: string,
): boolean {
  if (!authorization) return false;
  const presented = createHash("sha256").update(authorization).digest();
  const expected = createHash("sha256").update(`Bearer ${token}`).digest();
  return timingSafeEqual(presented, expected);
}

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

  return async (routeGroup): Promise<void> => {
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
        `memory-router could not record auth_failed: ${message}\n`,
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

export function assertRouterAuthEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): void {
  if (!environment.MEMORY_ROUTER_TOKEN) {
    const anonymous = environment.MEMORY_ROUTER_ALLOW_ANONYMOUS === "true";
    process.stderr.write(
      anonymous
        ? "memory-router WARNING: anonymous router access enabled for development\n"
        : "memory-router WARNING: MEMORY_ROUTER_TOKEN is unset; router endpoints fail closed\n",
    );
  }
  if (!environment.MEMORY_ROUTER_ADMIN_TOKEN) {
    process.stderr.write(
      "memory-router WARNING: MEMORY_ROUTER_ADMIN_TOKEN is unset; admin endpoints fail closed\n",
    );
  }
}
