import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { QuarantineStore } from "./quarantine/quarantineStore.js";

const ROUTER_TOKEN = process.env.MEMORY_ROUTER_TOKEN;
const ADMIN_TOKEN = process.env.MEMORY_ROUTER_ADMIN_TOKEN;
const ADMIN_READ_TOKEN = process.env.MEMORY_ROUTER_ADMIN_READ_TOKEN;
const ADMIN_REVIEW_TOKEN = process.env.MEMORY_ROUTER_ADMIN_REVIEW_TOKEN;
const ADMIN_CLEANUP_TOKEN = process.env.MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN;
const AUTH_FAILURE_LOG_WINDOW_MS = 60_000;

export type AuthRouteGroup = "router" | "admin";
export type AdminScope = "read" | "review" | "cleanup";

export interface AdminTokens {
  legacy?: string;
  read?: string;
  review?: string;
  cleanup?: string;
}

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
  scope: AdminScope,
  configured: AdminTokens = {},
): boolean {
  const tokens = adminTokensForScope(scope, configured);
  return bearerTokenMatchesAny(req.headers.authorization, tokens);
}

function adminTokensForScope(
  scope: AdminScope,
  configured: AdminTokens,
): string[] {
  const legacy = configured.legacy ?? ADMIN_TOKEN;
  const read = configured.read ?? ADMIN_READ_TOKEN;
  const review = configured.review ?? ADMIN_REVIEW_TOKEN;
  const cleanup = configured.cleanup ?? ADMIN_CLEANUP_TOKEN;

  return [
    legacy,
    ...(scope === "read" ? [read, review] : []),
    ...(scope === "review" ? [review] : []),
    ...(scope === "cleanup" ? [cleanup] : []),
  ].filter((token): token is string => token !== undefined && token !== "");
}

function bearerTokenMatchesAny(
  authorization: string | undefined,
  tokens: readonly string[],
): boolean {
  if (!authorization || tokens.length === 0) return false;
  const presented = createHash("sha256").update(authorization).digest();
  let matched = false;
  for (const token of tokens) {
    const expected = createHash("sha256").update(`Bearer ${token}`).digest();
    matched = timingSafeEqual(presented, expected) || matched;
  }
  return matched;
}

function bearerTokenMatches(
  authorization: string | undefined,
  token: string,
): boolean {
  return bearerTokenMatchesAny(authorization, [token]);
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

export function assertRouterAuthEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): void {
  if (!environment.MEMORY_ROUTER_TOKEN) {
    if (environment.MEMORY_ROUTER_ALLOW_ANONYMOUS === "true") {
      process.stderr.write(
        "memory-router WARNING: MEMORY_ROUTER_ALLOW_ANONYMOUS=true; Development only\n",
      );
    } else {
      process.stderr.write(
        "memory-router WARNING: MEMORY_ROUTER_TOKEN is not set; router endpoints fail-closed\n",
      );
    }
  }

  if (environment.MEMORY_ROUTER_ADMIN_TOKEN) return;

  if (
    !environment.MEMORY_ROUTER_ADMIN_READ_TOKEN &&
    !environment.MEMORY_ROUTER_ADMIN_REVIEW_TOKEN
  ) {
    process.stderr.write(
      "memory-router WARNING: admin read token is not set; admin read endpoints fail-closed\n",
    );
  }
  if (!environment.MEMORY_ROUTER_ADMIN_REVIEW_TOKEN) {
    process.stderr.write(
      "memory-router WARNING: admin review token is not set; review endpoints fail-closed\n",
    );
  }
  if (!environment.MEMORY_ROUTER_ADMIN_CLEANUP_TOKEN) {
    process.stderr.write(
      "memory-router WARNING: admin cleanup token is not set; cleanup endpoint fails-closed\n",
    );
  }
}
