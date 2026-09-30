// Typed client for the router admin API. Same-origin by default (nginx
// proxies /admin to the router); a host may inject a base URL via
// window.__MEMORY_ROUTER_UI_CONFIG__ (see lib/config.ts). Tokens are supplied
// per request, never stored here.

import { apiUrl, resolveUiConfig } from "./config";

import type {
  CleanupRequest,
  CleanupResponse,
  DecryptedQuarantineObject,
  QuarantineItemResponse,
  QuarantineQueueResponse,
  QuarantineStats,
  ReconcileRequest,
  ReconcileResponse,
  RouterError,
  LivenessResponse,
} from "./types";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export interface AdminTokens {
  read: string;
  review: string;
  cleanup: string;
}

export type AdminSession = AdminTokens | "host";

type TokenScope = keyof AdminTokens;

async function request<T>(
  path: string,
  scope: TokenScope,
  tokens: AdminSession,
  init?: RequestInit,
): Promise<T> {
  const config = resolveUiConfig();
  const hostAuth = config.auth === "host";
  const token = hostAuth || tokens === "host" ? "" : tokens[scope];
  if (!hostAuth && !token) throw new ApiError(0, "token_missing", `no ${scope} token configured`);
  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      ...init,
      ...(hostAuth ? { credentials: "same-origin" as const, mode: "same-origin" as const, redirect: "error" as const } : {}),
      headers: {
        ...(!hostAuth ? { Authorization: `Bearer ${token}` } : {}),
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
      },
    });
  } catch {
    throw new ApiError(0, "network_error", "router unreachable");
  }
  if (!response.ok) {
    let code = `http_${response.status}`;
    let message = `request failed with status ${response.status}`;
    try {
      const body = (await response.json()) as RouterError;
      if (typeof body.error === "string") code = body.error;
      if (typeof body.message === "string") message = body.message;
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    throw new ApiError(response.status, code, message);
  }
  return (await response.json()) as T;
}

export async function fetchLiveness(): Promise<LivenessResponse> {
  const response = await fetch(apiUrl("/health/live"));
  if (!response.ok) throw new Error("offline");
  const body: unknown = await response.json();
  if (typeof body !== "object" || body === null || !("status" in body) || body.status !== "alive") {
    throw new Error("invalid liveness response");
  }
  return { status: "alive" };
}

export function listQueue(
  tokens: AdminSession,
  limit = 100,
  offset = 0,
): Promise<QuarantineQueueResponse> {
  return request(`/admin/quarantine/queue?limit=${limit}&offset=${offset}`, "read", tokens);
}

export function fetchStats(tokens: AdminSession): Promise<QuarantineStats> {
  return request("/admin/quarantine/stats", "read", tokens);
}

export function fetchItem(tokens: AdminSession, quarantineId: string): Promise<QuarantineItemResponse> {
  return request(`/admin/quarantine/items/${encodeURIComponent(quarantineId)}`, "read", tokens);
}

export function approveItem(
  tokens: AdminSession,
  quarantineId: string,
  decrypted: DecryptedQuarantineObject,
): Promise<Record<string, unknown>> {
  return request(
    `/admin/quarantine/items/${encodeURIComponent(quarantineId)}/approve`,
    "review",
    tokens,
    { method: "POST", body: JSON.stringify({ decrypted }) },
  );
}

function reviewItem(
  tokens: AdminSession,
  quarantineId: string,
  action: "reject" | "postpone",
): Promise<Record<string, unknown>> {
  return request(
    `/admin/quarantine/items/${encodeURIComponent(quarantineId)}/${action}`,
    "review",
    tokens,
    { method: "POST" },
  );
}

export function rejectItem(
  tokens: AdminSession,
  quarantineId: string,
): Promise<Record<string, unknown>> {
  return reviewItem(tokens, quarantineId, "reject");
}

export function postponeItem(
  tokens: AdminSession,
  quarantineId: string,
): Promise<Record<string, unknown>> {
  return reviewItem(tokens, quarantineId, "postpone");
}

export function reconcileItem(
  tokens: AdminSession,
  quarantineId: string,
  body: ReconcileRequest,
): Promise<ReconcileResponse> {
  return request(
    `/admin/quarantine/items/${encodeURIComponent(quarantineId)}/reconcile`,
    "review",
    tokens,
    { method: "POST", body: JSON.stringify(body) },
  );
}

export function runCleanup(tokens: AdminSession, body: CleanupRequest): Promise<CleanupResponse> {
  return request("/admin/quarantine/cleanup", "cleanup", tokens, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
