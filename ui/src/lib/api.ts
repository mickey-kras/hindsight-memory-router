// Typed client for the router admin API. Same-origin only (nginx proxies
// /admin to the router). Tokens are supplied per request, never stored here.

import type {
  CleanupRequest,
  CleanupResponse,
  DecryptedQuarantineObject,
  QuarantineItemResponse,
  QuarantineQueueResponse,
  QuarantineStats,
  RouterError,
  VersionResponse,
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

type TokenScope = keyof AdminTokens;

async function request<T>(
  path: string,
  scope: TokenScope,
  tokens: AdminTokens,
  init?: RequestInit,
): Promise<T> {
  const token = tokens[scope];
  if (!token) throw new ApiError(0, "token_missing", `no ${scope} token configured`);
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
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

export function fetchVersion(): Promise<VersionResponse> {
  // Unauthenticated probe used to show router presence on the connect screen.
  return fetch("/version").then((r) => (r.ok ? r.json() : Promise.reject(new Error("offline"))));
}

export function listQueue(
  tokens: AdminTokens,
  limit = 100,
  offset = 0,
): Promise<QuarantineQueueResponse> {
  return request(`/admin/quarantine/queue?limit=${limit}&offset=${offset}`, "read", tokens);
}

export function fetchStats(tokens: AdminTokens): Promise<QuarantineStats> {
  return request("/admin/quarantine/stats", "read", tokens);
}

export function fetchItem(tokens: AdminTokens, quarantineId: string): Promise<QuarantineItemResponse> {
  return request(`/admin/quarantine/items/${encodeURIComponent(quarantineId)}`, "read", tokens);
}

export function approveItem(
  tokens: AdminTokens,
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
  tokens: AdminTokens,
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
  tokens: AdminTokens,
  quarantineId: string,
): Promise<Record<string, unknown>> {
  return reviewItem(tokens, quarantineId, "reject");
}

export function postponeItem(
  tokens: AdminTokens,
  quarantineId: string,
): Promise<Record<string, unknown>> {
  return reviewItem(tokens, quarantineId, "postpone");
}

export function runCleanup(tokens: AdminTokens, body: CleanupRequest): Promise<CleanupResponse> {
  return request("/admin/quarantine/cleanup", "cleanup", tokens, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
