import { HttpError } from "./httpError.js";
import type { RecallBody, RecallResponse, RetainBody } from "./types.js";

export const DEFAULT_HINDSIGHT_TIMEOUT_MS = 10_000;
const MAX_UPSTREAM_ERROR_BODY_CHARS = 512;

export type HindsightGatewayErrorKind =
  "timeout" | "http" | "invalid-response" | "network";

const GATEWAY_ERROR_CODES: Record<HindsightGatewayErrorKind, string> = {
  timeout: "hindsight_timeout",
  http: "hindsight_http_error",
  "invalid-response": "hindsight_invalid_response",
  network: "hindsight_unavailable",
};

export class HindsightGatewayError extends HttpError {
  constructor(
    readonly kind: HindsightGatewayErrorKind,
    message: string,
    readonly upstreamStatus?: number,
  ) {
    super(kind === "timeout" ? 504 : 502, GATEWAY_ERROR_CODES[kind], message);
    this.name = "HindsightGatewayError";
  }
}

export function gatewayErrorKind(
  error: unknown,
): HindsightGatewayErrorKind | "unknown" {
  return error instanceof HindsightGatewayError ? error.kind : "unknown";
}

export interface HindsightGateway {
  health(): Promise<unknown>;
  version(): Promise<unknown>;
  retain(bankId: string, body: RetainBody): Promise<unknown>;
  recall(bankId: string, body: RecallBody): Promise<RecallResponse>;
  invalidateMemory(
    bankId: string,
    memoryId: string,
    reason: string,
  ): Promise<void>;
}

export class FetchHindsightGateway implements HindsightGateway {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey?: string,
    private readonly timeoutMs: number = DEFAULT_HINDSIGHT_TIMEOUT_MS,
  ) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
      throw new Error("Hindsight timeout must be a positive integer");
    }
  }

  async health(): Promise<unknown> {
    return this.request("GET", "/health");
  }

  async version(): Promise<unknown> {
    return this.request("GET", "/version");
  }

  async retain(bankId: string, body: RetainBody): Promise<unknown> {
    return this.request(
      "POST",
      `/v1/default/banks/${encodeURIComponent(bankId)}/memories`,
      body,
    );
  }

  async recall(bankId: string, body: RecallBody): Promise<RecallResponse> {
    return this.request(
      "POST",
      `/v1/default/banks/${encodeURIComponent(bankId)}/memories/recall`,
      body,
    ) as Promise<RecallResponse>;
  }

  async invalidateMemory(
    bankId: string,
    memoryId: string,
    reason: string,
  ): Promise<void> {
    await this.request(
      "PATCH",
      `/v1/default/banks/${encodeURIComponent(bankId)}/memories/${encodeURIComponent(memoryId)}`,
      { state: "invalidated", reason },
    );
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (this.apiKey) headers.authorization = `Bearer ${this.apiKey}`;

    let res: Response;
    let text: string;
    try {
      res = await fetch(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      text = await res.text();
    } catch (error) {
      throw this.toGatewayError(error, method, path);
    }

    if (!res.ok) {
      throw new HindsightGatewayError(
        "http",
        `Hindsight ${method} ${path} failed: HTTP ${res.status} ${truncateUpstreamBody(text)}`,
        res.status,
      );
    }
    if (!text) return null;
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new HindsightGatewayError(
        "invalid-response",
        `Hindsight ${method} ${path} returned an invalid JSON response`,
        res.status,
      );
    }
  }

  private toGatewayError(
    error: unknown,
    method: string,
    path: string,
  ): HindsightGatewayError {
    if (error instanceof HindsightGatewayError) return error;
    const name = (error as { name?: unknown } | null)?.name;
    if (name === "TimeoutError" || name === "AbortError") {
      return new HindsightGatewayError(
        "timeout",
        `Hindsight ${method} ${path} timed out after ${this.timeoutMs}ms`,
      );
    }
    const message =
      error instanceof Error ? error.message : "upstream request failed";
    return new HindsightGatewayError(
      "network",
      `Hindsight ${method} ${path} failed: ${truncateUpstreamBody(message)}`,
    );
  }
}

function truncateUpstreamBody(text: string): string {
  return text.length > MAX_UPSTREAM_ERROR_BODY_CHARS
    ? `${text.slice(0, MAX_UPSTREAM_ERROR_BODY_CHARS)}...(truncated)`
    : text;
}

export class FakeHindsightGateway implements HindsightGateway {
  readonly retained: Array<{ bankId: string; body: RetainBody }> = [];
  readonly recalled: Array<{ bankId: string; body: RecallBody }> = [];
  readonly invalidated: Array<{
    bankId: string;
    memoryId: string;
    reason: string;
  }> = [];

  async health(): Promise<unknown> {
    return { status: "healthy" };
  }

  async version(): Promise<unknown> {
    return { api_version: "0.8.3", features: {} };
  }

  async retain(bankId: string, body: RetainBody): Promise<unknown> {
    this.retained.push({ bankId, body });
    return { ok: true };
  }

  async recall(bankId: string, body: RecallBody): Promise<RecallResponse> {
    this.recalled.push({ bankId, body });
    return {
      results: [
        {
          id: `${bankId}-result`,
          text: `memory from ${bankId}`,
          type: "world",
          metadata: { bank_id: bankId },
        },
      ],
    };
  }

  async invalidateMemory(
    bankId: string,
    memoryId: string,
    reason: string,
  ): Promise<void> {
    this.invalidated.push({ bankId, memoryId, reason });
  }
}
