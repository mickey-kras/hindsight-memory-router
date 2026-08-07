import { HttpError } from "./httpError.js";
import type { RecallBody, RecallResponse, RetainBody } from "./types.js";

export const DEFAULT_HINDSIGHT_TIMEOUT_MS = 10_000;

export type HindsightGatewayErrorKind =
  "timeout" | "http" | "invalid-response" | "network";

type HindsightOperation =
  "health" | "version" | "retain" | "recall" | "invalidate_memory";

type HindsightMethod = "GET" | "POST" | "PATCH";

export interface HindsightGatewayErrorContext {
  operation?: HindsightOperation;
  method?: HindsightMethod;
  timeoutMs?: number;
}

const GATEWAY_ERROR_CODES: Record<HindsightGatewayErrorKind, string> = {
  timeout: "hindsight_timeout",
  http: "hindsight_http_error",
  "invalid-response": "hindsight_invalid_response",
  network: "hindsight_unavailable",
};

const GATEWAY_ERROR_MESSAGES: Record<HindsightGatewayErrorKind, string> = {
  timeout: "Upstream memory service timed out",
  http: "Upstream memory service request failed",
  "invalid-response": "Upstream memory service returned an invalid response",
  network: "Upstream memory service is unavailable",
};

export class HindsightGatewayError extends HttpError {
  readonly upstreamStatus?: number;
  readonly context: Readonly<HindsightGatewayErrorContext>;

  constructor(
    readonly kind: HindsightGatewayErrorKind,
    upstreamStatusOrLegacyMessage?: number | string,
    contextOrLegacyStatus: Readonly<HindsightGatewayErrorContext> | number = {},
  ) {
    super(
      kind === "timeout" ? 504 : 502,
      GATEWAY_ERROR_CODES[kind],
      GATEWAY_ERROR_MESSAGES[kind],
    );
    this.name = "HindsightGatewayError";
    this.upstreamStatus =
      typeof upstreamStatusOrLegacyMessage === "number"
        ? upstreamStatusOrLegacyMessage
        : typeof contextOrLegacyStatus === "number"
          ? contextOrLegacyStatus
          : undefined;
    this.context =
      contextOrLegacyStatus !== null &&
      typeof contextOrLegacyStatus === "object"
        ? contextOrLegacyStatus
        : {};
  }
}

export function hindsightGatewayErrorDetails(
  error: HindsightGatewayError,
): Record<string, unknown> {
  return {
    error_kind: error.kind,
    status: error.status,
    ...(error.upstreamStatus === undefined
      ? {}
      : { upstream_status: error.upstreamStatus }),
    ...(error.context.operation === undefined
      ? {}
      : { operation: error.context.operation }),
    ...(error.context.method === undefined
      ? {}
      : { method: error.context.method }),
    ...(error.context.timeoutMs === undefined
      ? {}
      : { timeout_ms: error.context.timeoutMs }),
  };
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
    return this.request("health", "GET", "/health");
  }

  async version(): Promise<unknown> {
    return this.request("version", "GET", "/version");
  }

  async retain(bankId: string, body: RetainBody): Promise<unknown> {
    return this.request(
      "retain",
      "POST",
      `/v1/default/banks/${encodeURIComponent(bankId)}/memories`,
      body,
    );
  }

  async recall(bankId: string, body: RecallBody): Promise<RecallResponse> {
    const response = await this.request(
      "recall",
      "POST",
      `/v1/default/banks/${encodeURIComponent(bankId)}/memories/recall`,
      body,
    );
    return parseRecallResponse(response);
  }

  async invalidateMemory(
    bankId: string,
    memoryId: string,
    reason: string,
  ): Promise<void> {
    await this.request(
      "invalidate_memory",
      "PATCH",
      `/v1/default/banks/${encodeURIComponent(bankId)}/memories/${encodeURIComponent(memoryId)}`,
      { state: "invalidated", reason },
    );
  }

  private async request(
    operation: HindsightOperation,
    method: HindsightMethod,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (this.apiKey) headers.authorization = `Bearer ${this.apiKey}`;

    let res: Response;
    try {
      res = await fetch(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw this.toGatewayError(error, operation, method);
    }

    if (!res.ok) {
      await discardErrorBody(res);
      throw new HindsightGatewayError("http", res.status, {
        operation,
        method,
      });
    }

    const text = await res.text();
    if (!text) return null;
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new HindsightGatewayError("invalid-response", res.status, {
        operation,
        method,
      });
    }
  }

  private toGatewayError(
    error: unknown,
    operation: HindsightOperation,
    method: HindsightMethod,
  ): HindsightGatewayError {
    if (error instanceof HindsightGatewayError) return error;
    const name = (error as { name?: unknown } | null)?.name;
    if (name === "TimeoutError" || name === "AbortError") {
      return new HindsightGatewayError("timeout", undefined, {
        operation,
        method,
        timeoutMs: this.timeoutMs,
      });
    }
    return new HindsightGatewayError("network", undefined, {
      operation,
      method,
    });
  }
}

export function parseRecallResponse(value: unknown): RecallResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalidRecallResponse();
  }
  const response = value as Record<string, unknown>;
  if (!Array.isArray(response.results)) {
    throw invalidRecallResponse();
  }
  for (const result of response.results) {
    if (
      !result ||
      typeof result !== "object" ||
      Array.isArray(result) ||
      typeof (result as Record<string, unknown>).id !== "string" ||
      typeof (result as Record<string, unknown>).text !== "string"
    ) {
      throw invalidRecallResponse();
    }
  }
  for (const field of [
    "chunks",
    "entities",
    "source_facts",
    "trace",
  ] as const) {
    const fieldValue = response[field];
    if (
      fieldValue !== undefined &&
      fieldValue !== null &&
      (typeof fieldValue !== "object" || Array.isArray(fieldValue))
    ) {
      throw invalidRecallResponse();
    }
  }
  return value as RecallResponse;
}

function invalidRecallResponse(): HindsightGatewayError {
  return new HindsightGatewayError("invalid-response", undefined, {
    operation: "recall",
    method: "POST",
  });
}

async function discardErrorBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The HTTP error remains authoritative if cancellation fails.
  }
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
