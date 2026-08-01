import type { RecallBody, RecallResponse, RetainBody } from "./types.js";

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
  ) {}

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

    const res = await fetch(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    const text = await res.text();
    const payload = text ? JSON.parse(text) : null;
    if (!res.ok) {
      throw new Error(
        `Hindsight ${method} ${path} failed: HTTP ${res.status} ${text}`,
      );
    }
    return payload;
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
