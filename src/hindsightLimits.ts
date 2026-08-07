import { HttpError } from "./httpError.js";
import { integerEnv } from "./integerEnv.js";
import {
  InMemorySlidingWindowRateLimiter,
  type RateLimitSession,
} from "./quarantine/rateLimiter.js";
import type { RecallBody, RetainBody } from "./types.js";

export interface HindsightLimitConfig {
  retainWriterMax: number;
  retainGlobalMax: number;
  recallWriterMax: number;
  recallGlobalMax: number;
  rateLimitWindowMs: number;
  maxRetainItems: number;
  maxRetainContentBytes: number;
  maxRecallQueryBytes: number;
  maxRecallMaxTokens: number;
}

export const DEFAULT_HINDSIGHT_LIMITS: HindsightLimitConfig = {
  retainWriterMax: 30,
  retainGlobalMax: 300,
  recallWriterMax: 120,
  recallGlobalMax: 1_200,
  rateLimitWindowMs: 60_000,
  maxRetainItems: 100,
  maxRetainContentBytes: 524_288,
  maxRecallQueryBytes: 32_768,
  maxRecallMaxTokens: 8_192,
};

export function hindsightLimitConfigFromEnv(
  environment: NodeJS.ProcessEnv = process.env,
): HindsightLimitConfig {
  return {
    retainWriterMax: integerEnv(
      environment,
      "HINDSIGHT_RETAIN_RATE_LIMIT_WRITER_MAX",
      DEFAULT_HINDSIGHT_LIMITS.retainWriterMax,
      { minimum: 1 },
    ),
    retainGlobalMax: integerEnv(
      environment,
      "HINDSIGHT_RETAIN_RATE_LIMIT_GLOBAL_MAX",
      DEFAULT_HINDSIGHT_LIMITS.retainGlobalMax,
      { minimum: 1 },
    ),
    recallWriterMax: integerEnv(
      environment,
      "HINDSIGHT_RECALL_RATE_LIMIT_WRITER_MAX",
      DEFAULT_HINDSIGHT_LIMITS.recallWriterMax,
      { minimum: 1 },
    ),
    recallGlobalMax: integerEnv(
      environment,
      "HINDSIGHT_RECALL_RATE_LIMIT_GLOBAL_MAX",
      DEFAULT_HINDSIGHT_LIMITS.recallGlobalMax,
      { minimum: 1 },
    ),
    rateLimitWindowMs: integerEnv(
      environment,
      "HINDSIGHT_RATE_LIMIT_WINDOW_MS",
      DEFAULT_HINDSIGHT_LIMITS.rateLimitWindowMs,
      { minimum: 1 },
    ),
    maxRetainItems: integerEnv(
      environment,
      "HINDSIGHT_RETAIN_MAX_ITEMS",
      DEFAULT_HINDSIGHT_LIMITS.maxRetainItems,
      { minimum: 1 },
    ),
    maxRetainContentBytes: integerEnv(
      environment,
      "HINDSIGHT_RETAIN_MAX_CONTENT_BYTES",
      DEFAULT_HINDSIGHT_LIMITS.maxRetainContentBytes,
      { minimum: 1 },
    ),
    maxRecallQueryBytes: integerEnv(
      environment,
      "HINDSIGHT_RECALL_MAX_QUERY_BYTES",
      DEFAULT_HINDSIGHT_LIMITS.maxRecallQueryBytes,
      { minimum: 1 },
    ),
    maxRecallMaxTokens: integerEnv(
      environment,
      "HINDSIGHT_RECALL_MAX_TOKENS",
      DEFAULT_HINDSIGHT_LIMITS.maxRecallMaxTokens,
      { minimum: 1 },
    ),
  };
}

export class HindsightLimits {
  private readonly limiter: RateLimitSession;

  constructor(
    private readonly config: HindsightLimitConfig = DEFAULT_HINDSIGHT_LIMITS,
    limiter: RateLimitSession = new InMemorySlidingWindowRateLimiter(),
    private readonly now: () => number = () => Date.now(),
  ) {
    this.limiter = limiter;
  }

  assertRetainBounds(body: RetainBody): void {
    if (body.items.length > this.config.maxRetainItems) {
      throw new HttpError(
        413,
        "retain_item_limit_exceeded",
        "retain request contains too many memory items",
      );
    }
    if (stringValueBytes(body) > this.config.maxRetainContentBytes) {
      throw new HttpError(
        413,
        "retain_content_too_large",
        "retain content exceeds the configured byte limit",
      );
    }
  }

  assertRecallBounds(body: RecallBody): void {
    if (
      Buffer.byteLength(body.query, "utf8") > this.config.maxRecallQueryBytes
    ) {
      throw new HttpError(
        413,
        "recall_query_too_large",
        "recall query exceeds the configured byte limit",
      );
    }
    if (
      body.max_tokens !== undefined &&
      body.max_tokens > this.config.maxRecallMaxTokens
    ) {
      throw new HttpError(
        413,
        "recall_max_tokens_exceeded",
        "recall max_tokens exceeds the configured limit",
      );
    }
  }

  consumeRetain(writerId: string): Promise<void> {
    return this.consumeQuota(
      "retain",
      writerId,
      this.config.retainWriterMax,
      this.config.retainGlobalMax,
    );
  }

  consumeRecall(writerId: string): Promise<void> {
    return this.consumeQuota(
      "recall",
      writerId,
      this.config.recallWriterMax,
      this.config.recallGlobalMax,
    );
  }

  private async consumeQuota(
    requestClass: "retain" | "recall",
    writerId: string,
    writerMax: number,
    globalMax: number,
  ): Promise<void> {
    try {
      await this.limiter.consumeMany(
        [
          {
            key: `hindsight:${requestClass}:writer:${writerId}`,
            rule: { max: writerMax, windowMs: this.config.rateLimitWindowMs },
          },
          {
            key: `hindsight:${requestClass}:global`,
            rule: { max: globalMax, windowMs: this.config.rateLimitWindowMs },
          },
        ],
        new Date(this.now()),
      );
    } catch (error) {
      if (error instanceof HttpError && error.status === 429) {
        throw new HttpError(
          429,
          "hindsight_rate_limited",
          `too many Hindsight ${requestClass} requests`,
          {
            "retry-after": String(
              Math.max(1, Math.ceil(this.config.rateLimitWindowMs / 1_000)),
            ),
          },
        );
      }
      throw error;
    }
  }
}

function stringValueBytes(value: unknown): number {
  const pending: unknown[] = [value];
  let total = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (typeof current === "string") {
      total += Buffer.byteLength(current, "utf8");
    } else if (Array.isArray(current)) {
      pending.push(...current);
    } else if (current !== null && typeof current === "object") {
      pending.push(...Object.values(current));
    }
  }
  return total;
}
