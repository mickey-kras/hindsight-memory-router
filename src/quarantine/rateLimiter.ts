import postgres, { type Sql } from "postgres";
import { HttpError } from "../httpError.js";

export interface RateLimitRule {
  max: number;
  windowMs: number;
}

/**
 * Pluggable quota backend for quarantine writes. Implementations throw an
 * HttpError with status 429 when a bucket is exhausted. Rules with a
 * non-positive max or windowMs are treated as disabled.
 */
export interface QuarantineRateLimiter {
  consume(key: string, rule: RateLimitRule, at?: Date): Promise<void>;
}

export function rateLimitExceededError(): HttpError {
  return new HttpError(
    429,
    "quarantine_rate_limited",
    "too many quarantine writes",
  );
}

/**
 * Per-process sliding-window counter. Buckets hold the timestamps of recent
 * consumes, so quota refills continuously instead of resetting at fixed
 * window boundaries (no boundary bursts). Restarting the process resets the
 * buckets; multi-instance deployments need the PostgreSQL limiter below.
 */
export class InMemorySlidingWindowRateLimiter implements QuarantineRateLimiter {
  private readonly buckets = new Map<string, number[]>();

  consume(key: string, rule: RateLimitRule, at?: Date): Promise<void> {
    if (rule.max <= 0 || rule.windowMs <= 0) return Promise.resolve();
    const now = at?.getTime() ?? Date.now();
    const cutoff = now - rule.windowMs;
    const events = (this.buckets.get(key) ?? []).filter(
      (occurredAt) => occurredAt > cutoff,
    );
    if (events.length >= rule.max) {
      return Promise.reject(rateLimitExceededError());
    }
    events.push(now);
    this.buckets.set(key, events);
    return Promise.resolve();
  }
}

export interface PostgresRateLimiterOptions {
  /** Delete expired rows for all buckets every N consumes. */
  pruneIntervalConsumes?: number;
}

const DEFAULT_PRUNE_INTERVAL_CONSUMES = 100;

/**
 * Cluster-wide sliding-window limiter backed by PostgreSQL. Each consume
 * records one row in quarantine_rate_limit_events inside a transaction
 * serialized per bucket with pg_advisory_xact_lock, so concurrent router
 * replicas share one quota. The bucket is locked before counting, which
 * keeps the check-and-insert atomic. Fails closed: if the database is
 * unreachable, consume rejects and the write is refused.
 */
export class PostgresSlidingWindowRateLimiter implements QuarantineRateLimiter {
  private readonly sql: Sql;
  private readonly pruneIntervalConsumes: number;
  private consumes = 0;

  constructor(
    connectionString: string,
    options: PostgresRateLimiterOptions = {},
  ) {
    this.sql = postgres(connectionString, { max: 2 });
    this.pruneIntervalConsumes =
      options.pruneIntervalConsumes ?? DEFAULT_PRUNE_INTERVAL_CONSUMES;
  }

  async initialize(): Promise<void> {
    await this.sql.unsafe(`
      CREATE TABLE IF NOT EXISTS quarantine_rate_limit_events (
        bucket TEXT NOT NULL,
        occurred_at_ms BIGINT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_quarantine_rate_limit_events_bucket
        ON quarantine_rate_limit_events (bucket, occurred_at_ms);
    `);
  }

  async consume(key: string, rule: RateLimitRule, at?: Date): Promise<void> {
    if (rule.max <= 0 || rule.windowMs <= 0) return;
    const now = at?.getTime() ?? Date.now();
    const cutoff = now - rule.windowMs;
    await this.sql.begin(async (transaction) => {
      await transaction.unsafe("SELECT pg_advisory_xact_lock(hashtext($1))", [
        key,
      ]);
      await transaction.unsafe(
        `DELETE FROM quarantine_rate_limit_events
         WHERE bucket = $1 AND occurred_at_ms < $2`,
        [key, cutoff],
      );
      const rows = await transaction.unsafe<Record<string, unknown>[]>(
        `SELECT COUNT(*) AS count FROM quarantine_rate_limit_events
         WHERE bucket = $1`,
        [key],
      );
      if (Number(rows[0]?.count ?? 0) >= rule.max) {
        throw rateLimitExceededError();
      }
      await transaction.unsafe(
        `INSERT INTO quarantine_rate_limit_events (bucket, occurred_at_ms)
         VALUES ($1, $2)`,
        [key, now],
      );
    });
    this.consumes += 1;
    if (this.consumes % this.pruneIntervalConsumes === 0) {
      await this.sql.unsafe(
        "DELETE FROM quarantine_rate_limit_events WHERE occurred_at_ms < $1",
        [cutoff],
      );
    }
  }

  async close(): Promise<void> {
    await this.sql.end();
  }
}
