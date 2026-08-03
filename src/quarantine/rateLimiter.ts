import postgres, { type Sql } from "postgres";
import { HttpError } from "../httpError.js";

export interface RateLimitRule {
  max: number;
  windowMs: number;
}

export interface RateLimitBucket {
  key: string;
  rule: RateLimitRule;
}

export interface QuarantineRateLimiter {
  consume(key: string, rule: RateLimitRule, at?: Date): Promise<void>;
  consumeMany(buckets: readonly RateLimitBucket[], at?: Date): Promise<void>;
  withIdentityLock<T>(
    identityKey: string,
    operation: () => Promise<T>,
  ): Promise<T>;
}

export function rateLimitExceededError(): HttpError {
  return new HttpError(
    429,
    "quarantine_rate_limited",
    "too many quarantine writes",
  );
}

export interface InMemoryRateLimiterOptions {
  sweepIntervalConsumes?: number;
}

const DEFAULT_SWEEP_INTERVAL_CONSUMES = 128;

export class InMemorySlidingWindowRateLimiter implements QuarantineRateLimiter {
  private readonly buckets = new Map<string, number[]>();
  private readonly identityLocks = new Map<string, Promise<void>>();
  private readonly sweepIntervalConsumes: number;
  private consumes = 0;
  private maxWindowMs = 0;

  constructor(options: InMemoryRateLimiterOptions = {}) {
    this.sweepIntervalConsumes =
      options.sweepIntervalConsumes ?? DEFAULT_SWEEP_INTERVAL_CONSUMES;
  }

  consume(key: string, rule: RateLimitRule, at?: Date): Promise<void> {
    return this.consumeMany([{ key, rule }], at);
  }

  consumeMany(buckets: readonly RateLimitBucket[], at?: Date): Promise<void> {
    const enabled = buckets.filter(({ rule }) => isEnabled(rule));
    if (enabled.length === 0) return Promise.resolve();

    const now = at?.getTime() ?? Date.now();
    const live = enabled.map(({ key, rule }) => ({
      key,
      rule,
      events: this.liveEvents(key, rule.windowMs, now),
    }));

    if (live.some(({ events, rule }) => events.length >= rule.max)) {
      return Promise.reject(rateLimitExceededError());
    }

    for (const { key, events } of live) {
      events.push(now);
      this.buckets.set(key, events);
    }

    this.consumes += 1;
    if (this.consumes % this.sweepIntervalConsumes === 0) this.sweep(now);
    return Promise.resolve();
  }

  async withIdentityLock<T>(
    identityKey: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    const previous = this.identityLocks.get(identityKey) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => gate);
    this.identityLocks.set(identityKey, tail);

    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this.identityLocks.get(identityKey) === tail) {
        this.identityLocks.delete(identityKey);
      }
    }
  }

  bucketCount(): number {
    return this.buckets.size;
  }

  private liveEvents(key: string, windowMs: number, now: number): number[] {
    this.maxWindowMs = Math.max(this.maxWindowMs, windowMs);
    const cutoff = now - windowMs;
    return (this.buckets.get(key) ?? []).filter(
      (occurredAt) => occurredAt > cutoff,
    );
  }

  private sweep(now: number): void {
    const staleBefore = now - this.maxWindowMs;
    for (const [key, events] of this.buckets) {
      const newest = events[events.length - 1];
      if (newest === undefined || newest <= staleBefore) {
        this.buckets.delete(key);
      }
    }
  }
}

export interface PostgresRateLimiterOptions {
  pruneIntervalConsumes?: number;
}

const DEFAULT_PRUNE_INTERVAL_CONSUMES = 100;

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

  consume(key: string, rule: RateLimitRule, at?: Date): Promise<void> {
    return this.consumeMany([{ key, rule }], at);
  }

  async consumeMany(
    buckets: readonly RateLimitBucket[],
    at?: Date,
  ): Promise<void> {
    const enabled = buckets.filter(({ rule }) => isEnabled(rule));
    if (enabled.length === 0) return;

    const unique = [
      ...new Map(enabled.map((bucket) => [bucket.key, bucket])).values(),
    ].sort((left, right) => left.key.localeCompare(right.key));

    let pruneCutoff = 0;
    await this.sql.begin(async (transaction) => {
      for (const { key } of unique) {
        await transaction.unsafe("SELECT pg_advisory_xact_lock(hashtext($1))", [
          `rate-limit:${key}`,
        ]);
      }

      const now = at?.getTime() ?? (await databaseNowMs(transaction));
      pruneCutoff = Math.min(...unique.map(({ rule }) => now - rule.windowMs));

      for (const { key, rule } of unique) {
        const cutoff = now - rule.windowMs;
        await transaction.unsafe(
          `DELETE FROM quarantine_rate_limit_events
           WHERE bucket = $1 AND occurred_at_ms <= $2`,
          [key, cutoff],
        );
        const rows = await transaction.unsafe<Record<string, unknown>[]>(
          `SELECT COUNT(*) AS count
           FROM quarantine_rate_limit_events
           WHERE bucket = $1`,
          [key],
        );
        if (Number(rows[0]?.count ?? 0) >= rule.max) {
          throw rateLimitExceededError();
        }
      }

      for (const { key } of unique) {
        const now = at?.getTime() ?? (await databaseNowMs(transaction));
        await transaction.unsafe(
          `INSERT INTO quarantine_rate_limit_events (bucket, occurred_at_ms)
           VALUES ($1, $2)`,
          [key, now],
        );
      }
    });

    this.consumes += 1;
    if (this.consumes % this.pruneIntervalConsumes === 0) {
      await this.sql.unsafe(
        "DELETE FROM quarantine_rate_limit_events WHERE occurred_at_ms <= $1",
        [pruneCutoff],
      );
    }
  }

  async withIdentityLock<T>(
    identityKey: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    return this.sql.begin(async (transaction) => {
      await transaction.unsafe("SELECT pg_advisory_xact_lock(hashtext($1))", [
        `quarantine-identity:${identityKey}`,
      ]);
      return operation();
    });
  }

  async close(): Promise<void> {
    await this.sql.end();
  }
}

function isEnabled(rule: RateLimitRule): boolean {
  return rule.max > 0 && rule.windowMs > 0;
}

async function databaseNowMs(sql: Sql): Promise<number> {
  const rows = await sql.unsafe<Record<string, unknown>[]>(
    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms",
  );
  const now = Number(rows[0]?.now_ms);
  if (!Number.isSafeInteger(now)) {
    throw new Error("PostgreSQL returned an invalid rate-limit timestamp");
  }
  return now;
}
