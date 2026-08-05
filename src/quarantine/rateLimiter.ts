import postgres, { type Sql, type TransactionSql } from "postgres";
import { HttpError } from "../httpError.js";

export interface RateLimitRule {
  max: number;
  windowMs: number;
}

export interface RateLimitBucket {
  key: string;
  rule: RateLimitRule;
}

export interface DistinctRateLimitIdentity {
  scope: string;
  identity: string;
  rule: RateLimitRule;
}

export interface RateLimitSession {
  consume(key: string, rule: RateLimitRule, at?: Date): Promise<void>;
  consumeMany(buckets: readonly RateLimitBucket[], at?: Date): Promise<void>;
  consumeManyDistinct(
    buckets: readonly RateLimitBucket[],
    identities: readonly DistinctRateLimitIdentity[],
    at?: Date,
  ): Promise<void>;
}

export interface QuarantineRateLimiter extends RateLimitSession {
  withIdentityLock<T>(
    identityKey: string,
    operation: (session: RateLimitSession) => Promise<T>,
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
  private readonly distinct = new Map<string, Map<string, number>>();
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
    return this.consumeManyDistinct(buckets, [], at);
  }

  consumeManyDistinct(
    buckets: readonly RateLimitBucket[],
    identities: readonly DistinctRateLimitIdentity[],
    at?: Date,
  ): Promise<void> {
    const enabledBuckets = buckets.filter(({ rule }) => isEnabled(rule));
    const enabledIdentities = normalizeDistinctIdentities(identities);
    if (enabledBuckets.length === 0 && enabledIdentities.length === 0) {
      return Promise.resolve();
    }

    const now = at?.getTime() ?? Date.now();
    const liveBuckets = enabledBuckets.map(({ key, rule }) => ({
      key,
      rule,
      events: this.liveEvents(key, rule.windowMs, now),
    }));
    if (liveBuckets.some(({ events, rule }) => events.length >= rule.max)) {
      return Promise.reject(rateLimitExceededError());
    }

    const liveDistinct = enabledIdentities.map(({ scope, identity, rule }) => {
      const identitiesForScope = this.liveDistinct(scope, rule.windowMs, now);
      return { scope, identity, rule, identitiesForScope };
    });
    const additions = new Map<string, Set<string>>();
    for (const { scope, identity, identitiesForScope } of liveDistinct) {
      if (identitiesForScope.has(identity)) continue;
      const scopeAdditions = additions.get(scope) ?? new Set<string>();
      scopeAdditions.add(identity);
      additions.set(scope, scopeAdditions);
    }
    for (const { scope, rule, identitiesForScope } of liveDistinct) {
      const added = additions.get(scope)?.size ?? 0;
      if (identitiesForScope.size + added > rule.max) {
        return Promise.reject(rateLimitExceededError());
      }
    }

    for (const { key, events } of liveBuckets) {
      events.push(now);
      this.buckets.set(key, events);
    }
    for (const { scope, identity, identitiesForScope } of liveDistinct) {
      identitiesForScope.set(identity, now);
      this.distinct.set(scope, identitiesForScope);
    }

    this.consumes += 1;
    if (this.consumes % this.sweepIntervalConsumes === 0) this.sweep(now);
    return Promise.resolve();
  }

  async withIdentityLock<T>(
    identityKey: string,
    operation: (session: RateLimitSession) => Promise<T>,
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
      return await operation(this);
    } finally {
      release();
      if (this.identityLocks.get(identityKey) === tail) {
        this.identityLocks.delete(identityKey);
      }
    }
  }

  bucketCount(): number {
    return this.buckets.size + this.distinct.size;
  }

  private liveEvents(key: string, windowMs: number, now: number): number[] {
    this.maxWindowMs = Math.max(this.maxWindowMs, windowMs);
    const cutoff = now - windowMs;
    return (this.buckets.get(key) ?? []).filter(
      (occurredAt) => occurredAt > cutoff,
    );
  }

  private liveDistinct(
    scope: string,
    windowMs: number,
    now: number,
  ): Map<string, number> {
    this.maxWindowMs = Math.max(this.maxWindowMs, windowMs);
    const cutoff = now - windowMs;
    return new Map(
      [...(this.distinct.get(scope) ?? new Map<string, number>())].filter(
        ([, occurredAt]) => occurredAt > cutoff,
      ),
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
    for (const [scope, identities] of this.distinct) {
      for (const [identity, occurredAt] of identities) {
        if (occurredAt <= staleBefore) identities.delete(identity);
      }
      if (identities.size === 0) this.distinct.delete(scope);
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
      CREATE TABLE IF NOT EXISTS quarantine_rate_limit_identities (
        scope TEXT NOT NULL,
        identity TEXT NOT NULL,
        occurred_at_ms BIGINT NOT NULL,
        PRIMARY KEY (scope, identity)
      );
      CREATE INDEX IF NOT EXISTS idx_quarantine_rate_limit_identities_scope
        ON quarantine_rate_limit_identities (scope, occurred_at_ms);
    `);
  }

  consume(key: string, rule: RateLimitRule, at?: Date): Promise<void> {
    return this.consumeMany([{ key, rule }], at);
  }

  consumeMany(
    buckets: readonly RateLimitBucket[],
    at?: Date,
  ): Promise<void> {
    return this.consumeManyDistinct(buckets, [], at);
  }

  async consumeManyDistinct(
    buckets: readonly RateLimitBucket[],
    identities: readonly DistinctRateLimitIdentity[],
    at?: Date,
  ): Promise<void> {
    const enabledBuckets = normalizeBuckets(buckets);
    const enabledIdentities = normalizeDistinctIdentities(identities);
    if (enabledBuckets.length === 0 && enabledIdentities.length === 0) return;

    const cutoff = await this.sql.begin((transaction) =>
      this.consumeInTransaction(
        transaction,
        enabledBuckets,
        enabledIdentities,
        at,
      ),
    );
    await this.recordConsume(cutoff);
  }

  async withIdentityLock<T>(
    identityKey: string,
    operation: (session: RateLimitSession) => Promise<T>,
  ): Promise<T> {
    let cutoff = 0;
    let outcome: { value: T } | undefined;

    await this.sql.begin(async (transaction) => {
      await advisoryLock(transaction, `quarantine-identity:${identityKey}`);
      const session: RateLimitSession = {
        consume: async (key, rule, at) => {
          cutoff = await this.consumeInTransaction(
            transaction,
            normalizeBuckets([{ key, rule }]),
            [],
            at,
          );
        },
        consumeMany: async (buckets, at) => {
          cutoff = await this.consumeInTransaction(
            transaction,
            normalizeBuckets(buckets),
            [],
            at,
          );
        },
        consumeManyDistinct: async (buckets, identities, at) => {
          cutoff = await this.consumeInTransaction(
            transaction,
            normalizeBuckets(buckets),
            normalizeDistinctIdentities(identities),
            at,
          );
        },
      };
      outcome = { value: await operation(session) };
    });

    if (cutoff !== 0) await this.recordConsume(cutoff);
    if (outcome === undefined) {
      throw new Error("rate-limit identity operation did not complete");
    }
    return outcome.value;
  }

  async close(): Promise<void> {
    await this.sql.end();
  }

  private async consumeInTransaction(
    sql: TransactionSql,
    buckets: readonly RateLimitBucket[],
    identities: readonly DistinctRateLimitIdentity[],
    at?: Date,
  ): Promise<number> {
    if (buckets.length === 0 && identities.length === 0) return 0;

    const lockKeys = [
      ...buckets.map(({ key }) => `rate-limit:${key}`),
      ...identities.map(({ scope }) => `rate-limit-distinct:${scope}`),
    ].sort();
    for (const key of new Set(lockKeys)) await advisoryLock(sql, key);

    const now = at?.getTime() ?? (await databaseNowMs(sql));
    for (const { key, rule } of buckets) {
      const cutoff = now - rule.windowMs;
      await sql.unsafe(
        `DELETE FROM quarantine_rate_limit_events
         WHERE bucket = $1 AND occurred_at_ms <= $2`,
        [key, cutoff],
      );
      const rows = await sql.unsafe<Record<string, unknown>[]>(
        `SELECT COUNT(*) AS count
         FROM quarantine_rate_limit_events
         WHERE bucket = $1`,
        [key],
      );
      if (Number(rows[0]?.count ?? 0) >= rule.max) {
        throw rateLimitExceededError();
      }
    }

    const byScope = new Map<string, DistinctRateLimitIdentity[]>();
    for (const identity of identities) {
      const values = byScope.get(identity.scope) ?? [];
      values.push(identity);
      byScope.set(identity.scope, values);
    }
    for (const [scope, scoped] of byScope) {
      const rule = scoped[0]?.rule;
      if (!rule) continue;
      const cutoff = now - rule.windowMs;
      await sql.unsafe(
        `DELETE FROM quarantine_rate_limit_identities
         WHERE scope = $1 AND occurred_at_ms <= $2`,
        [scope, cutoff],
      );
      const countRows = await sql.unsafe<Record<string, unknown>[]>(
        `SELECT COUNT(*) AS count
         FROM quarantine_rate_limit_identities
         WHERE scope = $1`,
        [scope],
      );
      const existingRows = await sql.unsafe<Record<string, unknown>[]>(
        `SELECT identity FROM quarantine_rate_limit_identities
         WHERE scope = $1 AND identity = ANY($2::text[])`,
        [scope, scoped.map(({ identity }) => identity)],
      );
      const existing = new Set(existingRows.map((row) => String(row.identity)));
      const additions = new Set(
        scoped
          .map(({ identity }) => identity)
          .filter((identity) => !existing.has(identity)),
      ).size;
      if (Number(countRows[0]?.count ?? 0) + additions > rule.max) {
        throw rateLimitExceededError();
      }
    }

    for (const { key } of buckets) {
      await sql.unsafe(
        `INSERT INTO quarantine_rate_limit_events (bucket, occurred_at_ms)
         VALUES ($1, $2)`,
        [key, now],
      );
    }
    for (const { scope, identity } of identities) {
      await sql.unsafe(
        `INSERT INTO quarantine_rate_limit_identities
           (scope, identity, occurred_at_ms)
         VALUES ($1, $2, $3)
         ON CONFLICT (scope, identity)
         DO UPDATE SET occurred_at_ms = EXCLUDED.occurred_at_ms`,
        [scope, identity, now],
      );
    }

    const cutoffs = [
      ...buckets.map(({ rule }) => now - rule.windowMs),
      ...identities.map(({ rule }) => now - rule.windowMs),
    ];
    return Math.min(...cutoffs);
  }

  private async recordConsume(cutoff: number): Promise<void> {
    this.consumes += 1;
    if (this.consumes % this.pruneIntervalConsumes !== 0) return;
    await this.sql.unsafe(
      "DELETE FROM quarantine_rate_limit_events WHERE occurred_at_ms <= $1",
      [cutoff],
    );
    await this.sql.unsafe(
      "DELETE FROM quarantine_rate_limit_identities WHERE occurred_at_ms <= $1",
      [cutoff],
    );
  }
}

function normalizeBuckets(
  buckets: readonly RateLimitBucket[],
): RateLimitBucket[] {
  return [
    ...new Map(
      buckets
        .filter(({ rule }) => isEnabled(rule))
        .map((bucket) => [bucket.key, bucket]),
    ).values(),
  ].sort((left, right) => left.key.localeCompare(right.key));
}

function normalizeDistinctIdentities(
  identities: readonly DistinctRateLimitIdentity[],
): DistinctRateLimitIdentity[] {
  return [
    ...new Map(
      identities
        .filter(({ rule }) => isEnabled(rule))
        .map((identity) => [
          `${identity.scope}\u0000${identity.identity}`,
          identity,
        ]),
    ).values(),
  ].sort((left, right) =>
    `${left.scope}\u0000${left.identity}`.localeCompare(
      `${right.scope}\u0000${right.identity}`,
    ),
  );
}

function isEnabled(rule: RateLimitRule): boolean {
  return rule.max > 0 && rule.windowMs > 0;
}

async function advisoryLock(sql: TransactionSql, key: string): Promise<void> {
  await sql.unsafe("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
    key,
  ]);
}

async function databaseNowMs(sql: TransactionSql): Promise<number> {
  const rows = await sql.unsafe<Record<string, unknown>[]>(
    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms",
  );
  const now = Number(rows[0]?.now_ms);
  if (!Number.isSafeInteger(now)) {
    throw new Error("PostgreSQL returned an invalid rate-limit timestamp");
  }
  return now;
}
