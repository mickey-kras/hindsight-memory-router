import { beforeEach, describe, expect, it, vi } from "vitest";

interface MockCall {
  statement: string;
  params: readonly unknown[];
}

const state = {
  counts: new Map<string, number>(),
  distinctCounts: new Map<string, number>(),
  distinctExisting: new Map<string, Set<string>>(),
  calls: [] as MockCall[],
  nowMs: 123_456,
};

const transactionSql = {
  unsafe: vi.fn(async (statement: string, params: readonly unknown[] = []) => {
    const sql = String(statement);
    state.calls.push({ statement: sql, params });
    if (sql.includes("clock_timestamp")) return [{ now_ms: state.nowMs }];
    if (
      sql.includes("SELECT COUNT(*) AS count") &&
      sql.includes("quarantine_rate_limit_identities")
    ) {
      return [{ count: state.distinctCounts.get(String(params[0])) ?? 0 }];
    }
    if (sql.includes("SELECT identity FROM quarantine_rate_limit_identities")) {
      const scope = String(params[0]);
      const requested = (params[1] as readonly string[]) ?? [];
      const existing = state.distinctExisting.get(scope) ?? new Set<string>();
      return requested
        .filter((identity) => existing.has(identity))
        .map((identity) => ({ identity }));
    }
    if (sql.includes("COUNT(*)")) {
      return [{ count: state.counts.get(String(params[0])) ?? 0 }];
    }
    return [];
  }),
};
const rootSql = {
  unsafe: vi.fn(async (statement: string, params: readonly unknown[] = []) => {
    state.calls.push({ statement: String(statement), params });
    return [];
  }),
  begin: vi.fn(async (operation: (sql: typeof transactionSql) => unknown) =>
    operation(transactionSql),
  ),
  end: vi.fn(async () => undefined),
};
const postgres = vi.fn(() => rootSql);

vi.mock("postgres", () => ({ default: postgres }));

beforeEach(() => {
  state.counts.clear();
  state.distinctCounts.clear();
  state.distinctExisting.clear();
  state.calls = [];
  state.nowMs = 123_456;
  postgres.mockClear();
  rootSql.unsafe.mockClear();
  rootSql.begin.mockClear();
  rootSql.end.mockClear();
  transactionSql.unsafe.mockClear();
});

const CONNECTION = "postgresql://router:test@database/router";
const RULE = { max: 30, windowMs: 60_000 };

describe("PostgresSlidingWindowRateLimiter", () => {
  it("creates events and distinct-identity tables on initialize", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.initialize();

    expect(postgres).toHaveBeenCalledWith(CONNECTION, { max: 2 });
    const schema = String(rootSql.unsafe.mock.calls[0]?.[0]);
    expect(schema).toContain(
      "CREATE TABLE IF NOT EXISTS quarantine_rate_limit_events",
    );
    expect(schema).toContain(
      "CREATE TABLE IF NOT EXISTS quarantine_rate_limit_identities",
    );
    expect(schema).toContain("PRIMARY KEY (scope, identity)");
  });

  it("checks and records one bucket inside a locked transaction", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.consume("writer:a", RULE, new Date(1_000));

    expect(rootSql.begin).toHaveBeenCalledOnce();
    expect(statements()).toEqual(
      expect.arrayContaining([
        expect.stringContaining("pg_advisory_xact_lock"),
        expect.stringContaining("DELETE FROM quarantine_rate_limit_events"),
        expect.stringContaining("COUNT(*)"),
        expect.stringContaining("INSERT INTO quarantine_rate_limit_events"),
      ]),
    );
    expect(
      findCall("INSERT INTO quarantine_rate_limit_events")?.params,
    ).toEqual(["writer:a", 1_000]);
    expect(findCall("bucket = $1 AND occurred_at_ms <= $2")?.params).toEqual([
      "writer:a",
      1_000 - 60_000,
    ]);
  });

  it("charges multiple buckets atomically", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);
    state.counts.set("global", 1);

    await expect(
      limiter.consumeMany(
        [
          { key: "writer:a", rule: { max: 1, windowMs: 60_000 } },
          { key: "global", rule: { max: 1, windowMs: 60_000 } },
        ],
        new Date(1_000),
      ),
    ).rejects.toMatchObject({ status: 429, code: "quarantine_rate_limited" });

    expect(
      statements().some((statement) =>
        statement.includes("INSERT INTO quarantine_rate_limit_events"),
      ),
    ).toBe(false);
  });

  it("registers and refreshes distinct identities in the same transaction", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.consumeManyDistinct(
      [{ key: "writer:a", rule: RULE }],
      [
        {
          scope: "family:a",
          identity: "f1",
          rule: { max: 2, windowMs: 60_000 },
        },
      ],
      new Date(1_000),
    );

    expect(rootSql.begin).toHaveBeenCalledOnce();
    expect(
      state.calls
        .filter((call) => call.statement.includes("pg_advisory_xact_lock"))
        .map((call) => call.params[0]),
    ).toEqual(["rate-limit-distinct:family:a", "rate-limit:writer:a"]);
    expect(
      findCall("DELETE FROM quarantine_rate_limit_identities")?.params,
    ).toEqual(["family:a", 1_000 - 60_000]);
    expect(findCall("identity = ANY($2::text[])")?.params).toEqual([
      "family:a",
      ["f1"],
    ]);
    const upsert = findCall("ON CONFLICT (scope, identity)");
    expect(upsert?.params).toEqual(["family:a", "f1", 1_000]);
    expect(upsert?.statement).toContain(
      "DO UPDATE SET occurred_at_ms = EXCLUDED.occurred_at_ms",
    );
  });

  it("rejects a new distinct identity without recording any quota", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);
    state.distinctCounts.set("family:a", 2);

    await expect(
      limiter.consumeManyDistinct(
        [{ key: "writer:a", rule: RULE }],
        [
          {
            scope: "family:a",
            identity: "f3",
            rule: { max: 2, windowMs: 60_000 },
          },
        ],
        new Date(1_000),
      ),
    ).rejects.toMatchObject({ status: 429, code: "quarantine_rate_limited" });

    expect(
      findCall("INSERT INTO quarantine_rate_limit_events"),
    ).toBeUndefined();
    expect(findCall("ON CONFLICT (scope, identity)")).toBeUndefined();
  });

  it("allows an existing distinct identity at the cap and refreshes it", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);
    state.distinctCounts.set("family:a", 2);
    state.distinctExisting.set("family:a", new Set(["f2"]));

    await limiter.consumeManyDistinct(
      [],
      [
        {
          scope: "family:a",
          identity: "f2",
          rule: { max: 2, windowMs: 60_000 },
        },
      ],
      new Date(2_000),
    );

    expect(findCall("ON CONFLICT (scope, identity)")?.params).toEqual([
      "family:a",
      "f2",
      2_000,
    ]);
  });

  it("uses PostgreSQL time when no test clock is supplied", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.consume("writer:a", RULE);

    expect(findCall("clock_timestamp")).toBeDefined();
    expect(
      findCall("INSERT INTO quarantine_rate_limit_events")?.params,
    ).toEqual(["writer:a", state.nowMs]);
  });

  it("holds the identity lock while the supplied session consumes quota", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.withIdentityLock("q_1", async (session) => {
      await session.consume("writer:a", RULE, new Date(1_000));
    });

    expect(rootSql.begin).toHaveBeenCalledOnce();
    const locks = state.calls.filter((call) =>
      call.statement.includes("pg_advisory_xact_lock"),
    );
    expect(locks.map((call) => call.params[0])).toEqual([
      "quarantine-identity:q_1",
      "rate-limit:writer:a",
    ]);
  });

  it("does nothing for disabled rules", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.consume("k", { max: 0, windowMs: 60_000 }, new Date(0));
    await limiter.consume("k", { max: 30, windowMs: 0 }, new Date(0));
    await limiter.consumeManyDistinct(
      [],
      [{ scope: "s", identity: "i", rule: { max: 0, windowMs: 60_000 } }],
      new Date(0),
    );

    expect(rootSql.begin).not.toHaveBeenCalled();
  });

  it("periodically prunes expired events and identities", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION, {
      pruneIntervalConsumes: 2,
    });

    await limiter.consume("k", RULE, new Date(1_000));
    await limiter.consumeManyDistinct(
      [],
      [{ scope: "family:a", identity: "f1", rule: RULE }],
      new Date(2_000),
    );

    const eventPrune = state.calls.find(
      (call) =>
        call.statement ===
        "DELETE FROM quarantine_rate_limit_events WHERE occurred_at_ms <= $1",
    );
    const identityPrune = state.calls.find(
      (call) =>
        call.statement ===
        "DELETE FROM quarantine_rate_limit_identities WHERE occurred_at_ms <= $1",
    );
    expect(eventPrune?.params).toEqual([2_000 - 60_000]);
    expect(identityPrune?.params).toEqual([2_000 - 60_000]);
  });

  it("closes the underlying client", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.close();

    expect(rootSql.end).toHaveBeenCalledOnce();
  });
});

function statements(): string[] {
  return state.calls.map((call) => call.statement);
}

function findCall(fragment: string): MockCall | undefined {
  return state.calls.find((call) => call.statement.includes(fragment));
}
