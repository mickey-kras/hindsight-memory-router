import { beforeEach, describe, expect, it, vi } from "vitest";

interface MockCall {
  statement: string;
  params: readonly unknown[];
}

const state = {
  counts: new Map<string, number>(),
  calls: [] as MockCall[],
  nowMs: 123_456,
};

const transactionSql = {
  unsafe: vi.fn(async (statement: string, params: readonly unknown[] = []) => {
    const sql = String(statement);
    state.calls.push({ statement: sql, params });
    if (sql.includes("clock_timestamp")) return [{ now_ms: state.nowMs }];
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
  it("creates its events table on initialize", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.initialize();

    expect(postgres).toHaveBeenCalledWith(CONNECTION, { max: 2 });
    const schema = String(rootSql.unsafe.mock.calls[0]?.[0]);
    expect(schema).toContain(
      "CREATE TABLE IF NOT EXISTS quarantine_rate_limit_events",
    );
    expect(schema).toContain("occurred_at_ms BIGINT");
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

    expect(rootSql.begin).not.toHaveBeenCalled();
  });

  it("periodically prunes expired events for all buckets", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION, {
      pruneIntervalConsumes: 2,
    });

    await limiter.consume("k", RULE, new Date(1_000));
    await limiter.consume("k", RULE, new Date(2_000));

    const globalPrune = state.calls.find(
      (call) =>
        call.statement ===
        "DELETE FROM quarantine_rate_limit_events WHERE occurred_at_ms <= $1",
    );
    expect(globalPrune?.params).toEqual([2_000 - 60_000]);
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
