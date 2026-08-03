import { beforeEach, describe, expect, it, vi } from "vitest";

interface MockCall {
  statement: string;
  params: readonly unknown[];
}

const state = {
  eventCount: 0,
  calls: [] as MockCall[],
};

const transactionSql = {
  unsafe: vi.fn(async (statement: string, params: readonly unknown[] = []) => {
    state.calls.push({ statement: String(statement), params });
    if (String(statement).includes("COUNT(*)")) {
      return [{ count: state.eventCount }];
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
  state.eventCount = 0;
  state.calls = [];
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

  it("counts and records consumes inside a per-bucket locked transaction", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);

    await limiter.consume("quarantine-writes:writer:a", RULE, new Date(1_000));

    expect(rootSql.begin).toHaveBeenCalledOnce();
    const statements = state.calls.map((call) => call.statement);
    expect(statements).toEqual(
      expect.arrayContaining([
        expect.stringContaining("pg_advisory_xact_lock(hashtext($1))"),
        expect.stringContaining("DELETE FROM quarantine_rate_limit_events"),
        expect.stringContaining("COUNT(*)"),
        expect.stringContaining("INSERT INTO quarantine_rate_limit_events"),
      ]),
    );
    const insert = state.calls.find((call) =>
      call.statement.includes("INSERT INTO quarantine_rate_limit_events"),
    );
    expect(insert?.params).toEqual(["quarantine-writes:writer:a", 1_000]);
    // Sliding window: expired events are pruned relative to `at`.
    const prune = state.calls.find(
      (call) =>
        call.statement.includes("DELETE FROM quarantine_rate_limit_events") &&
        call.statement.includes("bucket = $1"),
    );
    expect(prune?.params).toEqual([
      "quarantine-writes:writer:a",
      1_000 - 60_000,
    ]);
  });

  it("rejects with 429 when the shared bucket is exhausted", async () => {
    const { PostgresSlidingWindowRateLimiter } =
      await import("../src/quarantine/rateLimiter.js");
    const limiter = new PostgresSlidingWindowRateLimiter(CONNECTION);
    state.eventCount = 30;

    await expect(
      limiter.consume("quarantine-writes", RULE, new Date(1_000)),
    ).rejects.toMatchObject({
      status: 429,
      code: "quarantine_rate_limited",
    });

    const statements = state.calls.map((call) => call.statement);
    expect(
      statements.some((statement) =>
        statement.includes("INSERT INTO quarantine_rate_limit_events"),
      ),
    ).toBe(false);
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
        "DELETE FROM quarantine_rate_limit_events WHERE occurred_at_ms < $1",
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
