import { describe, expect, it } from "vitest";
import { InMemorySlidingWindowRateLimiter } from "../src/quarantine/rateLimiter.js";
import type { QuarantineStoreInput } from "../src/quarantine/quarantineStore.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

function input(content: string): QuarantineStoreInput {
  return {
    timestamp: "2026-08-01T00:00:00.000Z",
    kind: "retain_request",
    reason: "suspicious_content",
    writerId: "agent",
    source: "openclaw",
    payload: { action: "retain", body: { items: [{ content }] } },
  };
}

describe("sliding window write rate limit", () => {
  it("rejects the fourth write within the window even with gaps", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 3,
      rateLimitWindowMs: 60_000,
    });

    await store.put(input("one"));
    await store.put(input("two"));
    await store.put(input("three"));

    await expect(store.put(input("four"))).rejects.toMatchObject({
      status: 429,
      code: "quarantine_rate_limited",
    });
  });

  it("allows another write after the oldest attempt leaves the window", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter();
    const rule = { max: 1, windowMs: 1_000 };

    await limiter.consume("writes", rule, new Date(1_000));
    await expect(
      limiter.consume("writes", rule, new Date(1_999)),
    ).rejects.toMatchObject({ status: 429 });
    await limiter.consume("writes", rule, new Date(2_001));
  });

  it("rejects once the writer budget fills without waiting for a full window", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 2,
      rateLimitWindowMs: 60_000,
    });

    await store.put(input("one"));
    await store.put(input("two"));

    await expect(store.put(input("three"))).rejects.toMatchObject({
      status: 429,
      code: "quarantine_rate_limited",
    });
  });

  it("drops buckets that are fully outside the window", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter({
      sweepIntervalConsumes: 2,
    });
    const rule = { max: 10, windowMs: 1_000 };

    await limiter.consume("stale", rule, new Date(1_000));
    await limiter.consume("fresh", rule, new Date(5_000));

    expect(limiter.bucketCount()).toBe(1);
  });

  it("keeps buckets with any event inside the window", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter({
      sweepIntervalConsumes: 2,
    });
    const rule = { max: 10, windowMs: 1_000 };

    await limiter.consume("stale", rule, new Date(1_000));
    await limiter.consume("fresh", rule, new Date(1_500));

    expect(limiter.bucketCount()).toBe(2);
  });

  it("rejects when the global budget fills across writers", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 10,
      rateLimitGlobalMax: 1,
      rateLimitWindowMs: 60_000,
    });

    await store.put(input("one"));
    await expect(
      store.put({ ...input("two"), writerId: "agent-b" }),
    ).rejects.toMatchObject({ status: 429 });
  });

  it("serializes concurrent writes for the same identity", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter();
    const order: string[] = [];

    await Promise.all([
      limiter.withIdentityLock("q_1", async () => {
        order.push("a-start");
        await new Promise((resolve) => setTimeout(resolve, 10));
        order.push("a-end");
      }),
      limiter.withIdentityLock("q_1", async () => {
        order.push("b-start");
        order.push("b-end");
      }),
    ]);

    expect(order).toEqual(["a-start", "a-end", "b-start", "b-end"]);
    expect(limiter.bucketCount()).toBe(0);
  });
});
