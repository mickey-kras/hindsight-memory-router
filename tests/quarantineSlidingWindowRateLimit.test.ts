import { describe, expect, it } from "vitest";
import { InMemorySlidingWindowRateLimiter } from "../src/quarantine/rateLimiter.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

const RULE = { max: 2, windowMs: 1_000 };

describe("InMemorySlidingWindowRateLimiter", () => {
  it("does not allow bursts across a fixed window boundary", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter();

    // A fixed-window limiter would reset at t=1000 and allow this burst;
    // the sliding window still counts the consumes at t=500 and t=900.
    await limiter.consume("k", RULE, new Date(500));
    await limiter.consume("k", RULE, new Date(900));
    await expect(
      limiter.consume("k", RULE, new Date(1_400)),
    ).rejects.toMatchObject({ status: 429, code: "quarantine_rate_limited" });

    // Quota refills continuously as old events leave the window.
    await limiter.consume("k", RULE, new Date(1_501));
    await expect(
      limiter.consume("k", RULE, new Date(1_502)),
    ).rejects.toMatchObject({ status: 429 });
    await limiter.consume("k", RULE, new Date(2_502));
  });

  it("keeps buckets isolated per key", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter();
    await limiter.consume("a", RULE, new Date(0));
    await limiter.consume("a", RULE, new Date(1));
    await expect(limiter.consume("a", RULE, new Date(2))).rejects.toMatchObject(
      { status: 429 },
    );
    await limiter.consume("b", RULE, new Date(2));
  });

  it("treats non-positive max or window as disabled", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter();
    await limiter.consume("k", { max: 0, windowMs: 1_000 }, new Date(0));
    await limiter.consume("k", { max: 2, windowMs: 0 }, new Date(0));
  });

  it("evicts stale bucket keys on the periodic sweep", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter({
      sweepIntervalConsumes: 4,
    });

    // Attacker rotates through many writer IDs, creating one bucket each.
    for (let i = 0; i < 100; i += 1) {
      await limiter.consume(`attacker-${i}`, RULE, new Date(0));
    }
    expect(limiter.bucketCount()).toBe(100);

    // Once those events leave the window, the next sweep drops the stale
    // keys instead of growing the map forever.
    for (let i = 0; i < 4; i += 1) {
      await limiter.consume(`recent-${i % 2}`, RULE, new Date(10_000));
    }
    expect(limiter.bucketCount()).toBe(2);

    // Evicted buckets start with a fresh quota when the writer returns.
    await limiter.consume("attacker-0", RULE, new Date(10_001));
    await limiter.consume("attacker-0", RULE, new Date(10_002));
    await expect(
      limiter.consume("attacker-0", RULE, new Date(10_003)),
    ).rejects.toMatchObject({ status: 429 });
  });
});

describe("quarantine store rate limiting", () => {
  it("isolates per-writer buckets so one noisy writer cannot starve others", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 1,
      rateLimitGlobalMax: 100,
      distinctFamilyLimitMax: 0,
      rateLimitWindowMs: 60_000,
    });

    await store.put(writerPut("writer-a", "first"));
    await expect(
      store.put(writerPut("writer-a", "second")),
    ).rejects.toMatchObject({ status: 429, code: "quarantine_rate_limited" });

    // A different registered writer still has its own quota.
    await store.put(writerPut("writer-b", "first"));
  });

  it("enforces the global backstop across writers", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 10,
      rateLimitGlobalMax: 2,
      distinctFamilyLimitMax: 0,
      rateLimitWindowMs: 60_000,
    });

    await store.put(writerPut("writer-a", "one"));
    await store.put(writerPut("writer-b", "two"));
    await expect(
      store.put(writerPut("writer-c", "three")),
    ).rejects.toMatchObject({ status: 429, code: "quarantine_rate_limited" });
  });

  it("does not consume request quota for requarantines of a tracked identity", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 1,
      rateLimitGlobalMax: 100,
      distinctFamilyLimitMax: 0,
      requarantineOpsMax: 100,
      rateLimitWindowMs: 60_000,
    });

    const probe = {
      timestamp: "2026-08-02T00:00:00.000Z",
      kind: "security_event" as const,
      reason: "denied_endpoint" as const,
      writerId: "writer-a",
      dedupeKey: "GET:/admin",
      payload: { action: "denied_endpoint", method: "GET", path: "/admin" },
    };

    await store.put(probe); // new identity: consumes the one request slot
    await store.put(probe); // requarantine: no request quota consumed
    await store.put(probe);

    // The writer's request quota was only spent on the first, unique event.
    await expect(
      store.put(writerPut("writer-a", "next")),
    ).rejects.toMatchObject({ status: 429 });
  });

  it("bounds requarantines by the ops ceiling", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 100,
      rateLimitGlobalMax: 1_000,
      distinctFamilyLimitMax: 0,
      requarantineOpsMax: 3,
      rateLimitWindowMs: 60_000,
    });

    const probe = {
      timestamp: "2026-08-02T00:00:00.000Z",
      kind: "security_event" as const,
      reason: "denied_endpoint" as const,
      dedupeKey: "GET:/admin",
      payload: { action: "denied_endpoint", method: "GET", path: "/admin" },
    };

    await store.put(probe);
    await store.put(probe);
    await store.put(probe);
    await store.put(probe);
    await expect(store.put(probe)).rejects.toMatchObject({
      status: 429,
      code: "quarantine_rate_limited",
    });
  });

  it("does not consume request quota for items rejected by capacity", async () => {
    const { store } = memoryQuarantine({
      maxPendingItems: 1,
      rateLimitMax: 2,
      rateLimitGlobalMax: 100,
      distinctFamilyLimitMax: 0,
      rateLimitWindowMs: 60_000,
    });

    await store.put(writerPut("writer-a", "stored"));
    await expect(
      store.put(writerPut("writer-a", "overflow-1")),
    ).rejects.toMatchObject({ status: 507 });
    // Quota was not burned by the 507, so a further attempt is still
    // rejected by capacity (507), not by the rate limiter (429).
    await expect(
      store.put(writerPut("writer-a", "overflow-2")),
    ).rejects.toMatchObject({ status: 507 });
  });

  it("keeps legacy semantics: rateLimitMax 0 disables new-identity limiting", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 0,
      rateLimitGlobalMax: 1,
      distinctFamilyLimitMax: 1,
      rateLimitWindowMs: 60_000,
    });

    // A zero per-writer limit turns the whole new-identity limiter off,
    // including the global and family backstops, as before the overhaul.
    await store.put(writerPut("writer-a", "one"));
    await store.put(writerPut("writer-b", "two"));
    await store.put(writerPut("writer-c", "three"));
  });

  it("does not consume request quota for oversized items", async () => {
    const { store } = memoryQuarantine({
      maxItemBytes: 2_000,
      rateLimitMax: 1,
      rateLimitGlobalMax: 100,
      distinctFamilyLimitMax: 0,
      rateLimitWindowMs: 60_000,
    });

    await expect(
      store.put(writerPut("writer-a", "x".repeat(5_000))),
    ).rejects.toMatchObject({ status: 413 });
    // The 413 did not burn the writer's single request slot.
    await store.put(writerPut("writer-a", "ok"));
  });
});

function writerPut(writerId: string, marker: string) {
  return {
    timestamp: "2026-08-02T00:00:00.000Z",
    kind: "retain_request" as const,
    reason: "suspicious_content" as const,
    writerId,
    source: "openclaw",
    payload: { action: "retain", body: { items: [{ content: marker }] } },
  };
}
