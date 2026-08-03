import { describe, expect, it } from "vitest";
import { InMemorySlidingWindowRateLimiter } from "../src/quarantine/rateLimiter.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

describe("rate-limit atomicity", () => {
  it("does not charge a writer when the global bucket rejects", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter();
    const rule = { max: 1, windowMs: 60_000 };
    const at = new Date(1_000);

    await limiter.consume("global", rule, at);
    await expect(
      limiter.consumeMany(
        [
          { key: "writer:a", rule },
          { key: "global", rule },
        ],
        at,
      ),
    ).rejects.toMatchObject({ status: 429 });

    await limiter.consume("writer:a", rule, at);
  });

  it("serializes concurrent writes for the same quarantine identity", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 1,
      rateLimitGlobalMax: 100,
      requarantineOpsMax: 100,
      rateLimitWindowMs: 60_000,
    });
    const probe = {
      timestamp: "2026-08-03T00:00:00.000Z",
      kind: "security_event" as const,
      reason: "denied_endpoint" as const,
      writerId: "writer-a",
      dedupeKey: "GET:/admin",
      payload: { action: "denied_endpoint", method: "GET", path: "/admin" },
    };

    await Promise.all([store.put(probe), store.put(probe)]);

    await expect(
      store.put({
        ...probe,
        dedupeKey: "GET:/other",
        payload: {
          action: "denied_endpoint",
          method: "GET",
          path: "/other",
        },
      }),
    ).rejects.toMatchObject({ status: 429 });
  });
});
