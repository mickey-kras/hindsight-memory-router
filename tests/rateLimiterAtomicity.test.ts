import { describe, expect, it } from "vitest";
import { InMemorySlidingWindowRateLimiter } from "../src/quarantine/rateLimiter.js";

describe("rate limiter atomicity", () => {
  it("does not charge one bucket when a paired bucket is already full", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter();
    const at = new Date(1_000);

    await limiter.consume("shared", { max: 1, windowMs: 60_000 }, at);

    await expect(
      limiter.consumeMany(
        [
          { key: "writer", rule: { max: 10, windowMs: 60_000 } },
          { key: "shared", rule: { max: 1, windowMs: 60_000 } },
        ],
        at,
      ),
    ).rejects.toMatchObject({ status: 429 });

    // The unfull bucket must not have been charged by the rejected attempt.
    await limiter.consume("writer", { max: 1, windowMs: 60_000 }, at);
    await expect(
      limiter.consume("writer", { max: 1, windowMs: 60_000 }, at),
    ).rejects.toMatchObject({ status: 429 });
  });
});
