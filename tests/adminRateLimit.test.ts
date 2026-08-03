import { describe, expect, it } from "vitest";
import {
  AdminRateLimiter,
  adminRateLimitConfigFromEnv,
  classifyAdminRequest,
  DEFAULT_ADMIN_RATE_LIMIT,
} from "../src/adminRateLimit.js";
import { HttpError } from "../src/httpError.js";

function rateLimited(consume: () => void): HttpError {
  try {
    consume();
  } catch (error) {
    expect(error).toBeInstanceOf(HttpError);
    return error as HttpError;
  }
  throw new Error("expected the rate limiter to reject the request");
}

describe("AdminRateLimiter", () => {
  it("applies a sliding window per request class", () => {
    let now = 1_000;
    const limiter = new AdminRateLimiter(
      { readMax: 2, writeMax: 1, windowMs: 1_000 },
      () => now,
    );

    limiter.consume("read");
    limiter.consume("read");
    expect(rateLimited(() => limiter.consume("read"))).toMatchObject({
      status: 429,
      code: "admin_rate_limited",
    });

    // Writes have an independent budget.
    limiter.consume("write");
    expect(rateLimited(() => limiter.consume("write"))).toMatchObject({
      status: 429,
    });

    // The oldest read ages out of the sliding window.
    now = 1_500;
    expect(rateLimited(() => limiter.consume("read"))).toMatchObject({
      status: 429,
    });
    now = 2_001;
    limiter.consume("read");
  });

  it("is disabled by non-positive limits", () => {
    const limiter = new AdminRateLimiter(
      { readMax: 0, writeMax: 0, windowMs: 60_000 },
      () => 0,
    );
    for (let attempt = 0; attempt < 100; attempt += 1) {
      limiter.consume("read");
      limiter.consume("write");
    }
  });

  it("classifies GET and HEAD as reads and everything else as writes", () => {
    expect(classifyAdminRequest("GET")).toBe("read");
    expect(classifyAdminRequest("HEAD")).toBe("read");
    expect(classifyAdminRequest("POST")).toBe("write");
    expect(classifyAdminRequest("DELETE")).toBe("write");
  });
});

describe("adminRateLimitConfigFromEnv", () => {
  it("uses documented defaults when unset", () => {
    expect(adminRateLimitConfigFromEnv({})).toEqual(DEFAULT_ADMIN_RATE_LIMIT);
  });

  it("reads overrides from the environment", () => {
    expect(
      adminRateLimitConfigFromEnv({
        MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX: "10",
        MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX: "5",
        MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS: "30000",
      }),
    ).toEqual({ readMax: 10, writeMax: 5, windowMs: 30_000 });
  });

  it("rejects malformed values instead of ignoring them", () => {
    expect(() =>
      adminRateLimitConfigFromEnv({
        MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX: "fast",
      }),
    ).toThrow("MEMORY_ROUTER_ADMIN_RATE_LIMIT_READ_MAX");
    expect(() =>
      adminRateLimitConfigFromEnv({
        MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX: "-1",
      }),
    ).toThrow("MEMORY_ROUTER_ADMIN_RATE_LIMIT_WRITE_MAX");
    expect(() =>
      adminRateLimitConfigFromEnv({
        MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS: "1.5",
      }),
    ).toThrow("MEMORY_ROUTER_ADMIN_RATE_LIMIT_WINDOW_MS");
  });
});
