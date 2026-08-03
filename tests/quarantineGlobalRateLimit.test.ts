import { describe, expect, it } from "vitest";
import { memoryQuarantine } from "./quarantineTestUtils.js";

describe("quarantine write rate limit", () => {
  it("global backstop cannot be bypassed by changing writer IDs", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 10,
      rateLimitGlobalMax: 2,
      rateLimitWindowMs: 60_000,
    });

    await store.put({
      timestamp: "2026-08-02T00:00:00.000Z",
      kind: "retain_request",
      reason: "unknown_writer",
      writerId: "writer-a",
      source: "openclaw",
      payload: { action: "retain", body: { items: [{ content: "a" }] } },
    });
    await store.put({
      timestamp: "2026-08-02T00:00:01.000Z",
      kind: "retain_request",
      reason: "unknown_writer",
      writerId: "writer-b",
      source: "openclaw",
      payload: { action: "retain", body: { items: [{ content: "b" }] } },
    });

    await expect(
      store.put({
        timestamp: "2026-08-02T00:00:02.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        writerId: "writer-c",
        source: "openclaw",
        payload: { action: "retain", body: { items: [{ content: "c" }] } },
      }),
    ).rejects.toMatchObject({
      status: 429,
      code: "quarantine_rate_limited",
    });
  });
});
