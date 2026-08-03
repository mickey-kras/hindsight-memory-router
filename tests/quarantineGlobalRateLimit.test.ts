import { describe, expect, it } from "vitest";
import type { QuarantineStoreInput } from "../src/quarantine/quarantineStore.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

describe("quarantine write rate limit", () => {
  it("auth failure audits cannot starve the security quarantine budget", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 2,
      rateLimitWindowMs: 60_000,
    });
    const authAudit: QuarantineStoreInput = {
      timestamp: "2026-08-02T00:00:00.000Z",
      kind: "security_event",
      reason: "auth_failed",
      source: "http",
      dedupeKey: "auth_failed:router",
      payload: { action: "auth_failed", route_group: "router" },
    };
    const retain: QuarantineStoreInput = {
      timestamp: "2026-08-02T00:00:01.000Z",
      kind: "retain_request",
      reason: "suspicious_content",
      writerId: "writer-a",
      source: "openclaw",
      payload: { action: "retain", body: { items: [{ content: "x" }] } },
    };

    const firstAudit = await store.put(authAudit);
    const secondAudit = await store.put(authAudit);
    expect(secondAudit.quarantine_id).toBe(firstAudit.quarantine_id);
    await expect(store.put(authAudit)).rejects.toMatchObject({ status: 429 });

    // The shared budget is untouched by auth audits, and vice versa.
    await store.put(retain);
    await store.put(retain);
    await expect(store.put(retain)).rejects.toMatchObject({ status: 429 });
  });

  it("cannot be bypassed by changing writer IDs", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 2,
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
