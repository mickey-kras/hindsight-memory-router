import { describe, expect, it } from "vitest";
import type { QuarantineStoreInput } from "../src/quarantine/quarantineStore.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

describe("quarantine write rate limit", () => {
  it("auth failure audits cannot starve security quarantine budgets", async () => {
    const { store } = memoryQuarantine({
      rateLimitMax: 2,
      rateLimitGlobalMax: 3,
      requarantineOpsMax: 2,
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
    const probe: QuarantineStoreInput = {
      timestamp: "2026-08-02T00:00:01.000Z",
      kind: "security_event",
      reason: "denied_endpoint",
      source: "http",
      dedupeKey: "GET:/unknown",
      payload: { action: "denied_endpoint", method: "GET", path: "/unknown" },
    };

    // A sustained bad-token flood exhausts only the dedicated audit buckets.
    const firstAudit = await store.put(authAudit);
    const secondAudit = await store.put(authAudit);
    expect(secondAudit.quarantine_id).toBe(firstAudit.quarantine_id);
    await store.put(authAudit);
    await expect(store.put(authAudit)).rejects.toMatchObject({ status: 429 });

    // Legitimate refreshes keep the full requarantine ops ceiling.
    await store.put(probe);
    await store.put(probe);

    // The shared new-identity budget is untouched by the flood.
    await store.put(retain("a"));
    await store.put(retain("b"));
    await expect(store.put(retain("c"))).rejects.toMatchObject({
      status: 429,
    });
  });

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

function retain(marker: string): QuarantineStoreInput {
  return {
    timestamp: "2026-08-02T00:00:02.000Z",
    kind: "retain_request",
    reason: "suspicious_content",
    writerId: "writer-a",
    source: "openclaw",
    payload: { action: "retain", body: { items: [{ content: marker }] } },
  };
}
