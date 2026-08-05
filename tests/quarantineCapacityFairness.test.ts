import { describe, expect, it } from "vitest";
import type { QuarantineInput } from "../src/quarantine/quarantineStore.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

function retain(
  writerId: string,
  reason: "unknown_writer" | "suspicious_content",
  suffix: string,
): QuarantineInput {
  return {
    timestamp: new Date().toISOString(),
    kind: "retain_request",
    reason,
    writerId,
    source: "test",
    dedupeKey: `${reason}:${writerId}:${suffix}`,
    payload: { action: "retain", writer_id: writerId, suffix },
  };
}

function fairnessLimits() {
  return {
    maxPendingItems: 10,
    maxPendingItemsPerWriter: 2,
    maxEncryptedBytes: 10_000_000,
    rateLimitMax: 0,
  };
}

describe("quarantine writer capacity fairness", () => {
  it("isolates registered writers", async () => {
    const quarantine = memoryQuarantine(fairnessLimits());

    await quarantine.store.put(retain("writer-a", "suspicious_content", "1"));
    await quarantine.store.put(retain("writer-a", "suspicious_content", "2"));
    await expect(
      quarantine.store.put(retain("writer-a", "suspicious_content", "3")),
    ).rejects.toMatchObject({
      status: 507,
      code: "quarantine_writer_capacity_exceeded",
    });

    await expect(
      quarantine.store.put(retain("writer-b", "suspicious_content", "1")),
    ).resolves.toHaveProperty("quarantine_id");
  });

  it("shares one quota across attacker-controlled unknown writer ids", async () => {
    const quarantine = memoryQuarantine(fairnessLimits());

    await quarantine.store.put(retain("unknown-a", "unknown_writer", "1"));
    await quarantine.store.put(retain("unknown-b", "unknown_writer", "2"));
    await expect(
      quarantine.store.put(retain("unknown-c", "unknown_writer", "3")),
    ).rejects.toMatchObject({
      status: 507,
      code: "quarantine_writer_capacity_exceeded",
    });

    await expect(
      quarantine.store.put(retain("writer-a", "suspicious_content", "1")),
    ).resolves.toHaveProperty("quarantine_id");
  });

  it("allows deduplicated refreshes at the writer limit", async () => {
    const quarantine = memoryQuarantine(fairnessLimits());
    const first = retain("writer-a", "suspicious_content", "same");

    const stored = await quarantine.store.put(first);
    await quarantine.store.put(retain("writer-a", "suspicious_content", "2"));
    await expect(quarantine.store.put(first)).resolves.toMatchObject(stored);
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      pending_items: 2,
    });
  });

  it("does not count expired items", async () => {
    const quarantine = memoryQuarantine({
      ...fairnessLimits(),
      maxPendingItemsPerWriter: 1,
      itemTtlDays: 1,
    });
    await quarantine.store.put({
      ...retain("writer-a", "suspicious_content", "expired"),
      timestamp: "2026-01-01T00:00:00.000Z",
    });

    await expect(
      quarantine.store.put(retain("writer-a", "suspicious_content", "fresh")),
    ).resolves.toHaveProperty("quarantine_id");
  });

  it("enforces the quota atomically for concurrent writes", async () => {
    const quarantine = memoryQuarantine(fairnessLimits());
    const results = await Promise.allSettled([
      quarantine.store.put(retain("writer-a", "suspicious_content", "1")),
      quarantine.store.put(retain("writer-a", "suspicious_content", "2")),
      quarantine.store.put(retain("writer-a", "suspicious_content", "3")),
    ]);

    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(2);
    expect(
      results.filter((result) => result.status === "rejected"),
    ).toHaveLength(1);
  });
});
