import { describe, expect, it } from "vitest";
import { decryptQuarantineEnvelope } from "../src/quarantine/envelopeCrypto.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

describe("EncryptedDatabaseQuarantineStore", () => {
  it("stores only an encrypted envelope and metadata", async () => {
    const { store, repository, keys } = memoryQuarantine();
    const raw = "VERY_SECRET_UNTRUSTED_PAYLOAD";
    const result = await store.put({
      timestamp: "2026-06-24T00:00:00.000Z",
      kind: "retain_request",
      reason: "suspicious_content",
      writerId: "ops",
      source: "test",
      payload: { content: raw },
    });

    const stored = await repository.get(result.quarantine_id);
    expect(stored).toMatchObject({
      sha256: result.sha256,
      status: "pending",
      kind: "retain_request",
    });
    expect(JSON.stringify(stored)).not.toContain(raw);
    expect(
      decryptQuarantineEnvelope(stored?.encrypted, keys.privateKey),
    ).toMatchObject({ payload: { content: raw } });
  });

  it("deduplicates recalled memory review state by bank and memory id", async () => {
    const { store, repository } = memoryQuarantine();
    const first = await store.put({
      timestamp: "2026-06-24T00:00:00.000Z",
      kind: "recalled_memory",
      reason: "recalled_suspicious_memory",
      sourceBank: "ops",
      sourceMemoryId: "memory-1",
      sourceContentSha256: "a".repeat(64),
      payload: { result: { id: "memory-1", text: "first" } },
    });
    await repository.markMemoryReviewed(
      first.quarantine_id,
      "reviewed_allowed",
      "2026-06-24T00:01:00.000Z",
    );

    await store.put({
      timestamp: "2026-06-24T00:02:00.000Z",
      kind: "recalled_memory",
      reason: "recalled_suspicious_memory",
      sourceBank: "ops",
      sourceMemoryId: "memory-1",
      sourceContentSha256: "b".repeat(64),
      payload: { result: { id: "memory-1", text: "changed" } },
    });

    expect(repository.items).toHaveLength?.(undefined);
    expect(repository.items.size).toBe(1);
    expect(await repository.get(first.quarantine_id)).toMatchObject({
      status: "pending",
      source_content_sha256: "b".repeat(64),
    });
    expect(repository.events.map((event) => event.event_type)).toEqual([
      "quarantined",
      "reviewed_allowed",
      "requarantined",
    ]);
  });

  it("enforces item size, persistent capacity, and write rate limits", async () => {
    const tooLarge = memoryQuarantine({ maxItemBytes: 100 });
    await expect(
      tooLarge.store.put({
        timestamp: "2026-06-24T00:00:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        payload: { content: "x".repeat(500) },
      }),
    ).rejects.toMatchObject({ status: 413 });

    const capacity = memoryQuarantine({ maxPendingItems: 1 });
    await capacity.store.put({
      timestamp: "2026-06-24T00:00:00.000Z",
      kind: "retain_request",
      reason: "unknown_writer",
      payload: { content: "first" },
    });
    await expect(
      capacity.store.put({
        timestamp: "2026-06-24T00:00:01.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        payload: { content: "second" },
      }),
    ).rejects.toMatchObject({ status: 507 });

    const limited = memoryQuarantine({ rateLimitMax: 1 });
    await limited.store.put({
      timestamp: "2026-06-24T00:00:00.000Z",
      kind: "retain_request",
      reason: "unknown_writer",
      writerId: "same",
      source: "same",
      payload: { content: "first" },
    });
    await expect(
      limited.store.put({
        timestamp: "2026-06-24T00:00:01.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        writerId: "same",
        source: "same",
        payload: { content: "second" },
      }),
    ).rejects.toMatchObject({ status: 429 });
  });
});
