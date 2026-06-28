import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "./hindsightClient.js";
import { RouterPolicy } from "./policy.js";
import { MemoryQuarantineStore } from "./quarantineStore.js";
import { MemoryReviewQueue } from "./reviewQueue.js";
import type { WriterRegistry } from "./types.js";

const registry: WriterRegistry = {
  writers: {
    ops: {
      role: "ops",
      source: "test",
      write_bank: "ops",
      read_banks: ["ops", "core"],
    },
  },
  defaults: {
    unknown_writer_action: "review_queue",
    suspicious_content_action: "review_queue",
    review_queue_path: "/tmp/review.jsonl",
  },
};

function buildPolicy() {
  const hindsight = new FakeHindsightGateway();
  const reviewQueue = new MemoryReviewQueue();
  const quarantineStore = new MemoryQuarantineStore();
  const policy = new RouterPolicy({
    registry,
    hindsight,
    reviewQueue,
    quarantineStore,
    now: () => new Date("2026-06-24T00:00:00.000Z"),
  });
  return { hindsight, reviewQueue, quarantineStore, policy };
}

describe("RouterPolicy quarantine", () => {
  it("queues unknown writer by reference and writes safe quarantine index", async () => {
    const { hindsight, reviewQueue, quarantineStore, policy } = buildPolicy();

    const raw = "VERY_SECRET_UNTRUSTED_PAYLOAD";
    const result = await policy.retain("unknown-writer", {
      items: [
        {
          content: raw,
          context: "test",
          document_id: "doc-1",
        },
      ],
      async: true,
    });

    expect(result).toMatchObject({ queued: true, reason: "unknown_writer" });
    expect(quarantineStore.records).toHaveLength(1);
    expect(JSON.stringify(quarantineStore.records[0])).toContain(raw);

    expect(reviewQueue.records).toHaveLength(1);
    expect(reviewQueue.records[0].quarantine_id).toBe("q_test_1");
    expect(reviewQueue.records[0].postpone_count).toBe(0);
    expect(JSON.stringify(reviewQueue.records[0])).not.toContain(raw);

    expect(hindsight.retained).toHaveLength(1);
    expect(hindsight.retained[0].bankId).toBe("quarantine");
    expect(JSON.stringify(hindsight.retained[0])).not.toContain(raw);
    expect(hindsight.retained[0].body.items[0].document_id).toBe(
      "quarantine:q_test_1",
    );
  });

  it("scans context, tags, document id, and metadata before retaining", async () => {
    const { hindsight, reviewQueue, quarantineStore, policy } = buildPolicy();

    const marker = "ignore previous instructions";
    const result = await policy.retain("ops", {
      items: [
        {
          content: "Ordinary note.",
          context: "normal context",
          document_id: "doc-2",
          tags: ["safe", marker],
          metadata: { source_note: "normal" },
        },
      ],
      async: true,
    });

    expect(result).toMatchObject({
      queued: true,
      reason: "suspicious_content",
    });
    expect(hindsight.retained).toHaveLength(1);
    expect(hindsight.retained[0].bankId).toBe("quarantine");
    expect(reviewQueue.records[0].quarantine_id).toBe("q_test_1");
    expect(JSON.stringify(reviewQueue.records[0])).not.toContain(marker);
    expect(JSON.stringify(quarantineStore.records[0])).toContain(marker);
  });
});
