import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  JsonlReviewQueue,
  MemoryReviewQueue,
  readReviewQueue,
  writeReviewQueue,
} from "../src/reviewQueue.js";
import type { ReviewRecord } from "../src/types.js";

function record(id: string): ReviewRecord {
  return {
    timestamp: "2026-07-31T00:00:00.000Z",
    reason: "unknown_writer",
    quarantine_id: id,
    sha256: "0".repeat(64),
    preview: "preview",
    decision: "pending",
  };
}

describe("review queues", () => {
  it("treats a missing JSONL file as an empty queue", () => {
    expect(
      readReviewQueue("/tmp/definitely-missing-review-queue.jsonl"),
    ).toEqual([]);
  });

  it("enqueues, lists, replaces, and empties JSONL records", () => {
    const directory = mkdtempSync(join(tmpdir(), "review-queue-"));
    const path = join(directory, "nested", "review.jsonl");
    const queue = new JsonlReviewQueue(path);
    try {
      queue.enqueue(record("q_one_0123456789abcdef"));
      queue.enqueue(record("q_two_0123456789abcdef"));
      expect(queue.list()).toHaveLength(2);

      queue.replace([record("q_three_0123456789abcdef")]);
      expect(queue.list().map((item) => item.quarantine_id)).toEqual([
        "q_three_0123456789abcdef",
      ]);
      expect(readFileSync(path, "utf8")).toMatch(/\n$/);

      queue.replace([]);
      expect(readFileSync(path, "utf8")).toBe("");
      expect(queue.list()).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rethrows malformed queue data", () => {
    const directory = mkdtempSync(join(tmpdir(), "review-queue-invalid-"));
    const path = join(directory, "review.jsonl");
    try {
      writeFileSync(path, "not-json\n");
      expect(() => readReviewQueue(path)).toThrow();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("writes records directly and stores records in memory", () => {
    const directory = mkdtempSync(join(tmpdir(), "review-queue-write-"));
    const path = join(directory, "nested", "review.jsonl");
    try {
      writeReviewQueue(path, [record("q_disk_0123456789abcdef")]);
      expect(readReviewQueue(path)).toHaveLength(1);

      const memory = new MemoryReviewQueue();
      memory.enqueue(record("q_memory_0123456789abcdef"));
      expect(memory.records[0]?.quarantine_id).toBe(
        "q_memory_0123456789abcdef",
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
