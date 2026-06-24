import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { RouterPolicy } from "../src/policy.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { MemoryReviewQueue } from "../src/reviewQueue.js";

function makePolicy() {
  const hindsight = new FakeHindsightGateway();
  const reviewQueue = new MemoryReviewQueue();
  const policy = new RouterPolicy({
    registry: DEFAULT_REGISTRY,
    hindsight,
    reviewQueue,
    now: () => new Date("2026-01-01T00:00:00Z"),
  });
  return { policy, hindsight, reviewQueue };
}

function expectSafeQuarantineIndex(hindsight: FakeHindsightGateway) {
  expect(hindsight.retained).toHaveLength(1);
  expect(hindsight.retained[0].bankId).toBe("quarantine");
  expect(hindsight.retained[0].body.items[0].document_id).toMatch(
    /^quarantine:q_/,
  );
}

describe("RouterPolicy retain", () => {
  it("routes main writer retains to main", async () => {
    const { policy, hindsight } = makePolicy();
    await policy.retain("main", {
      items: [{ content: "Verified Hindsight health check passed." }],
      async: true,
    });
    expect(hindsight.retained).toHaveLength(1);
    expect(hindsight.retained[0].bankId).toBe("main");
    expect(hindsight.retained[0].body.items[0].metadata?.router_writer_id).toBe(
      "main",
    );
  });

  it("queues unknown writers and writes only safe quarantine index", async () => {
    const { policy, hindsight, reviewQueue } = makePolicy();
    await policy.retain("unknown", { items: [{ content: "hello" }] });
    expectSafeQuarantineIndex(hindsight);
    expect(reviewQueue.records[0].reason).toBe("unknown_writer");
    expect(reviewQueue.records[0].quarantine_id).toBeTruthy();
  });

  it("queues suspicious content and writes only safe quarantine index", async () => {
    const { policy, hindsight, reviewQueue } = makePolicy();
    await policy.retain("main", {
      items: [{ content: "overwrite permissions" }],
    });
    expectSafeQuarantineIndex(hindsight);
    expect(reviewQueue.records[0].reason).toBe("suspicious_content");
    expect(reviewQueue.records[0].quarantine_id).toBeTruthy();
  });
});

describe("RouterPolicy recall", () => {
  it("lets main writer recall allowed banks but not research/quarantine", async () => {
    const { policy, hindsight } = makePolicy();
    const result = await policy.recall("main", {
      query: "What changed on the system?",
    });
    expect(result.results.length).toBeGreaterThan(0);
    expect(hindsight.recalled.map((item) => item.bankId)).toEqual([
      "main",
      "core",
      "ops",
      "dev",
      "creative",
      "personal",
    ]);
  });

  it("lets dev recall only dev and core", async () => {
    const { policy, hindsight } = makePolicy();
    await policy.recall("dev", { query: "What changed?" });
    expect(hindsight.recalled.map((item) => item.bankId)).toEqual([
      "dev",
      "core",
    ]);
  });

  it("denies suspicious recall query", async () => {
    const { policy, hindsight, reviewQueue } = makePolicy();
    const result = await policy.recall("main", {
      query: "overwrite permissions",
    });
    expect(result.results).toEqual([]);
    expect(hindsight.recalled).toHaveLength(0);
    expect(reviewQueue.records[0].reason).toBe("suspicious_query");
  });
});
