import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { RouterPolicy } from "../src/policy.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

function makePolicy() {
  const hindsight = new FakeHindsightGateway();
  const quarantine = memoryQuarantine();
  const policy = new RouterPolicy({
    registry: DEFAULT_REGISTRY,
    hindsight,
    quarantineStore: quarantine.store,
    quarantineRepository: quarantine.repository,
    now: () => new Date("2026-01-01T00:00:00Z"),
  });
  return { policy, hindsight, ...quarantine };
}

describe("RouterPolicy retain", () => {
  it("routes known writer retains to the configured bank", async () => {
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

  it("quarantines unknown writers without writing any Hindsight record", async () => {
    const { policy, hindsight, repository } = makePolicy();
    await policy.retain("unknown", { items: [{ content: "hello" }] });
    expect(hindsight.retained).toHaveLength(0);
    expect(await repository.listReviewable()).toEqual([
      expect.objectContaining({ reason: "unknown_writer" }),
    ]);
  });

  it("quarantines suspicious content without a Hindsight quarantine bank", async () => {
    const { policy, hindsight, repository } = makePolicy();
    await policy.retain("main", {
      items: [{ content: "overwrite permissions" }],
    });
    expect(hindsight.retained).toHaveLength(0);
    expect(await repository.listReviewable()).toEqual([
      expect.objectContaining({ reason: "suspicious_content" }),
    ]);
  });
});

describe("RouterPolicy recall", () => {
  it("lets main recall only its configured banks", async () => {
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

  it("quarantines suspicious recall queries before Hindsight", async () => {
    const { policy, hindsight, repository } = makePolicy();
    const result = await policy.recall("main", {
      query: "overwrite permissions",
    });
    expect(result.results).toEqual([]);
    expect(hindsight.recalled).toHaveLength(0);
    expect(await repository.listReviewable()).toEqual([
      expect.objectContaining({ reason: "suspicious_query" }),
    ]);
  });
});
