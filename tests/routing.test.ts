import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { RouterPolicy } from "../src/policy.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import type { WriterRegistry } from "../src/types.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

const DEV_REGISTRY: WriterRegistry = {
  writers: {
    dev: {
      role: "dev",
      source: "application",
      write_bank: "dev",
      read_banks: ["dev", "core"],
    },
  },
  defaults: {
    unknown_writer_action: "review_queue",
    suspicious_content_action: "review_queue",
  },
};

function makePolicy(registry: WriterRegistry = DEFAULT_REGISTRY) {
  const hindsight = new FakeHindsightGateway();
  const quarantine = memoryQuarantine();
  const policy = new RouterPolicy({
    registry,
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
  it("lets default main recall only main", async () => {
    const { policy, hindsight } = makePolicy();
    const result = await policy.recall("main", {
      query: "What changed on the system?",
    });
    expect(result.results.length).toBeGreaterThan(0);
    expect(hindsight.recalled.map((item) => item.bankId)).toEqual(["main"]);
  });

  it("honors a custom dev and core read policy", async () => {
    const { policy, hindsight } = makePolicy(DEV_REGISTRY);
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
