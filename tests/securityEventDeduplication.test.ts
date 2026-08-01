import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { RouterPolicy } from "../src/policy.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

describe("denied endpoint quarantine", () => {
  it("keeps one current item per method and path while appending events", async () => {
    const quarantine = memoryQuarantine({ rateLimitMax: 0 });
    let second = 0;
    const policy = new RouterPolicy({
      registry: DEFAULT_REGISTRY,
      hindsight: new FakeHindsightGateway(),
      quarantineStore: quarantine.store,
      quarantineRepository: quarantine.repository,
      now: () => new Date(Date.UTC(2026, 7, 1, 12, 0, second++)),
    });

    await policy.denyEndpoint("GET", "/unknown");
    await policy.denyEndpoint("GET", "/unknown");
    await policy.denyEndpoint("POST", "/unknown");

    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 2,
      pending_items: 2,
      event_count: 3,
    });
    const items = await quarantine.repository.listReviewable();
    expect(items).toHaveLength(2);
    expect(new Set(items.map((item) => item.quarantine_id)).size).toBe(2);
    expect(
      quarantine.repository.events.map((event) => event.event_type),
    ).toEqual(["quarantined", "requarantined", "quarantined"]);
  });
});
