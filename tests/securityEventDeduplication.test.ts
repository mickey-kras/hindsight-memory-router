import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { RouterPolicy } from "../src/policy.js";
import { MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER } from "../src/quarantine/dedupeKey.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

function setup() {
  const quarantine = memoryQuarantine({ rateLimitMax: 0 });
  let second = 0;
  const policy = new RouterPolicy({
    registry: DEFAULT_REGISTRY,
    hindsight: new FakeHindsightGateway(),
    quarantineStore: quarantine.store,
    quarantineRepository: quarantine.repository,
    now: () => new Date(Date.UTC(2026, 7, 1, 12, 0, second++)),
  });
  return { quarantine, policy };
}

describe("denied endpoint quarantine", () => {
  it("keeps one current item per method and path while appending events", async () => {
    const { quarantine, policy } = setup();

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

  it("normalizes query strings, casing, and trailing slashes into one identity", async () => {
    const { quarantine, policy } = setup();

    await policy.denyEndpoint("GET", "/Admin/Panel/?probe=1");
    await policy.denyEndpoint("get", "/admin/panel");
    await policy.denyEndpoint("GET", "/admin/panel#fragment");
    await policy.denyEndpoint("GET", "/admin/panel?probe=2");

    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 1,
      pending_items: 1,
      event_count: 4,
    });
    const [item] = await quarantine.repository.listReviewable();
    expect(item).toMatchObject({
      kind: "security_event",
      dedupe_key: "GET:/admin/panel",
      requarantine_count: 3,
    });
  });

  it("caps distinct security-event identities per writer", async () => {
    const { quarantine, policy } = setup();

    for (
      let index = 0;
      index < MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER;
      index += 1
    ) {
      await policy.denyEndpoint("GET", `/probe-${index}`, "fuzzer");
    }
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER,
    });

    // Further distinct paths from the same writer bucket into one aggregate
    // identity instead of minting new capacity slots.
    await policy.denyEndpoint("GET", "/probe-extra-1", "fuzzer");
    await policy.denyEndpoint("POST", "/probe-extra-2", "fuzzer");
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER + 1,
    });

    // Another writer still gets its own identities and its own cap.
    await policy.denyEndpoint("GET", "/probe-extra-1", "other");
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER + 2,
    });
  });
});
