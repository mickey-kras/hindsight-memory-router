import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { QuarantineAdminService } from "../src/quarantine/quarantineAdmin.js";
import { decryptQuarantineEnvelope } from "../src/quarantine/envelopeCrypto.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

class SlowHindsightGateway extends FakeHindsightGateway {
  override async retain(
    bankId: string,
    body: Parameters<FakeHindsightGateway["retain"]>[1],
  ): Promise<unknown> {
    await new Promise((resolve) => setTimeout(resolve, 20));
    return super.retain(bankId, body);
  }
}

class FailingHindsightGateway extends FakeHindsightGateway {
  override async retain(): Promise<unknown> {
    throw new Error("upstream unavailable");
  }
}

class SelectiveSlowHindsightGateway extends FakeHindsightGateway {
  constructor(private readonly slowContent: string) {
    super();
  }

  override async retain(
    bankId: string,
    body: Parameters<FakeHindsightGateway["retain"]>[1],
  ): Promise<unknown> {
    const content = String(body.items?.[0]?.content ?? "");
    if (content === this.slowContent) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    return super.retain(bankId, body);
  }
}

describe("quarantine review action locking", () => {
  it("issues one Hindsight write for concurrent approvals", async () => {
    const quarantine = memoryQuarantine({ rateLimitMax: 0 });
    const hindsight = new SlowHindsightGateway();
    const stored = await putRetain(quarantine, "approved once");
    const decrypted = await decryptStored(quarantine, stored.quarantine_id);
    const admin = new QuarantineAdminService({
      repository: quarantine.repository,
      hindsight,
      registry: DEFAULT_REGISTRY,
    });

    const results = await Promise.allSettled([
      admin.approve(stored.quarantine_id, { decrypted }),
      admin.approve(stored.quarantine_id, { decrypted }),
    ]);

    expect(hindsight.retained).toHaveLength(1);
    expect(
      results.filter((result) => result.status === "fulfilled"),
    ).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({
      status: "rejected",
      reason: { status: 409, code: "quarantine_already_finalized" },
    });
  });

  it("keeps the item pending when Hindsight rejects approval", async () => {
    const quarantine = memoryQuarantine({ rateLimitMax: 0 });
    const stored = await putRetain(quarantine, "retry later");
    const decrypted = await decryptStored(quarantine, stored.quarantine_id);
    const admin = new QuarantineAdminService({
      repository: quarantine.repository,
      hindsight: new FailingHindsightGateway(),
      registry: DEFAULT_REGISTRY,
    });

    await expect(
      admin.approve(stored.quarantine_id, { decrypted }),
    ).rejects.toThrow("upstream unavailable");
    await expect(
      quarantine.repository.get(stored.quarantine_id),
    ).resolves.toMatchObject({
      status: "pending",
      encrypted: expect.any(Object),
    });
    expect(quarantine.repository.events).toHaveLength(2);
    expect(quarantine.repository.events[0]?.event_type).toBe("quarantined");
    expect(quarantine.repository.events[1]).toMatchObject({
      event_type: "review_interrupted",
      details: { outcome: "restored", status: "pending" },
    });
  });

  it("does not block other reviews behind a hung Hindsight call", async () => {
    const quarantine = memoryQuarantine({ rateLimitMax: 0 });
    const hindsight = new SelectiveSlowHindsightGateway("slow approval");
    const slow = await putRetain(quarantine, "slow approval");
    const fast = await putRetain(quarantine, "fast approval");
    const admin = new QuarantineAdminService({
      repository: quarantine.repository,
      hindsight,
      registry: DEFAULT_REGISTRY,
    });

    const completions: string[] = [];
    const slowApproval = admin
      .approve(slow.quarantine_id, {
        decrypted: await decryptStored(quarantine, slow.quarantine_id),
      })
      .then(() => completions.push("slow"));
    const fastApproval = admin
      .approve(fast.quarantine_id, {
        decrypted: await decryptStored(quarantine, fast.quarantine_id),
      })
      .then(() => completions.push("fast"));
    await Promise.all([slowApproval, fastApproval]);

    expect(completions).toEqual(["fast", "slow"]);
    expect(hindsight.retained).toHaveLength(2);
    await expect(
      quarantine.repository.get(slow.quarantine_id),
    ).resolves.toBeNull();
    await expect(
      quarantine.repository.get(fast.quarantine_id),
    ).resolves.toBeNull();
  });

  it("rejects finalization when the item changes mid-review", async () => {
    const quarantine = memoryQuarantine({ rateLimitMax: 0 });
    const stored = await putRetain(quarantine, "changed mid-review");
    let releaseOperation: () => void = () => undefined;
    const approval = quarantine.repository.approveRetain(
      stored.quarantine_id,
      "2026-08-02T01:00:00.000Z",
      {},
      () =>
        new Promise<void>((resolve) => {
          releaseOperation = resolve;
        }),
    );
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const item = await quarantine.repository.get(stored.quarantine_id);
      if (item?.status === "review_in_progress") break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const claimed = await quarantine.repository.get(stored.quarantine_id);
    if (!claimed) throw new Error("missing claimed test item");
    quarantine.repository.items.set(stored.quarantine_id, {
      ...claimed,
      status: "pending",
    });

    releaseOperation();
    await expect(approval).rejects.toMatchObject({
      status: 409,
      code: "quarantine_review_changed",
    });
  });

  it("recovers interrupted reviews to postponed on initialize", async () => {
    const quarantine = memoryQuarantine({ rateLimitMax: 0 });
    const stored = await putRetain(quarantine, "interrupted");
    const item = await quarantine.repository.get(stored.quarantine_id);
    if (!item) throw new Error("missing stored test item");
    quarantine.repository.items.set(stored.quarantine_id, {
      ...item,
      status: "review_in_progress",
    });

    await quarantine.repository.initialize();

    await expect(
      quarantine.repository.get(stored.quarantine_id),
    ).resolves.toMatchObject({ status: "postponed" });
    expect(
      quarantine.repository.events.map((event) => event.event_type),
    ).toEqual(["quarantined", "review_interrupted"]);
    expect(quarantine.repository.events[1]?.details).toMatchObject({
      outcome: "postponed",
      recovered: true,
    });
  });
});

async function putRetain(
  quarantine: ReturnType<typeof memoryQuarantine>,
  content: string,
) {
  return quarantine.store.put({
    timestamp: "2026-08-02T00:00:00.000Z",
    kind: "retain_request",
    reason: "unknown_writer",
    writerId: "ops",
    source: "openclaw",
    payload: {
      action: "retain",
      writer_id: "ops",
      body: { items: [{ content }] },
    },
  });
}

async function decryptStored(
  quarantine: ReturnType<typeof memoryQuarantine>,
  quarantineId: string,
) {
  const item = await quarantine.repository.get(quarantineId);
  if (!item?.encrypted) throw new Error("missing encrypted test item");
  return decryptQuarantineEnvelope(item.encrypted, quarantine.keys.privateKey);
}
