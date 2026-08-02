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

describe("quarantine review action locking", () => {
  it("issues one Hindsight write for concurrent approvals", async () => {
    const quarantine = memoryQuarantine({ rateLimitMax: 0 });
    const hindsight = new SlowHindsightGateway();
    const stored = await quarantine.store.put({
      timestamp: "2026-08-02T00:00:00.000Z",
      kind: "retain_request",
      reason: "unknown_writer",
      writerId: "ops",
      source: "openclaw",
      payload: {
        action: "retain",
        writer_id: "ops",
        body: { items: [{ content: "approved once" }] },
      },
    });
    const item = await quarantine.repository.get(stored.quarantine_id);
    if (!item?.encrypted) throw new Error("missing encrypted test item");
    const decrypted = decryptQuarantineEnvelope(
      item.encrypted,
      quarantine.keys.privateKey,
    );
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
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(
      1,
    );
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({
      status: "rejected",
      reason: { status: 404, code: "quarantine_not_found" },
    });
  });
});
