import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { QuarantineAdminService } from "../src/quarantine/quarantineAdmin.js";
import { decryptQuarantineEnvelope } from "../src/quarantine/envelopeCrypto.js";
import type {
  QuarantineKind,
  ReviewReason,
  WriterRegistry,
} from "../src/types.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

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
  },
};

function context(maxPostpones = 1) {
  const quarantine = memoryQuarantine();
  const hindsight = new FakeHindsightGateway();
  const service = new QuarantineAdminService({
    repository: quarantine.repository,
    hindsight,
    registry,
    maxPostpones,
    now: () => new Date("2026-08-01T00:00:00.000Z"),
  });
  return { ...quarantine, hindsight, service };
}

async function addItem(
  state: ReturnType<typeof context>,
  input: {
    kind?: QuarantineKind;
    reason?: ReviewReason;
    writerId?: string;
    sourceBank?: "ops";
    sourceMemoryId?: string;
    sourceContentSha256?: string;
    payload?: unknown;
  } = {},
) {
  const stored = await state.store.put({
    timestamp: "2026-07-31T23:00:00.000Z",
    kind: input.kind ?? "retain_request",
    reason: input.reason ?? "suspicious_content",
    writerId: input.writerId,
    source: "admin-branch-test",
    sourceBank: input.sourceBank,
    sourceMemoryId: input.sourceMemoryId,
    sourceContentSha256: input.sourceContentSha256,
    payload: input.payload ?? {
      action: "retain",
      writer_id: "ops",
      body: { items: [{ content: "exact original" }] },
    },
  });
  const item = await state.repository.get(stored.quarantine_id);
  if (!item?.encrypted) throw new Error("expected encrypted item");
  const decrypted = decryptQuarantineEnvelope(
    item.encrypted,
    state.keys.privateKey,
  );
  return { id: stored.quarantine_id, item, decrypted };
}

describe("QuarantineAdminService validation", () => {
  it("rejects invalid, missing, finalized, and payload-free items", async () => {
    const state = context();
    await expect(state.service.readItem("bad-id")).rejects.toMatchObject({
      status: 400,
      code: "invalid_quarantine_id",
    });
    await expect(
      state.service.readItem("q_missing_0123456789abcdef"),
    ).rejects.toMatchObject({ status: 404, code: "quarantine_not_found" });

    const finalized = await addItem(state, {
      kind: "recalled_memory",
      reason: "recalled_suspicious_memory",
      sourceBank: "ops",
      sourceMemoryId: "memory-finalized",
      sourceContentSha256: "a".repeat(64),
      payload: {
        action: "recalled_memory",
        bank_id: "ops",
        result: { id: "memory-finalized", text: "unsafe" },
      },
    });
    await state.repository.markMemoryReviewed(
      finalized.id,
      "reviewed_allowed",
      "2026-07-31T23:30:00.000Z",
    );
    await expect(state.service.readItem(finalized.id)).rejects.toMatchObject({
      status: 409,
      code: "quarantine_already_finalized",
    });

    const payloadFree = await addItem(state);
    state.repository.items.set(payloadFree.id, {
      ...payloadFree.item,
      encrypted: null,
    });
    await expect(state.service.readItem(payloadFree.id)).rejects.toMatchObject({
      status: 409,
      code: "quarantine_payload_unavailable",
    });
  });

  it("rejects malformed, altered, and metadata-mismatched approvals", async () => {
    const malformed = context();
    const malformedItem = await addItem(malformed);
    await expect(
      malformed.service.approve(malformedItem.id, { decrypted: null }),
    ).rejects.toMatchObject({
      status: 400,
      code: "invalid_decrypted_quarantine",
    });

    const altered = context();
    const alteredItem = await addItem(altered);
    const changed = structuredClone(alteredItem.decrypted) as {
      payload: { body: { items: Array<{ content: string }> } };
    };
    changed.payload.body.items[0].content = "changed";
    await expect(
      altered.service.approve(alteredItem.id, { decrypted: changed }),
    ).rejects.toMatchObject({
      status: 409,
      code: "quarantine_hash_mismatch",
    });

    const metadata = context();
    const metadataItem = await addItem(metadata);
    metadata.repository.items.set(metadataItem.id, {
      ...metadataItem.item,
      created_at: "2026-07-31T22:00:00.000Z",
    });
    await expect(
      metadata.service.approve(metadataItem.id, {
        decrypted: metadataItem.decrypted,
      }),
    ).rejects.toMatchObject({
      status: 409,
      code: "quarantine_metadata_mismatch",
    });
  });

  it("validates every retain approval prerequisite", async () => {
    const wrongAction = context();
    const wrongActionItem = await addItem(wrongAction, {
      payload: { action: "recall" },
    });
    await expect(
      wrongAction.service.approve(wrongActionItem.id, {
        decrypted: wrongActionItem.decrypted,
      }),
    ).rejects.toMatchObject({
      status: 409,
      code: "invalid_quarantine_payload",
    });

    const missingWriter = context();
    const missingWriterItem = await addItem(missingWriter, {
      payload: { action: "retain", body: { items: [] } },
    });
    await expect(
      missingWriter.service.approve(missingWriterItem.id, {
        decrypted: missingWriterItem.decrypted,
      }),
    ).rejects.toMatchObject({ status: 400, code: "invalid_request" });

    const unknownWriter = context();
    const unknownWriterItem = await addItem(unknownWriter, {
      payload: {
        action: "retain",
        writer_id: "not-registered",
        body: { items: [] },
      },
    });
    await expect(
      unknownWriter.service.approve(unknownWriterItem.id, {
        decrypted: unknownWriterItem.decrypted,
      }),
    ).rejects.toMatchObject({
      status: 409,
      code: "writer_not_registered",
    });

    const invalidBody = context();
    const invalidBodyItem = await addItem(invalidBody, {
      payload: { action: "retain", writer_id: "ops", body: {} },
    });
    await expect(
      invalidBody.service.approve(invalidBodyItem.id, {
        decrypted: invalidBodyItem.decrypted,
      }),
    ).rejects.toMatchObject({ status: 400, code: "invalid_retain_body" });
  });

  it("validates recalled-memory source and review actions", async () => {
    const sourceMismatch = context();
    const recalled = await addItem(sourceMismatch, {
      kind: "recalled_memory",
      reason: "recalled_suspicious_memory",
      sourceBank: "ops",
      sourceMemoryId: "memory-1",
      sourceContentSha256: "a".repeat(64),
      payload: {
        action: "recalled_memory",
        bank_id: "ops",
        result: { id: "memory-1", text: "unsafe" },
      },
    });
    sourceMismatch.repository.items.set(recalled.id, {
      ...recalled.item,
      source_memory_id: "memory-other",
    });
    await expect(
      sourceMismatch.service.approve(recalled.id, {
        decrypted: recalled.decrypted,
      }),
    ).rejects.toMatchObject({
      status: 409,
      code: "quarantine_source_mismatch",
    });

    const invalidAction = context();
    const recallRequest = await addItem(invalidAction, {
      kind: "recall_request",
      reason: "suspicious_query",
      payload: { action: "recall", body: { query: "unsafe" } },
    });
    await expect(
      invalidAction.service.approve(recallRequest.id, {
        decrypted: recallRequest.decrypted,
      }),
    ).rejects.toMatchObject({
      status: 409,
      code: "invalid_review_action",
    });

    const missingSource = context();
    const ordinary = await addItem(missingSource);
    missingSource.repository.items.set(ordinary.id, {
      ...ordinary.item,
      kind: "recalled_memory",
      source_bank: undefined,
      source_memory_id: undefined,
    });
    await expect(
      missingSource.service.reject(ordinary.id),
    ).rejects.toMatchObject({
      status: 409,
      code: "quarantine_source_missing",
    });
  });

  it("enforces postpone and cleanup confirmation rules", async () => {
    const state = context(1);
    const item = await addItem(state);
    await expect(state.service.postpone(item.id)).resolves.toMatchObject({
      count: 1,
    });
    await expect(state.service.postpone(item.id)).rejects.toMatchObject({
      status: 409,
      code: "postpone_limit_reached",
    });

    await expect(
      state.service.cleanup({ older_than: "not-a-date" }),
    ).rejects.toMatchObject({ status: 400, code: "invalid_cleanup_time" });
    await expect(state.service.cleanup({})).resolves.toMatchObject({
      dry_run: true,
      count: 1,
    });
    await expect(
      state.service.cleanup({ dry_run: false }),
    ).rejects.toMatchObject({
      status: 400,
      code: "expected_count_required",
    });
    await expect(
      state.service.cleanup({ dry_run: false, expected_count: 2 }),
    ).rejects.toMatchObject({
      status: 409,
      code: "quarantine_cleanup_changed",
    });
    await expect(state.service.stats()).resolves.toMatchObject({
      total_items: 1,
      postponed_items: 1,
    });
  });
});
