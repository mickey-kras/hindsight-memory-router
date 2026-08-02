import { describe, expect, it } from "vitest";
import { MemoryQuarantineRepository } from "../src/quarantine/memoryRepository.js";
import type { NewQuarantineItem } from "../src/quarantine/repository.js";

function item(
  id: string,
  createdAt: string,
  overrides: Partial<NewQuarantineItem> = {},
): NewQuarantineItem {
  return {
    quarantine_id: id,
    created_at: createdAt,
    updated_at: createdAt,
    kind: "retain_request",
    reason: "unknown_writer",
    sha256: "a".repeat(64),
    encrypted: {
      version: 1,
      quarantine_id: id,
      created_at: createdAt,
      reason: "unknown_writer",
      sha256: "a".repeat(64),
      encryption: {
        algorithm: "AES-256-GCM",
        key_wrap: "RSA-OAEP-SHA256",
        wrapped_key_b64: "AAAA",
        iv_b64: "AAAAAAAAAAAAAAAA",
        tag_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
      },
      ciphertext_b64: "AAAA",
    },
    status: "pending",
    postpone_count: 0,
    ...overrides,
  };
}

describe("MemoryQuarantineRepository branches", () => {
  it("initializes, sorts, paginates, and rejects duplicate ids", async () => {
    const repository = new MemoryQuarantineRepository();
    await expect(repository.initialize()).resolves.toBeUndefined();
    await repository.insert(
      item("q_later_0123456789abcdef", "2026-08-02T00:00:00.000Z"),
    );
    await repository.insert(
      item("q_earlier_0123456789abcdef", "2026-08-01T00:00:00.000Z"),
    );

    await expect(
      repository.insert(
        item("q_later_0123456789abcdef", "2026-08-03T00:00:00.000Z"),
      ),
    ).rejects.toThrow("duplicate quarantine_id");
    await expect(repository.listReviewable(1, 0)).resolves.toEqual([
      expect.objectContaining({ quarantine_id: "q_earlier_0123456789abcdef" }),
    ]);
    await expect(repository.listReviewable(1, 1)).resolves.toEqual([
      expect.objectContaining({ quarantine_id: "q_later_0123456789abcdef" }),
    ]);
    await expect(repository.close()).resolves.toBeUndefined();
  });

  it("covers missing records and invalid state transitions", async () => {
    const repository = new MemoryQuarantineRepository();
    await expect(repository.get("missing")).resolves.toBeNull();
    await expect(
      repository.findMemoryState("ops", "missing"),
    ).resolves.toBeNull();
    await expect(
      repository.postpone("missing", "2026-08-01T00:00:00.000Z"),
    ).rejects.toMatchObject({ status: 404 });
    await expect(
      repository.remove("missing", "rejected", "2026-08-01T00:00:00.000Z"),
    ).rejects.toMatchObject({ status: 404 });

    const ordinary = item(
      "q_ordinary_0123456789abcdef",
      "2026-08-01T00:00:00.000Z",
    );
    await repository.insert(ordinary);
    await expect(
      repository.markMemoryReviewed(
        ordinary.quarantine_id,
        "reviewed_allowed",
        "2026-08-01T01:00:00.000Z",
      ),
    ).rejects.toMatchObject({ status: 409, code: "invalid_review_action" });

    repository.items.set(ordinary.quarantine_id, {
      ...ordinary,
      status: "reviewed_allowed",
    });
    await expect(
      repository.postpone(ordinary.quarantine_id, "2026-08-01T02:00:00.000Z"),
    ).rejects.toMatchObject({
      status: 409,
      code: "quarantine_already_finalized",
    });
  });

  it("tracks reviewed states and removes ciphertext", async () => {
    const repository = new MemoryQuarantineRepository();
    const allowed = item(
      "q_allowed_0123456789abcdef",
      "2026-08-01T00:00:00.000Z",
      {
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        source_bank: "ops",
        source_memory_id: "memory-allowed",
        source_content_sha256: "b".repeat(64),
      },
    );
    const blocked = item(
      "q_blocked_0123456789abcdef",
      "2026-08-01T00:01:00.000Z",
      {
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        source_bank: "ops",
        source_memory_id: "memory-blocked",
        source_content_sha256: "c".repeat(64),
      },
    );
    await repository.insert(allowed);
    await repository.insert(blocked);
    await repository.markMemoryReviewed(
      allowed.quarantine_id,
      "reviewed_allowed",
      "2026-08-01T01:00:00.000Z",
    );
    await repository.markMemoryReviewed(
      blocked.quarantine_id,
      "reviewed_blocked",
      "2026-08-01T01:01:00.000Z",
    );

    await expect(
      repository.findMemoryState("ops", "memory-allowed"),
    ).resolves.toMatchObject({ status: "reviewed_allowed", encrypted: null });
    await expect(repository.stats()).resolves.toMatchObject({
      total_items: 2,
      reviewed_allowed_items: 1,
      reviewed_blocked_items: 1,
      encrypted_bytes: 0,
      event_count: 4,
    });
  });

  it("filters cleanup by scope, reason, and age", async () => {
    const repository = new MemoryQuarantineRepository();
    await repository.insert(
      item("q_old_0123456789abcdef", "2026-07-01T00:00:00.000Z"),
    );
    await repository.insert(
      item("q_new_0123456789abcdef", "2026-08-01T00:00:00.000Z", {
        reason: "suspicious_content",
      }),
    );
    const reviewed = item(
      "q_reviewed_0123456789abcdef",
      "2026-06-01T00:00:00.000Z",
      {
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        source_bank: "ops",
        source_memory_id: "memory-reviewed",
      },
    );
    await repository.insert(reviewed);
    await repository.markMemoryReviewed(
      reviewed.quarantine_id,
      "reviewed_allowed",
      "2026-08-01T01:00:00.000Z",
    );

    await expect(
      repository.previewCleanup({
        scope: "pending",
        reasons: ["unknown_writer"],
        older_than: "2026-07-15T00:00:00.000Z",
      }),
    ).resolves.toMatchObject({ count: 1 });
    await expect(
      repository.cleanup(
        { scope: "pending", reasons: ["unknown_writer"] },
        2,
        "2026-08-02T00:00:00.000Z",
      ),
    ).rejects.toMatchObject({ status: 409 });
    await expect(
      repository.cleanup(
        { scope: "all", older_than: "2026-07-15T00:00:00.000Z" },
        2,
        "2026-08-02T00:00:00.000Z",
      ),
    ).resolves.toMatchObject({ count: 2 });
    await expect(repository.stats()).resolves.toMatchObject({
      total_items: 1,
      event_count: 6,
    });
  });
});
