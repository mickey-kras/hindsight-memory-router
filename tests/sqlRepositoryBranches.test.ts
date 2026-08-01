import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { NewQuarantineItem } from "../src/quarantine/repository.js";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import { EncryptedDatabaseQuarantineStore } from "../src/quarantine/quarantineStore.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

async function withRepository<T>(
  run: (context: {
    repository: SqliteQuarantineRepository;
    store: EncryptedDatabaseQuarantineStore;
  }) => Promise<T>,
): Promise<T> {
  const directory = mkdtempSync(join(tmpdir(), "sql-repository-branches-"));
  const repository = new SqliteQuarantineRepository(join(directory, "state.db"));
  const keys = quarantineKeys();
  await repository.initialize();
  try {
    return await run({
      repository,
      store: new EncryptedDatabaseQuarantineStore(keys.publicKey, repository),
    });
  } finally {
    await repository.close();
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("SqlQuarantineRepository branches", () => {
  it("returns zero statistics and missing records for an empty database", async () => {
    await withRepository(async ({ repository }) => {
      await expect(repository.get("missing")).resolves.toBeNull();
      await expect(
        repository.findMemoryState("ops", "missing"),
      ).resolves.toBeNull();
      await expect(repository.listReviewable()).resolves.toEqual([]);
      await expect(repository.stats()).resolves.toEqual({
        total_items: 0,
        pending_items: 0,
        postponed_items: 0,
        reviewed_allowed_items: 0,
        reviewed_blocked_items: 0,
        encrypted_bytes: 0,
        event_count: 0,
      });
      await expect(
        repository.remove(
          "q_missing_0123456789abcdef",
          "rejected",
          "2026-08-01T00:00:00.000Z",
        ),
      ).rejects.toMatchObject({ status: 404 });
    });
  });

  it("upserts changed recalled content into the existing review identity", async () => {
    await withRepository(async ({ repository, store }) => {
      const first = await store.put({
        timestamp: "2026-08-01T00:00:00.000Z",
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        sourceBank: "ops",
        sourceMemoryId: "memory-1",
        sourceContentSha256: "a".repeat(64),
        payload: { result: { id: "memory-1", text: "first" } },
      });
      await repository.markMemoryReviewed(
        first.quarantine_id,
        "reviewed_allowed",
        "2026-08-01T00:10:00.000Z",
      );
      await store.put({
        timestamp: "2026-08-01T00:20:00.000Z",
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        sourceBank: "ops",
        sourceMemoryId: "memory-1",
        sourceContentSha256: "b".repeat(64),
        payload: { result: { id: "memory-1", text: "changed" } },
      });

      await expect(
        repository.findMemoryState("ops", "memory-1"),
      ).resolves.toMatchObject({
        quarantine_id: first.quarantine_id,
        status: "pending",
        postpone_count: 0,
        source_content_sha256: "b".repeat(64),
      });
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 1,
        pending_items: 1,
        reviewed_allowed_items: 0,
        event_count: 3,
      });
    });
  });

  it("rejects recalled upserts without stable source identity", async () => {
    await withRepository(async ({ repository }) => {
      const invalid: NewQuarantineItem = {
        quarantine_id: "q_invalid_0123456789abcdef",
        created_at: "2026-08-01T00:00:00.000Z",
        updated_at: "2026-08-01T00:00:00.000Z",
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        sha256: "a".repeat(64),
        encrypted: {
          version: 1,
          quarantine_id: "q_invalid_0123456789abcdef",
          created_at: "2026-08-01T00:00:00.000Z",
          reason: "recalled_suspicious_memory",
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
      };
      await expect(repository.upsertRecalledMemory(invalid)).rejects.toThrow(
        "source identity is required",
      );
    });
  });

  it("rejects review transitions for ordinary or finalized items", async () => {
    await withRepository(async ({ repository, store }) => {
      const ordinary = await store.put({
        timestamp: "2026-08-01T00:00:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        payload: { content: "ordinary" },
      });
      await expect(
        repository.markMemoryReviewed(
          ordinary.quarantine_id,
          "reviewed_allowed",
          "2026-08-01T00:10:00.000Z",
        ),
      ).rejects.toMatchObject({ status: 409, code: "invalid_review_action" });

      const recalled = await store.put({
        timestamp: "2026-08-01T01:00:00.000Z",
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        sourceBank: "ops",
        sourceMemoryId: "memory-final",
        sourceContentSha256: "c".repeat(64),
        payload: { result: { id: "memory-final", text: "unsafe" } },
      });
      await repository.markMemoryReviewed(
        recalled.quarantine_id,
        "reviewed_blocked",
        "2026-08-01T01:10:00.000Z",
      );
      await expect(
        repository.markMemoryReviewed(
          recalled.quarantine_id,
          "reviewed_allowed",
          "2026-08-01T01:20:00.000Z",
        ),
      ).rejects.toMatchObject({
        status: 409,
        code: "quarantine_already_finalized",
      });
    });
  });

  it("removes approved and rejected rows while preserving events", async () => {
    await withRepository(async ({ repository, store }) => {
      const approved = await store.put({
        timestamp: "2026-07-01T00:00:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        payload: { content: "approved" },
      });
      const rejected = await store.put({
        timestamp: "2026-07-02T00:00:00.000Z",
        kind: "retain_request",
        reason: "suspicious_content",
        payload: { content: "rejected" },
      });
      await repository.remove(
        approved.quarantine_id,
        "approved",
        "2026-08-01T00:00:00.000Z",
        { target_bank: "ops" },
      );
      await repository.remove(
        rejected.quarantine_id,
        "rejected",
        "2026-08-01T00:01:00.000Z",
      );
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 0,
        event_count: 4,
      });
    });
  });

  it("cleans all matching ages when scope is all", async () => {
    await withRepository(async ({ repository, store }) => {
      await store.put({
        timestamp: "2026-06-01T00:00:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        payload: { content: "old" },
      });
      await store.put({
        timestamp: "2026-08-01T00:00:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        payload: { content: "new" },
      });
      await expect(
        repository.previewCleanup({
          scope: "all",
          older_than: "2026-07-01T00:00:00.000Z",
        }),
      ).resolves.toMatchObject({ count: 1 });
      await expect(
        repository.cleanup(
          {
            scope: "all",
            older_than: "2026-07-01T00:00:00.000Z",
          },
          1,
          "2026-08-02T00:00:00.000Z",
        ),
      ).resolves.toMatchObject({ count: 1 });
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 1,
        pending_items: 1,
        event_count: 3,
      });
    });
  });
});
