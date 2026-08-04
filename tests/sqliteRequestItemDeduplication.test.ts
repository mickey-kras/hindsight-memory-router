import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { NewQuarantineItem } from "../src/quarantine/repository.js";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import {
  DEFAULT_QUARANTINE_LIMITS,
  EncryptedDatabaseQuarantineStore,
} from "../src/quarantine/quarantineStore.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

async function withRepository<T>(
  run: (context: {
    directory: string;
    path: string;
    repository: SqliteQuarantineRepository;
    store: EncryptedDatabaseQuarantineStore;
  }) => Promise<T>,
  limits: Partial<typeof DEFAULT_QUARANTINE_LIMITS> = {},
): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), "hmr-sqlite-request-"));
  const path = join(directory, "quarantine.db");
  const repository = new SqliteQuarantineRepository(path);
  const store = new EncryptedDatabaseQuarantineStore(
    quarantineKeys().publicKey,
    repository,
    { ...DEFAULT_QUARANTINE_LIMITS, rateLimitMax: 0, ...limits },
  );
  try {
    return await run({ directory, path, repository, store });
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
}

function requestItem(overrides: Partial<NewQuarantineItem>): NewQuarantineItem {
  return {
    quarantine_id: "q_invalid_0123456789abcdef",
    created_at: "2026-08-01T00:00:00.000Z",
    updated_at: "2026-08-01T00:00:00.000Z",
    kind: "retain_request",
    reason: "unknown_writer",
    sha256: "a".repeat(64),
    encrypted: {
      version: 1,
      quarantine_id: "q_invalid_0123456789abcdef",
      created_at: "2026-08-01T00:00:00.000Z",
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

describe("SQLite request item deduplication", () => {
  it("refreshes one current item per dedupe key and counts requarantines", async () => {
    await withRepository(async ({ repository, store }) => {
      await repository.initialize();
      const first = await store.put({
        timestamp: "2026-08-01T12:00:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        writerId: "ghost",
        dedupeKey: "request-key",
        payload: { action: "retain", body: { items: [] } },
      });
      const second = await store.put({
        timestamp: "2026-08-01T12:05:00.000Z",
        kind: "recall_request",
        reason: "suspicious_query",
        writerId: "ghost",
        dedupeKey: "request-key",
        payload: { action: "recall", body: { query: "x" } },
      });

      expect(second.quarantine_id).toBe(first.quarantine_id);
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 1,
        pending_items: 1,
        event_count: 2,
      });
      await expect(repository.get(first.quarantine_id)).resolves.toMatchObject({
        dedupe_key: "request-key",
        requarantine_count: 1,
        updated_at: "2026-08-01T12:05:00.000Z",
      });
      const summary = await repository.listReviewable();
      expect(summary).toHaveLength(1);
      expect(summary[0]).toMatchObject({
        dedupe_key: "request-key",
        requarantine_count: 1,
      });
    });
  });

  it("rejects request upserts without a dedupe identity", async () => {
    await withRepository(async ({ repository }) => {
      await repository.initialize();
      await expect(
        repository.upsertRequestItem(requestItem({})),
      ).rejects.toThrow("request item dedupe identity is required");
      await expect(
        repository.upsertRequestItem(
          requestItem({ kind: "security_event", dedupe_key: "key" }),
        ),
      ).rejects.toThrow("request item dedupe identity is required");
    });
  });

  it("migrates pre-existing databases and keeps legacy rows readable", async () => {
    await withRepository(async ({ path, repository, store }) => {
      // Build a database with the pre-dedup schema and one legacy row.
      const legacy = new DatabaseSync(path);
      legacy.exec(`
        CREATE TABLE quarantine_items (
          quarantine_id TEXT PRIMARY KEY,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          kind TEXT NOT NULL,
          reason TEXT NOT NULL,
          writer_id TEXT,
          source TEXT,
          source_bank TEXT,
          source_memory_id TEXT,
          source_content_sha256 TEXT,
          sha256 TEXT NOT NULL,
          encrypted_envelope TEXT,
          encrypted_bytes INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL,
          postpone_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE quarantine_events (
          event_id TEXT PRIMARY KEY,
          quarantine_id TEXT NOT NULL,
          occurred_at TEXT NOT NULL,
          event_type TEXT NOT NULL,
          details TEXT NOT NULL
        );
        INSERT INTO quarantine_items (
          quarantine_id, created_at, updated_at, kind, reason, writer_id,
          sha256, status, postpone_count
        ) VALUES (
          'q_legacy_0123456789abcdef', '2026-07-01T00:00:00.000Z',
          '2026-07-01T00:00:00.000Z', 'retain_request', 'unknown_writer',
          'ghost', '${"b".repeat(64)}', 'pending', 0
        );
      `);
      legacy.close();

      await repository.initialize();

      // The legacy row stays readable and has no dedupe identity.
      const legacyItem = await repository.get("q_legacy_0123456789abcdef");
      expect(legacyItem).toMatchObject({
        kind: "retain_request",
        requarantine_count: 0,
      });
      expect(legacyItem?.dedupe_key).toBeUndefined();

      // New request items deduplicate against the migrated schema.
      const first = await store.put({
        timestamp: "2026-08-01T12:00:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        writerId: "ghost",
        dedupeKey: "request-key",
        payload: { action: "retain", body: { items: [] } },
      });
      const second = await store.put({
        timestamp: "2026-08-01T12:01:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        writerId: "ghost",
        dedupeKey: "request-key",
        payload: { action: "retain", body: { items: [] } },
      });

      expect(second.quarantine_id).toBe(first.quarantine_id);
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 2,
        pending_items: 2,
        event_count: 2,
      });

      // Reopening an already-migrated database is a no-op.
      await repository.initialize();
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 2,
        pending_items: 2,
      });
    });
  });

  it("charges repeats to the requarantine budget and never refreshes an active review", async () => {
    await withRepository(
      async ({ path, repository, store }) => {
        await repository.initialize();
        const input = {
          timestamp: "2026-08-01T12:00:00.000Z",
          kind: "retain_request" as const,
          reason: "unknown_writer",
          writerId: "ghost",
          dedupeKey: "request-key",
          payload: { action: "retain", body: { items: [] } },
        };
        const first = await store.put(input);

        // The per-writer write quota (1 per window) is exhausted by the first
        // write, but repeats are known identities and charge the
        // requarantine-ops budget instead.
        const repeat = await store.put({
          ...input,
          timestamp: "2026-08-01T12:05:00.000Z",
        });
        expect(repeat.quarantine_id).toBe(first.quarantine_id);
        await expect(
          repository.get(first.quarantine_id),
        ).resolves.toMatchObject({ requarantine_count: 1 });

        // A review claimed by another process must survive a repeat: the
        // refresh applies only while the item is pending or postponed.
        const claim = new DatabaseSync(path);
        claim.exec(`
          UPDATE quarantine_items
          SET status = 'review_in_progress',
            updated_at = '2026-08-01T12:10:00.000Z'
          WHERE quarantine_id = '${first.quarantine_id}';
        `);
        claim.close();

        const duringReview = await store.put({
          ...input,
          timestamp: "2026-08-01T12:15:00.000Z",
        });
        expect(duringReview.quarantine_id).toBe(first.quarantine_id);
        await expect(
          repository.get(first.quarantine_id),
        ).resolves.toMatchObject({
          status: "review_in_progress",
          updated_at: "2026-08-01T12:10:00.000Z",
          requarantine_count: 1,
        });
        await expect(repository.stats()).resolves.toMatchObject({
          total_items: 1,
          event_count: 2,
        });
      },
      { rateLimitMax: 1, requarantineOpsMax: 10 },
    );
  });
});
