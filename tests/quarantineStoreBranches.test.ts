import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { toPostgresPlaceholders } from "../src/quarantine/postgresRepository.js";
import {
  repositoryFromConnectionString,
  sqlitePath,
} from "../src/quarantine/repositoryFactory.js";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import { EncryptedDatabaseQuarantineStore } from "../src/quarantine/quarantineStore.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

async function withSqlite<T>(
  run: (context: {
    repository: SqliteQuarantineRepository;
    store: EncryptedDatabaseQuarantineStore;
  }) => Promise<T>,
): Promise<T> {
  const directory = mkdtempSync(join(tmpdir(), "quarantine-sqlite-"));
  const repository = new SqliteQuarantineRepository(
    join(directory, "quarantine.db"),
  );
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

describe("SQL quarantine repository", () => {
  it("persists indexed review state and append-only event counts", async () => {
    await withSqlite(async ({ repository, store }) => {
      const first = await store.put({
        timestamp: "2026-07-01T00:00:00.000Z",
        kind: "retain_request",
        reason: "unknown_writer",
        payload: { content: "first" },
      });
      await store.put({
        timestamp: "2026-07-02T00:00:00.000Z",
        kind: "retain_request",
        reason: "suspicious_content",
        payload: { content: "second" },
      });

      expect(await repository.listReviewable(1, 0)).toEqual([
        expect.objectContaining({ quarantine_id: first.quarantine_id }),
      ]);
      expect(
        await repository.postpone(
          first.quarantine_id,
          "2026-07-03T00:00:00.000Z",
        ),
      ).toMatchObject({ status: "postponed", postpone_count: 1 });
      expect(await repository.stats()).toMatchObject({
        total_items: 2,
        pending_items: 1,
        postponed_items: 1,
        event_count: 3,
      });

      const preview = await repository.previewCleanup({
        scope: "pending",
        reasons: ["unknown_writer"],
      });
      expect(preview.count).toBe(1);
      await expect(
        repository.cleanup(
          { scope: "pending", reasons: ["unknown_writer"] },
          2,
          "2026-07-04T00:00:00.000Z",
        ),
      ).rejects.toMatchObject({ status: 409 });
      await expect(
        repository.cleanup(
          { scope: "pending", reasons: ["unknown_writer"] },
          1,
          "2026-07-04T00:00:00.000Z",
        ),
      ).resolves.toMatchObject({ count: 1 });
      expect(await repository.get(first.quarantine_id)).toBeNull();
      expect(await repository.stats()).toMatchObject({
        total_items: 1,
        event_count: 4,
      });
    });
  });

  it("stores recalled-memory decisions without retaining ciphertext", async () => {
    await withSqlite(async ({ repository, store }) => {
      const created = await store.put({
        timestamp: "2026-07-01T00:00:00.000Z",
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        sourceBank: "ops",
        sourceMemoryId: "memory-1",
        sourceContentSha256: "a".repeat(64),
        payload: { result: { id: "memory-1", text: "suspicious" } },
      });
      expect(await repository.findMemoryState("ops", "memory-1")).toMatchObject(
        {
          quarantine_id: created.quarantine_id,
          status: "pending",
        },
      );

      await repository.markMemoryReviewed(
        created.quarantine_id,
        "reviewed_blocked",
        "2026-07-01T01:00:00.000Z",
      );
      expect(await repository.get(created.quarantine_id)).toMatchObject({
        status: "reviewed_blocked",
        encrypted: null,
      });
      expect(await repository.stats()).toMatchObject({
        reviewed_blocked_items: 1,
        encrypted_bytes: 0,
        event_count: 2,
      });
      await expect(
        repository.postpone(created.quarantine_id, "2026-07-01T02:00:00.000Z"),
      ).rejects.toMatchObject({ status: 409 });
    });
  });

  it("parses database connection strings and PostgreSQL placeholders", async () => {
    expect(sqlitePath("sqlite::memory:")).toBe(":memory:");
    expect(sqlitePath("sqlite:///tmp/quarantine.db")).toBe(
      "/tmp/quarantine.db",
    );
    expect(repositoryFromConnectionString("sqlite::memory:")).toBeInstanceOf(
      SqliteQuarantineRepository,
    );
    expect(() =>
      repositoryFromConnectionString("mysql://localhost/db"),
    ).toThrow("QUARANTINE_DATABASE_URL");
    expect(() => sqlitePath("sqlite:")).toThrow("path is required");
    expect(toPostgresPlaceholders("a = ? AND b = ?")).toBe("a = $1 AND b = $2");
  });
});
