import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import {
  DEFAULT_QUARANTINE_LIMITS,
  EncryptedDatabaseQuarantineStore,
} from "../src/quarantine/quarantineStore.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("SQLite quarantine concurrency", () => {
  it("serializes concurrent writes on the shared connection", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hmr-sqlite-concurrency-"));
    temporaryDirectories.push(directory);
    const repository = new SqliteQuarantineRepository(
      join(directory, "quarantine.db"),
    );
    await repository.initialize();
    const { publicKey } = quarantineKeys();
    const store = new EncryptedDatabaseQuarantineStore(publicKey, repository, {
      ...DEFAULT_QUARANTINE_LIMITS,
      rateLimitMax: 0,
    });

    try {
      const writes = await Promise.all(
        Array.from({ length: 12 }, (_, index) =>
          store.put({
            timestamp: new Date(
              Date.UTC(2026, 7, 1, 12, 0, index),
            ).toISOString(),
            kind: "retain_request",
            reason: "unknown_writer",
            writerId: `writer-${index}`,
            source: "concurrency-test",
            payload: {
              action: "retain",
              body: { items: [{ content: `memory-${index}` }] },
            },
          }),
        ),
      );

      expect(new Set(writes.map((write) => write.quarantine_id)).size).toBe(12);
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 12,
        pending_items: 12,
        event_count: 12,
      });
    } finally {
      await repository.close();
    }
  });
});
