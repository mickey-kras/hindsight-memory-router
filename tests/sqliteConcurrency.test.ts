import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import {
  DEFAULT_QUARANTINE_LIMITS,
  EncryptedDatabaseQuarantineStore,
  type QuarantineStoreLimits,
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
    await withStore(
      { ...DEFAULT_QUARANTINE_LIMITS, rateLimitMax: 0 },
      async ({ repository, store }) => {
        const writes = await Promise.all(
          Array.from({ length: 12 }, (_, index) =>
            put(store, index, `writer-${index}`),
          ),
        );

        expect(new Set(writes.map((write) => write.quarantine_id)).size).toBe(
          12,
        );
        await expect(repository.stats()).resolves.toMatchObject({
          total_items: 12,
          pending_items: 12,
          event_count: 12,
        });
      },
    );
  });

  it("enforces capacity atomically across concurrent writes", async () => {
    await withStore(
      {
        ...DEFAULT_QUARANTINE_LIMITS,
        maxPendingItems: 1,
        rateLimitMax: 0,
      },
      async ({ repository, store }) => {
        const results = await Promise.allSettled([
          put(store, 1, "writer-a"),
          put(store, 2, "writer-b"),
        ]);

        expect(
          results.filter((result) => result.status === "fulfilled"),
        ).toHaveLength(1);
        const rejected = results.find(
          (result): result is PromiseRejectedResult =>
            result.status === "rejected",
        );
        expect(rejected?.reason).toMatchObject({
          status: 507,
          code: "quarantine_capacity_exceeded",
        });
        await expect(repository.stats()).resolves.toMatchObject({
          total_items: 1,
          pending_items: 1,
          event_count: 1,
        });
      },
    );
  });
});

async function withStore(
  limits: QuarantineStoreLimits,
  run: (context: {
    repository: SqliteQuarantineRepository;
    store: EncryptedDatabaseQuarantineStore;
  }) => Promise<void>,
): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "hmr-sqlite-concurrency-"));
  temporaryDirectories.push(directory);
  const repository = new SqliteQuarantineRepository(
    join(directory, "quarantine.db"),
  );
  await repository.initialize();
  const { publicKey } = quarantineKeys();
  const store = new EncryptedDatabaseQuarantineStore(
    publicKey,
    repository,
    limits,
  );
  try {
    await run({ repository, store });
  } finally {
    await repository.close();
  }
}

function put(
  store: EncryptedDatabaseQuarantineStore,
  index: number,
  writerId: string,
) {
  return store.put({
    timestamp: new Date(Date.UTC(2026, 7, 1, 12, 0, index)).toISOString(),
    kind: "retain_request",
    reason: "unknown_writer",
    writerId,
    source: "concurrency-test",
    payload: {
      action: "retain",
      body: { items: [{ content: `memory-${index}` }] },
    },
  });
}
