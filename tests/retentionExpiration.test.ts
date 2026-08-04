import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { QuarantineAdminService } from "../src/quarantine/quarantineAdmin.js";
import type {
  NewQuarantineItem,
  QuarantineRepository,
} from "../src/quarantine/repository.js";
import {
  RETENTION_EVENT_QUARANTINE_ID,
  RETENTION_SWEEP_BATCH_LIMIT,
} from "../src/quarantine/repository.js";
import {
  DEFAULT_QUARANTINE_LIMITS,
  EncryptedDatabaseQuarantineStore,
} from "../src/quarantine/quarantineStore.js";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import {
  runQuarantineSweep,
  startQuarantineSweeper,
} from "../src/quarantine/sweeper.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { createMemoryRouterServer } from "../src/server.js";
import type { WriterRegistry } from "../src/types.js";
import { memoryQuarantine, quarantineKeys } from "./quarantineTestUtils.js";

const PAST = "2026-01-01T00:00:00.000Z";
const PAST_EXPIRY = "2026-01-02T00:00:00.000Z";
const SWEEP_AT = "2026-08-01T00:00:00.000Z";

const registry: WriterRegistry = {
  writers: {
    ops: {
      role: "ops",
      source: "test",
      write_bank: "ops",
      read_banks: ["ops"],
    },
  },
  defaults: {
    unknown_writer_action: "review_queue",
    suspicious_content_action: "review_queue",
  },
};

function storeWithTtl(
  repository: ConstructorParameters<typeof EncryptedDatabaseQuarantineStore>[1],
  itemTtlDays: number,
  extraLimits: Partial<typeof DEFAULT_QUARANTINE_LIMITS> = {},
) {
  return new EncryptedDatabaseQuarantineStore(
    quarantineKeys().publicKey,
    repository,
    {
      ...DEFAULT_QUARANTINE_LIMITS,
      rateLimitMax: 0,
      ...extraLimits,
      itemTtlDays,
    },
  );
}

function put(timestamp: string) {
  return {
    timestamp,
    kind: "retain_request" as const,
    reason: "unknown_writer" as const,
    writerId: "ghost",
    payload: { action: "retain", body: { items: [] } },
  };
}

function directItem(overrides: Partial<NewQuarantineItem>): NewQuarantineItem {
  return {
    quarantine_id: "q_direct_0123456789abcdef",
    created_at: PAST,
    updated_at: PAST,
    kind: "security_event",
    reason: "denied_endpoint",
    sha256: "a".repeat(64),
    encrypted: {
      version: 1,
      quarantine_id: "q_direct_0123456789abcdef",
      created_at: PAST,
      reason: "denied_endpoint",
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

async function withSqlite<T>(
  itemTtlDays: number,
  run: (context: {
    directory: string;
    path: string;
    repository: SqliteQuarantineRepository;
    store: EncryptedDatabaseQuarantineStore;
  }) => Promise<T>,
  extraLimits: Partial<typeof DEFAULT_QUARANTINE_LIMITS> = {},
): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), "hmr-sqlite-retention-"));
  const path = join(directory, "quarantine.db");
  const repository = new SqliteQuarantineRepository(path);
  const store = storeWithTtl(repository, itemTtlDays, extraLimits);
  try {
    return await run({ directory, path, repository, store });
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe("item TTL expiration", () => {
  it("stamps expires_at from the configured TTL and omits it when disabled", async () => {
    const expiring = memoryQuarantine();
    const store = storeWithTtl(expiring.repository, 30);
    const stored = await store.put(put("2026-08-01T00:00:00.000Z"));
    await expect(
      expiring.repository.get(stored.quarantine_id),
    ).resolves.toMatchObject({ expires_at: "2026-08-31T00:00:00.000Z" });

    const noExpiry = memoryQuarantine();
    const plain = await noExpiry.store.put(put("2026-08-01T00:00:00.000Z"));
    const item = await noExpiry.repository.get(plain.quarantine_id);
    expect(item?.expires_at).toBeUndefined();
  });

  it("rejects unparseable timestamps when a TTL is configured", async () => {
    const quarantine = memoryQuarantine();
    const store = storeWithTtl(quarantine.repository, 30);
    await expect(store.put(put("not-a-date"))).rejects.toMatchObject({
      status: 400,
      code: "invalid_quarantine_timestamp",
    });
  });

  it("sweeps expired memory items with an expired cleanup audit event", async () => {
    const quarantine = memoryQuarantine();
    const store = storeWithTtl(quarantine.repository, 1);
    const expired = await store.put(put(PAST));
    const fresh = await store.put(
      put(new Date(Date.now() + 60_000).toISOString()),
    );

    await expect(
      quarantine.repository.sweepExpiredItems(SWEEP_AT),
    ).resolves.toBe(1);
    await expect(
      quarantine.repository.get(expired.quarantine_id),
    ).resolves.toBeNull();
    await expect(
      quarantine.repository.get(fresh.quarantine_id),
    ).resolves.toMatchObject({ status: "pending" });
    expect(
      quarantine.repository.events.map((event) => event.event_type),
    ).toEqual(["quarantined", "quarantined", "cleanup"]);
    expect(quarantine.repository.events[2]).toMatchObject({
      quarantine_id: expired.quarantine_id,
      occurred_at: SWEEP_AT,
      details: { reason: "expired", expires_at: PAST_EXPIRY },
    });
  });

  it("excludes expired items from memory capacity and statistics", async () => {
    const quarantine = memoryQuarantine();
    await quarantine.repository.insert(
      directItem({ expires_at: PAST_EXPIRY }),
      { maxPendingItems: 1, maxEncryptedBytes: 10_000 },
    );

    // The expired item occupies no pending slot, so a fresh insert fits.
    await quarantine.repository.insert(
      directItem({ quarantine_id: "q_direct2_0123456789abcdef" }),
      { maxPendingItems: 1, maxEncryptedBytes: 10_000 },
    );
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 2,
      pending_items: 1,
      expired_items: 1,
    });

    // Once swept, the slot accounting stays consistent.
    await quarantine.repository.sweepExpiredItems(SWEEP_AT);
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 1,
      pending_items: 1,
      expired_items: 0,
    });
  });

  it("expires SQLite items end to end and excludes them from capacity", async () => {
    await withSqlite(1, async ({ repository, store }) => {
      await repository.initialize();
      const expired = await store.put(put(PAST));
      await expect(
        repository.get(expired.quarantine_id),
      ).resolves.toMatchObject({ expires_at: PAST_EXPIRY });
      await expect(repository.stats()).resolves.toMatchObject({
        pending_items: 0,
        expired_items: 1,
      });

      // Expired items do not consume pending capacity.
      const capped = new EncryptedDatabaseQuarantineStore(
        quarantineKeys().publicKey,
        repository,
        { ...DEFAULT_QUARANTINE_LIMITS, rateLimitMax: 0, maxPendingItems: 1 },
      );
      await capped.put(put(SWEEP_AT));

      await expect(repository.sweepExpiredItems(SWEEP_AT)).resolves.toBe(1);
      await expect(repository.get(expired.quarantine_id)).resolves.toBeNull();
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 1,
        pending_items: 1,
        expired_items: 0,
      });
    });
  });

  it("migrates pre-expiration databases and keeps legacy rows readable", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hmr-sqlite-retention-"));
    const path = join(directory, "quarantine.db");
    const repository = new SqliteQuarantineRepository(path);
    const store = storeWithTtl(repository, 30);
    try {
      // Build a database with the pre-expiration schema and one legacy row.
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
          dedupe_key TEXT,
          sha256 TEXT NOT NULL,
          encrypted_envelope TEXT,
          encrypted_bytes INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL,
          postpone_count INTEGER NOT NULL DEFAULT 0,
          requarantine_count INTEGER NOT NULL DEFAULT 0
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

      // The legacy row stays readable and has no expiry; it never counts as
      // expired, so it still occupies a pending slot until reviewed.
      const legacyItem = await repository.get("q_legacy_0123456789abcdef");
      expect(legacyItem).toMatchObject({ kind: "retain_request" });
      expect(legacyItem?.expires_at).toBeUndefined();
      await expect(repository.stats()).resolves.toMatchObject({
        pending_items: 1,
        expired_items: 0,
      });

      // New items receive an expiry from the configured TTL.
      const stored = await store.put(put("2026-08-01T00:00:00.000Z"));
      await expect(repository.get(stored.quarantine_id)).resolves.toMatchObject(
        { expires_at: "2026-08-31T00:00:00.000Z" },
      );

      // Reopening an already-migrated database is a no-op.
      await repository.initialize();
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 2,
        pending_items: 2,
      });
    } finally {
      await repository.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe("audit event retention", () => {
  it("prunes old memory events and appends a retention_pruned marker", async () => {
    const quarantine = memoryQuarantine();
    await quarantine.store.put(put(PAST));
    await quarantine.store.put(put("2026-07-31T00:00:00.000Z"));

    await expect(
      quarantine.repository.pruneEventsBefore(
        "2026-06-01T00:00:00.000Z",
        SWEEP_AT,
      ),
    ).resolves.toBe(1);
    expect(
      quarantine.repository.events.map((event) => event.event_type),
    ).toEqual(["quarantined", "retention_pruned"]);
    expect(quarantine.repository.events[1]).toMatchObject({
      quarantine_id: RETENTION_EVENT_QUARANTINE_ID,
      occurred_at: SWEEP_AT,
      details: { pruned_events: 1, older_than: "2026-06-01T00:00:00.000Z" },
    });

    // A run that prunes nothing leaves no marker behind.
    await expect(
      quarantine.repository.pruneEventsBefore(
        "2026-06-01T00:00:00.000Z",
        SWEEP_AT,
      ),
    ).resolves.toBe(0);
    expect(quarantine.repository.events).toHaveLength(2);
  });

  it("prunes old SQLite events with a single bounded delete plus marker", async () => {
    await withSqlite(0, async ({ path, repository, store }) => {
      await repository.initialize();
      await store.put(put(PAST));
      await store.put(put("2026-07-31T00:00:00.000Z"));
      await expect(repository.stats()).resolves.toMatchObject({
        event_count: 2,
      });

      await expect(
        repository.pruneEventsBefore("2026-06-01T00:00:00.000Z", SWEEP_AT),
      ).resolves.toBe(1);
      await expect(repository.stats()).resolves.toMatchObject({
        event_count: 2,
      });

      const check = new DatabaseSync(path, { readOnly: true });
      const rows = check
        .prepare(
          "SELECT event_type, quarantine_id, details FROM quarantine_events ORDER BY occurred_at",
        )
        .all() as Array<Record<string, unknown>>;
      check.close();
      expect(rows.map((row) => row.event_type)).toEqual([
        "quarantined",
        "retention_pruned",
      ]);
      expect(rows[1]).toMatchObject({
        quarantine_id: RETENTION_EVENT_QUARANTINE_ID,
      });
      expect(JSON.parse(String(rows[1].details))).toMatchObject({
        pruned_events: 1,
        older_than: "2026-06-01T00:00:00.000Z",
      });
    });
  });

  it("runs a full sweep: expiry removal plus retention window pruning", async () => {
    const quarantine = memoryQuarantine();
    const store = storeWithTtl(quarantine.repository, 1);
    await store.put(put(PAST));

    const result = await runQuarantineSweep(quarantine.repository, {
      eventRetentionDays: 90,
      now: () => new Date("2026-08-01T00:00:00.000Z"),
    });
    expect(result).toEqual({ expired_items: 1, pruned_events: 1 });
    // The cleanup event for the expired item is inside the retention window,
    // so it survives pruning alongside the marker.
    expect(
      quarantine.repository.events.map((event) => event.event_type),
    ).toEqual(["cleanup", "retention_pruned"]);
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 0,
      event_count: 2,
    });

    // With retention disabled, the sweep keeps every event forever.
    const keeping = memoryQuarantine();
    await keeping.store.put(put(PAST));
    const kept = await runQuarantineSweep(keeping.repository, {
      eventRetentionDays: 0,
      now: () => new Date("2026-08-01T00:00:00.000Z"),
    });
    expect(kept).toEqual({ expired_items: 0, pruned_events: 0 });
    expect(keeping.repository.events).toHaveLength(1);
  });
});

describe("sweeper lifecycle", () => {
  it("sweeps on the interval until the timer is cleared", async () => {
    vi.useFakeTimers();
    const quarantine = memoryQuarantine();
    const store = storeWithTtl(quarantine.repository, 1);
    await store.put(put(PAST));

    const timer = startQuarantineSweeper(quarantine.repository, {
      intervalSeconds: 60,
      eventRetentionDays: 0,
    });
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 0,
    });

    clearInterval(timer);
    await store.put(put(PAST));
    await vi.advanceTimersByTimeAsync(120_000);
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 1,
    });
  });

  it("logs sweep failures and keeps the timer alive", async () => {
    vi.useFakeTimers();
    const quarantine = memoryQuarantine();
    const store = storeWithTtl(quarantine.repository, 1);
    await store.put(put(PAST));
    const failing = vi
      .spyOn(quarantine.repository, "sweepExpiredItems")
      .mockRejectedValueOnce(new Error("database locked"));
    const written = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);

    const timer = startQuarantineSweeper(quarantine.repository, {
      intervalSeconds: 60,
      eventRetentionDays: 0,
    });
    await vi.advanceTimersByTimeAsync(60_000);
    expect(written).toHaveBeenCalledWith(
      "quarantine retention sweep failed: database locked\n",
    );

    // The next interval still sweeps after a failure.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(failing).toHaveBeenCalledTimes(2);
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 0,
    });
    clearInterval(timer);
    written.mockRestore();
  });

  it("skips ticks while a sweep is still in flight", async () => {
    vi.useFakeTimers();
    const quarantine = memoryQuarantine();
    let release = () => {};
    const gate = new Promise<number>((resolve) => {
      release = () => resolve(0);
    });
    const spy = vi
      .spyOn(quarantine.repository, "sweepExpiredItems")
      .mockImplementationOnce(() => gate);

    const timer = startQuarantineSweeper(quarantine.repository, {
      intervalSeconds: 60,
      eventRetentionDays: 0,
    });
    await vi.advanceTimersByTimeAsync(60_000);
    expect(spy).toHaveBeenCalledTimes(1);

    // Ticks fire while the first sweep is blocked, but none overlap it.
    await vi.advanceTimersByTimeAsync(180_000);
    expect(spy).toHaveBeenCalledTimes(1);

    release();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(spy).toHaveBeenCalledTimes(2);
    clearInterval(timer);
  });

  it("returns an unref'd timer and rejects non-positive intervals", async () => {
    const quarantine = memoryQuarantine();
    const timer = startQuarantineSweeper(quarantine.repository, {
      intervalSeconds: 3600,
      eventRetentionDays: 90,
    });
    expect(timer.hasRef()).toBe(false);
    clearInterval(timer);

    expect(() =>
      startQuarantineSweeper(quarantine.repository, {
        intervalSeconds: 0,
        eventRetentionDays: 90,
      }),
    ).toThrow("sweeper intervalSeconds must be a positive integer");
  });

  it("starts and stops the sweeper with the configured server", async () => {
    const quarantine = memoryQuarantine();
    const server = createMemoryRouterServer({
      registry: DEFAULT_REGISTRY,
      hindsight: new FakeHindsightGateway(),
      quarantineRepository: quarantine.repository,
      quarantineStore: quarantine.store,
      sweepIntervalSeconds: 60,
      eventRetentionDays: 30,
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });
});

describe("expired requarantine capacity parity", () => {
  // One live item and one expired item with maxPendingItems=1: requarantining
  // the expired item revives it next to the live one, so both backends must
  // reject it with 507 instead of double-subtracting the expired row.
  async function expectRequarantineRejected(
    repository: QuarantineRepository,
    store: EncryptedDatabaseQuarantineStore,
    tight: (
      limits: Partial<typeof DEFAULT_QUARANTINE_LIMITS>,
    ) => EncryptedDatabaseQuarantineStore,
  ) {
    const now = new Date().toISOString();
    await store.put({ ...put(PAST), dedupeKey: "expired-key" });
    await store.put({ ...put(now), dedupeKey: "live-key" });
    await expect(repository.stats()).resolves.toMatchObject({
      pending_items: 1,
    });

    // Pending-count capacity: the live item fills the single slot.
    const capped = tight({ maxPendingItems: 1 });
    await expect(
      capped.put({ ...put(now), dedupeKey: "expired-key" }),
    ).rejects.toMatchObject({
      status: 507,
      code: "quarantine_capacity_exceeded",
    });

    // Encrypted-byte capacity: the live item's bytes fill the whole budget.
    const { encrypted_bytes: liveBytes } = await repository.stats();
    const byteCapped = tight({ maxEncryptedBytes: liveBytes });
    await expect(
      byteCapped.put({ ...put(now), dedupeKey: "expired-key" }),
    ).rejects.toMatchObject({
      status: 507,
      code: "quarantine_capacity_exceeded",
    });
  }

  it("memory and sqlite backends both reject the requarantine", async () => {
    const quarantine = memoryQuarantine();
    await expectRequarantineRejected(
      quarantine.repository,
      storeWithTtl(quarantine.repository, 1),
      (limits) => storeWithTtl(quarantine.repository, 1, limits),
    );

    await withSqlite(1, async ({ repository, store }) => {
      await repository.initialize();
      await expectRequarantineRejected(repository, store, (limits) =>
        storeWithTtl(repository, 1, limits),
      );
    });
  });
});

describe("retention batching", () => {
  function batchItem(index: number): NewQuarantineItem {
    return directItem({
      quarantine_id: `q_batch_${index.toString(16).padStart(16, "0")}`,
      expires_at: PAST_EXPIRY,
    });
  }

  it("bounds each memory sweep and prune to the batch limit", async () => {
    const quarantine = memoryQuarantine();
    for (let index = 0; index < RETENTION_SWEEP_BATCH_LIMIT + 1; index++) {
      await quarantine.repository.insert(batchItem(index));
    }

    await expect(
      quarantine.repository.sweepExpiredItems(SWEEP_AT),
    ).resolves.toBe(RETENTION_SWEEP_BATCH_LIMIT);
    await expect(quarantine.repository.stats()).resolves.toMatchObject({
      total_items: 1,
    });
    // The remainder drains on the next run.
    await expect(
      quarantine.repository.sweepExpiredItems(SWEEP_AT),
    ).resolves.toBe(1);

    // The 1001 inserts logged 1001 events at PAST; pruning drains them in
    // batches too.
    await expect(
      quarantine.repository.pruneEventsBefore(
        "2026-06-01T00:00:00.000Z",
        SWEEP_AT,
      ),
    ).resolves.toBe(RETENTION_SWEEP_BATCH_LIMIT);
    await expect(
      quarantine.repository.pruneEventsBefore(
        "2026-06-01T00:00:00.000Z",
        SWEEP_AT,
      ),
    ).resolves.toBe(1);
    expect(
      quarantine.repository.events.filter(
        (event) => event.event_type === "retention_pruned",
      ),
    ).toHaveLength(2);
  });

  it("bounds each sqlite sweep and prune to the batch limit", async () => {
    await withSqlite(0, async ({ repository }) => {
      await repository.initialize();
      for (let index = 0; index < RETENTION_SWEEP_BATCH_LIMIT + 1; index++) {
        await repository.insert(batchItem(index));
      }

      await expect(repository.sweepExpiredItems(SWEEP_AT)).resolves.toBe(
        RETENTION_SWEEP_BATCH_LIMIT,
      );
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 1,
      });
      await expect(repository.sweepExpiredItems(SWEEP_AT)).resolves.toBe(1);

      // The 1001 inserts logged 1001 events at PAST; pruning drains them in
      // batches too.
      await expect(
        repository.pruneEventsBefore("2026-06-01T00:00:00.000Z", SWEEP_AT),
      ).resolves.toBe(RETENTION_SWEEP_BATCH_LIMIT);
      await expect(
        repository.pruneEventsBefore("2026-06-01T00:00:00.000Z", SWEEP_AT),
      ).resolves.toBe(1);
    });
  });
});

describe("postpone cap escalation", () => {
  it("points to TTL expiration when the postpone cap is reached", async () => {
    const quarantine = memoryQuarantine();
    const service = new QuarantineAdminService({
      repository: quarantine.repository,
      hindsight: new FakeHindsightGateway(),
      registry,
      maxPostpones: 0,
      now: () => new Date(SWEEP_AT),
    });
    const stored = await quarantine.store.put(put("2026-07-31T00:00:00.000Z"));
    await expect(service.postpone(stored.quarantine_id)).rejects.toMatchObject({
      status: 409,
      code: "postpone_limit_reached",
      message: expect.stringContaining("QUARANTINE_ITEM_TTL_DAYS"),
    });
    await expect(service.postpone(stored.quarantine_id)).rejects.toMatchObject({
      message: expect.stringContaining("expire"),
    });
  });
});
