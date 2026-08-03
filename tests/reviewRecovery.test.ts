import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { EncryptedDatabaseQuarantineStore } from "../src/quarantine/quarantineStore.js";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

const AT = "2026-08-02T00:00:00.000Z";

interface ReviewEventRow {
  event_type: string;
  details: string;
}

describe("SQLite review action recovery", () => {
  let directory = "";

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = "";
  });

  async function setup() {
    directory = mkdtempSync(join(tmpdir(), "review-recovery-"));
    const path = join(directory, "quarantine.db");
    const repository = new SqliteQuarantineRepository(path);
    await repository.initialize();
    const keys = quarantineKeys();
    const store = new EncryptedDatabaseQuarantineStore(
      keys.publicKey,
      repository,
    );
    return { path, repository, store };
  }

  function reviewEvents(path: string): ReviewEventRow[] {
    const database = new DatabaseSync(path, { readOnly: true });
    try {
      return database
        .prepare(
          "SELECT event_type, details FROM quarantine_events ORDER BY rowid",
        )
        .all() as unknown as ReviewEventRow[];
    } finally {
      database.close();
    }
  }

  it("restores the item and audits the interruption when Hindsight fails", async () => {
    const { path, repository, store } = await setup();
    try {
      const stored = await store.put({
        timestamp: AT,
        kind: "retain_request",
        reason: "unknown_writer",
        writerId: "ops",
        source: "openclaw",
        payload: { action: "retain", writer_id: "ops", body: { items: [] } },
      });

      await expect(
        repository.approveRetain(stored.quarantine_id, AT, {}, async () => {
          throw new Error("upstream unavailable");
        }),
      ).rejects.toThrow("upstream unavailable");

      await expect(repository.get(stored.quarantine_id)).resolves.toMatchObject(
        { status: "pending" },
      );
      const events = reviewEvents(path);
      expect(events.map((event) => event.event_type)).toEqual([
        "quarantined",
        "review_interrupted",
      ]);
      expect(JSON.parse(events[1]?.details ?? "{}")).toMatchObject({
        outcome: "restored",
        status: "pending",
        error_kind: "unknown",
      });
    } finally {
      await repository.close();
    }
  });

  it("restores a postponed item to postponed when invalidation fails", async () => {
    const { repository, store } = await setup();
    try {
      const stored = await store.put({
        timestamp: AT,
        kind: "recalled_memory",
        reason: "recalled_suspicious_memory",
        writerId: "ops",
        source: "openclaw",
        sourceBank: "ops",
        sourceMemoryId: "memory-1",
        payload: {
          action: "recalled_memory",
          bank_id: "ops",
          result: { id: "memory-1", text: "blocked" },
        },
      });
      await repository.postpone(stored.quarantine_id, AT);

      await expect(
        repository.rejectRecalledMemory(
          stored.quarantine_id,
          "2026-08-02T01:00:00.000Z",
          async () => {
            throw new Error("upstream unavailable");
          },
        ),
      ).rejects.toThrow("upstream unavailable");

      await expect(repository.get(stored.quarantine_id)).resolves.toMatchObject(
        { status: "postponed", postpone_count: 1 },
      );
    } finally {
      await repository.close();
    }
  });

  it("recovers crashed in-progress reviews to postponed on initialize", async () => {
    const { path, repository, store } = await setup();
    const stored = await store.put({
      timestamp: AT,
      kind: "retain_request",
      reason: "unknown_writer",
      writerId: "ops",
      source: "openclaw",
      payload: { action: "retain", writer_id: "ops", body: { items: [] } },
    });

    let releaseOperation: (error: Error) => void = () => undefined;
    const crashed = repository.approveRetain(
      stored.quarantine_id,
      AT,
      {},
      () =>
        new Promise<void>((_resolve, reject) => {
          releaseOperation = reject;
        }),
    );
    crashed.catch(() => undefined);
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const item = await repository.get(stored.quarantine_id);
      if (item?.status === "review_in_progress") break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    await expect(repository.get(stored.quarantine_id)).resolves.toMatchObject({
      status: "review_in_progress",
    });

    const restarted = new SqliteQuarantineRepository(path);
    await restarted.initialize();
    try {
      await expect(restarted.get(stored.quarantine_id)).resolves.toMatchObject({
        status: "postponed",
      });
      const events = reviewEvents(path);
      expect(events.map((event) => event.event_type)).toEqual([
        "quarantined",
        "review_interrupted",
      ]);
      expect(JSON.parse(events[1]?.details ?? "{}")).toMatchObject({
        outcome: "postponed",
        recovered: true,
      });
    } finally {
      await restarted.close();
    }

    releaseOperation(new Error("process crashed"));
    await expect(crashed).rejects.toThrow("process crashed");
    await expect(repository.get(stored.quarantine_id)).resolves.toMatchObject({
      status: "postponed",
    });
    await repository.close();
  });

  it("fails finalization when recovery resets the item mid-review", async () => {
    const { path, repository, store } = await setup();
    const stored = await store.put({
      timestamp: AT,
      kind: "retain_request",
      reason: "unknown_writer",
      writerId: "ops",
      source: "openclaw",
      payload: { action: "retain", writer_id: "ops", body: { items: [] } },
    });

    let releaseOperation: () => void = () => undefined;
    const approval = repository.approveRetain(
      stored.quarantine_id,
      AT,
      {},
      () =>
        new Promise<void>((resolve) => {
          releaseOperation = resolve;
        }),
    );
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const item = await repository.get(stored.quarantine_id);
      if (item?.status === "review_in_progress") break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }

    const restarted = new SqliteQuarantineRepository(path);
    await restarted.initialize();
    await restarted.close();

    releaseOperation();
    await expect(approval).rejects.toMatchObject({
      status: 409,
      code: "quarantine_review_changed",
    });
    await expect(repository.get(stored.quarantine_id)).resolves.toMatchObject({
      status: "postponed",
    });
    await repository.close();
  });
});
