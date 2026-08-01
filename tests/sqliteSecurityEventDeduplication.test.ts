import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import {
  DEFAULT_QUARANTINE_LIMITS,
  EncryptedDatabaseQuarantineStore,
} from "../src/quarantine/quarantineStore.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

describe("SQLite security event deduplication", () => {
  it("refreshes one current item and appends both audit events", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hmr-sqlite-security-"));
    const repository = new SqliteQuarantineRepository(
      join(directory, "quarantine.db"),
    );
    await repository.initialize();
    const store = new EncryptedDatabaseQuarantineStore(
      quarantineKeys().publicKey,
      repository,
      { ...DEFAULT_QUARANTINE_LIMITS, rateLimitMax: 0 },
    );

    try {
      const first = await store.put({
        timestamp: "2026-08-01T12:00:00.000Z",
        kind: "security_event",
        reason: "denied_endpoint",
        source: "http",
        dedupeKey: "GET:/unknown",
        payload: { action: "denied_endpoint", method: "GET", path: "/unknown" },
      });
      const second = await store.put({
        timestamp: "2026-08-01T12:01:00.000Z",
        kind: "security_event",
        reason: "denied_endpoint",
        source: "http",
        dedupeKey: "GET:/unknown",
        payload: { action: "denied_endpoint", method: "GET", path: "/unknown" },
      });

      expect(second.quarantine_id).toBe(first.quarantine_id);
      await expect(repository.stats()).resolves.toMatchObject({
        total_items: 1,
        pending_items: 1,
        event_count: 2,
      });
      await expect(repository.get(first.quarantine_id)).resolves.toMatchObject({
        created_at: "2026-08-01T12:01:00.000Z",
        updated_at: "2026-08-01T12:01:00.000Z",
        kind: "security_event",
      });
    } finally {
      await repository.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
});
