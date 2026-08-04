import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EncryptedDatabaseQuarantineStore } from "../src/quarantine/quarantineStore.js";
import { SqliteQuarantineRepository } from "../src/quarantine/sqliteRepository.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

describe("review claim recovery", () => {
  let directory = "";

  afterEach(() => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    directory = "";
  });

  it("does not recover a live review claimed by another repository instance", async () => {
    directory = mkdtempSync(join(tmpdir(), "active-review-"));
    const path = join(directory, "quarantine.db");
    const repository = new SqliteQuarantineRepository(path);
    await repository.initialize();
    const store = new EncryptedDatabaseQuarantineStore(
      quarantineKeys().publicKey,
      repository,
    );
    const at = new Date().toISOString();
    const stored = await store.put({
      timestamp: at,
      kind: "retain_request",
      reason: "unknown_writer",
      writerId: "ops",
      source: "openclaw",
      payload: { action: "retain", writer_id: "ops", body: { items: [] } },
    });

    let release: (error: Error) => void = () => undefined;
    const approval = repository.approveRetain(
      stored.quarantine_id,
      at,
      {},
      () =>
        new Promise<void>((_resolve, reject) => {
          release = reject;
        }),
    );
    approval.catch(() => undefined);

    for (let attempt = 0; attempt < 50; attempt += 1) {
      if ((await repository.get(stored.quarantine_id))?.status === "review_in_progress") {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }

    const second = new SqliteQuarantineRepository(path);
    await second.initialize();
    await expect(second.get(stored.quarantine_id)).resolves.toMatchObject({
      status: "review_in_progress",
    });
    await second.close();

    release(new Error("stop test operation"));
    await expect(approval).rejects.toThrow("stop test operation");
    await repository.close();
  });
});
