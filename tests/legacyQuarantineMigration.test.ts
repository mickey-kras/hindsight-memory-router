import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEncryptedQuarantineEnvelope } from "../src/quarantine/envelopeCrypto.js";
import { importLegacyQuarantine } from "../src/quarantine/legacyMigration.js";
import { MemoryQuarantineRepository } from "../src/quarantine/memoryRepository.js";
import { quarantineKeys } from "./quarantineTestUtils.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("legacy quarantine migration", () => {
  it("imports reviewable encrypted items and is repeat-safe", async () => {
    const directory = await mkdtemp(join(tmpdir(), "hmr-legacy-migration-"));
    directories.push(directory);
    const objectDirectory = join(directory, "objects");
    await mkdir(objectDirectory);
    const queuePath = join(directory, "review.jsonl");
    const keys = quarantineKeys();
    const pendingId = "q_20260802000000000Z_0123456789abcdef";
    const postponedId = "q_20260802000001000Z_fedcba9876543210";

    for (const [quarantineId, action] of [
      [pendingId, "retain"],
      [postponedId, "recall"],
    ] as const) {
      const encrypted = createEncryptedQuarantineEnvelope(
        {
          quarantine_id: quarantineId,
          created_at:
            quarantineId === pendingId
              ? "2026-08-02T00:00:00.000Z"
              : "2026-08-02T00:00:01.000Z",
          reason: "unknown_writer",
          writer_id: "legacy-writer",
          source: "openclaw",
          payload:
            action === "retain"
              ? {
                  action,
                  writer_id: "legacy-writer",
                  body: { items: [{ content: "legacy memory" }] },
                }
              : {
                  action,
                  writer_id: "legacy-writer",
                  body: { query: "legacy query" },
                },
        },
        keys.publicKey,
      );
      await writeFile(
        join(objectDirectory, `${quarantineId}.enc.json`),
        JSON.stringify(encrypted),
      );
    }

    await writeFile(
      queuePath,
      [
        {
          timestamp: "2026-08-02T00:00:00.000Z",
          reason: "unknown_writer",
          quarantine_id: pendingId,
          decision: "pending",
        },
        {
          timestamp: "2026-08-02T00:00:01.000Z",
          reason: "unknown_writer",
          quarantine_id: postponedId,
          decision: "postponed",
          postpone_count: 2,
          decided_at: "2026-08-02T00:05:00.000Z",
        },
        {
          timestamp: "2026-08-01T00:00:00.000Z",
          reason: "suspicious_content",
          decision: "rejected",
        },
        {
          timestamp: "2026-08-01T00:00:01.000Z",
          reason: "denied_endpoint",
          decision: "pending",
        },
      ]
        .map((record) => JSON.stringify(record))
        .join("\n") + "\n",
    );

    const repository = new MemoryQuarantineRepository();
    const first = await importLegacyQuarantine(repository, {
      queuePath,
      objectDirectory,
      privateKey: keys.privateKey,
    });
    expect(first).toEqual({
      imported: 2,
      skipped_existing: 0,
      skipped_finalized: 1,
      skipped_without_payload: 1,
    });
    await expect(repository.get(pendingId)).resolves.toMatchObject({
      kind: "retain_request",
      status: "pending",
      postpone_count: 0,
      encrypted: expect.any(Object),
    });
    await expect(repository.get(postponedId)).resolves.toMatchObject({
      kind: "recall_request",
      status: "postponed",
      postpone_count: 2,
      encrypted: expect.any(Object),
    });

    const second = await importLegacyQuarantine(repository, {
      queuePath,
      objectDirectory,
      privateKey: keys.privateKey,
    });
    expect(second).toEqual({
      imported: 0,
      skipped_existing: 2,
      skipped_finalized: 1,
      skipped_without_payload: 1,
    });
  });
});
