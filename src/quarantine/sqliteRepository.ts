import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { HttpError } from "../httpError.js";
import type { ReviewReason } from "../types.js";
import {
  parseStoredItem,
  quarantineEvent,
  toSummary,
  type CleanupFilter,
  type CleanupPreview,
  type NewQuarantineItem,
  type QuarantineRepository,
  type QuarantineStats,
  type StoredQuarantineItem,
} from "./repository.js";

export class SqliteQuarantineRepository implements QuarantineRepository {
  private readonly database: DatabaseSync;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.database = new DatabaseSync(path);
  }

  async initialize(): Promise<void> {
    this.database.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS quarantine_items (
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
        status TEXT NOT NULL,
        postpone_count INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_quarantine_items_review
        ON quarantine_items(status, created_at);
      CREATE INDEX IF NOT EXISTS idx_quarantine_items_reason
        ON quarantine_items(reason, status, created_at);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_items_source_memory
        ON quarantine_items(source_bank, source_memory_id)
        WHERE source_bank IS NOT NULL AND source_memory_id IS NOT NULL;
      CREATE TABLE IF NOT EXISTS quarantine_events (
        event_id TEXT PRIMARY KEY,
        quarantine_id TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        details TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_quarantine_events_item
        ON quarantine_events(quarantine_id, occurred_at);
      CREATE INDEX IF NOT EXISTS idx_quarantine_events_type
        ON quarantine_events(event_type, occurred_at);
    `);
  }

  async close(): Promise<void> {
    this.database.close();
  }

  async insert(item: NewQuarantineItem): Promise<void> {
    this.transaction(() => {
      this.insertItem(item);
      this.insertEvent(
        quarantineEvent(item.quarantine_id, "quarantined", item.created_at, {
          kind: item.kind,
          reason: item.reason,
          sha256: item.sha256,
        }),
      );
    });
  }

  async upsertRecalledMemory(item: NewQuarantineItem): Promise<void> {
    if (!item.source_bank || !item.source_memory_id) {
      throw new Error("recalled memory source identity is required");
    }
    this.transaction(() => {
      const existing = this.database
        .prepare(
          `SELECT quarantine_id FROM quarantine_items
           WHERE source_bank = ? AND source_memory_id = ?`,
        )
        .get(item.source_bank, item.source_memory_id) as
        | Record<string, unknown>
        | undefined;
      if (!existing) {
        this.insertItem(item);
        this.insertEvent(
          quarantineEvent(item.quarantine_id, "quarantined", item.created_at, {
            kind: item.kind,
            reason: item.reason,
            sha256: item.sha256,
          }),
        );
        return;
      }

      const quarantineId = String(existing.quarantine_id);
      this.database
        .prepare(
          `UPDATE quarantine_items SET
             created_at = ?, updated_at = ?, kind = ?, reason = ?, writer_id = ?, source = ?,
             source_content_sha256 = ?, sha256 = ?, encrypted_envelope = ?,
             status = 'pending', postpone_count = 0
           WHERE quarantine_id = ?`,
        )
        .run(
          item.created_at,
          item.updated_at,
          item.kind,
          item.reason,
          item.writer_id ?? null,
          item.source ?? null,
          item.source_content_sha256 ?? null,
          item.sha256,
          JSON.stringify(item.encrypted),
          quarantineId,
        );
      this.insertEvent(
        quarantineEvent(quarantineId, "requarantined", item.created_at, {
          reason: item.reason,
          sha256: item.sha256,
        }),
      );
    });
  }

  async get(quarantineId: string): Promise<StoredQuarantineItem | null> {
    const row = this.database
      .prepare("SELECT * FROM quarantine_items WHERE quarantine_id = ?")
      .get(quarantineId) as Record<string, unknown> | undefined;
    return row ? parseStoredItem(row) : null;
  }

  async listReviewable(limit = 100, offset = 0) {
    const rows = this.database
      .prepare(
        `SELECT * FROM quarantine_items
         WHERE status IN ('pending', 'postponed')
         ORDER BY created_at ASC LIMIT ? OFFSET ?`,
      )
      .all(limit, offset) as Record<string, unknown>[];
    return rows.map((row) => toSummary(parseStoredItem(row)));
  }

  async findMemoryState(bankId: string, memoryId: string) {
    const row = this.database
      .prepare(
        `SELECT * FROM quarantine_items
         WHERE source_bank = ? AND source_memory_id = ?`,
      )
      .get(bankId, memoryId) as Record<string, unknown> | undefined;
    return row ? parseStoredItem(row) : null;
  }

  async postpone(quarantineId: string, at: string): Promise<StoredQuarantineItem> {
    return this.transaction(() => {
      const current = this.requireReviewable(quarantineId);
      this.database
        .prepare(
          `UPDATE quarantine_items
           SET status = 'postponed', postpone_count = postpone_count + 1, updated_at = ?
           WHERE quarantine_id = ?`,
        )
        .run(at, quarantineId);
      this.insertEvent(
        quarantineEvent(quarantineId, "postponed", at, {
          postpone_count: current.postpone_count + 1,
        }),
      );
      return this.requireItem(quarantineId);
    });
  }

  async markMemoryReviewed(
    quarantineId: string,
    status: "reviewed_allowed" | "reviewed_blocked",
    at: string,
  ): Promise<void> {
    this.transaction(() => {
      const current = this.requireReviewable(quarantineId);
      if (current.kind !== "recalled_memory") {
        throw new HttpError(
          409,
          "invalid_review_action",
          "only recalled memories can be marked reviewed",
        );
      }
      this.database
        .prepare(
          `UPDATE quarantine_items
           SET status = ?, encrypted_envelope = NULL, updated_at = ?
           WHERE quarantine_id = ?`,
        )
        .run(status, at, quarantineId);
      this.insertEvent(
        quarantineEvent(
          quarantineId,
          status === "reviewed_allowed"
            ? "reviewed_allowed"
            : "reviewed_blocked",
          at,
          {
            source_bank: current.source_bank,
            source_memory_id: current.source_memory_id,
            source_content_sha256: current.source_content_sha256,
          },
        ),
      );
    });
  }

  async remove(
    quarantineId: string,
    eventType: "approved" | "rejected" | "cleanup",
    at: string,
    details: Record<string, unknown> = {},
  ): Promise<void> {
    this.transaction(() => {
      this.requireItem(quarantineId);
      this.database
        .prepare("DELETE FROM quarantine_items WHERE quarantine_id = ?")
        .run(quarantineId);
      this.insertEvent(quarantineEvent(quarantineId, eventType, at, details));
    });
  }

  async stats(): Promise<QuarantineStats> {
    const row = this.database
      .prepare(
        `SELECT
           COUNT(*) AS total_items,
           SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_items,
           SUM(CASE WHEN status = 'postponed' THEN 1 ELSE 0 END) AS postponed_items,
           SUM(CASE WHEN status = 'reviewed_allowed' THEN 1 ELSE 0 END) AS reviewed_allowed_items,
           SUM(CASE WHEN status = 'reviewed_blocked' THEN 1 ELSE 0 END) AS reviewed_blocked_items,
           COALESCE(SUM(LENGTH(encrypted_envelope)), 0) AS encrypted_bytes
         FROM quarantine_items`,
      )
      .get() as Record<string, unknown>;
    const events = this.database
      .prepare("SELECT COUNT(*) AS event_count FROM quarantine_events")
      .get() as Record<string, unknown>;
    return {
      total_items: Number(row.total_items),
      pending_items: Number(row.pending_items),
      postponed_items: Number(row.postponed_items),
      reviewed_allowed_items: Number(row.reviewed_allowed_items),
      reviewed_blocked_items: Number(row.reviewed_blocked_items),
      encrypted_bytes: Number(row.encrypted_bytes),
      event_count: Number(events.event_count),
    };
  }

  async previewCleanup(filter: CleanupFilter): Promise<CleanupPreview> {
    const { where, params } = cleanupWhere(filter);
    const row = this.database
      .prepare(
        `SELECT COUNT(*) AS count,
                COALESCE(SUM(LENGTH(encrypted_envelope)), 0) AS encrypted_bytes
         FROM quarantine_items ${where}`,
      )
      .get(...params) as Record<string, unknown>;
    return {
      count: Number(row.count),
      encrypted_bytes: Number(row.encrypted_bytes),
    };
  }

  async cleanup(
    filter: CleanupFilter,
    expectedCount: number,
    at: string,
  ): Promise<CleanupPreview> {
    return this.transaction(() => {
      const { where, params } = cleanupWhere(filter);
      const rows = this.database
        .prepare(
          `SELECT quarantine_id, LENGTH(encrypted_envelope) AS encrypted_bytes
           FROM quarantine_items ${where}`,
        )
        .all(...params) as Record<string, unknown>[];
      if (rows.length !== expectedCount) {
        throw new HttpError(
          409,
          "quarantine_cleanup_changed",
          "quarantine cleanup selection changed after preview",
        );
      }
      let encryptedBytes = 0;
      for (const row of rows) {
        const quarantineId = String(row.quarantine_id);
        encryptedBytes += Number(row.encrypted_bytes ?? 0);
        this.database
          .prepare("DELETE FROM quarantine_items WHERE quarantine_id = ?")
          .run(quarantineId);
        this.insertEvent(
          quarantineEvent(quarantineId, "cleanup", at, { filter }),
        );
      }
      return { count: rows.length, encrypted_bytes: encryptedBytes };
    });
  }

  private insertItem(item: NewQuarantineItem): void {
    this.database
      .prepare(
        `INSERT INTO quarantine_items (
           quarantine_id, created_at, updated_at, kind, reason, writer_id, source,
           source_bank, source_memory_id, source_content_sha256, sha256,
           encrypted_envelope, status, postpone_count
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        item.quarantine_id,
        item.created_at,
        item.updated_at,
        item.kind,
        item.reason,
        item.writer_id ?? null,
        item.source ?? null,
        item.source_bank ?? null,
        item.source_memory_id ?? null,
        item.source_content_sha256 ?? null,
        item.sha256,
        JSON.stringify(item.encrypted),
        item.status,
        item.postpone_count,
      );
  }

  private insertEvent(event: ReturnType<typeof quarantineEvent>): void {
    this.database
      .prepare(
        `INSERT INTO quarantine_events
         (event_id, quarantine_id, occurred_at, event_type, details)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        event.event_id,
        event.quarantine_id,
        event.occurred_at,
        event.event_type,
        JSON.stringify(event.details),
      );
  }

  private requireItem(quarantineId: string): StoredQuarantineItem {
    const row = this.database
      .prepare("SELECT * FROM quarantine_items WHERE quarantine_id = ?")
      .get(quarantineId) as Record<string, unknown> | undefined;
    if (!row) {
      throw new HttpError(
        404,
        "quarantine_not_found",
        "quarantine item not found",
      );
    }
    return parseStoredItem(row);
  }

  private requireReviewable(quarantineId: string): StoredQuarantineItem {
    const item = this.requireItem(quarantineId);
    if (item.status !== "pending" && item.status !== "postponed") {
      throw new HttpError(
        409,
        "quarantine_already_finalized",
        "quarantine item is not pending review",
      );
    }
    return item;
  }

  private transaction<T>(operation: () => T): T {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
}

function cleanupWhere(filter: CleanupFilter): {
  where: string;
  params: Array<string>;
} {
  const conditions: string[] = [];
  const params: string[] = [];
  if ((filter.scope ?? "pending") === "pending") {
    conditions.push("status IN ('pending', 'postponed')");
  }
  if (filter.reasons?.length) {
    conditions.push(`reason IN (${filter.reasons.map(() => "?").join(", ")})`);
    params.push(...(filter.reasons as ReviewReason[]));
  }
  if (filter.older_than) {
    conditions.push("created_at < ?");
    params.push(filter.older_than);
  }
  return {
    where: conditions.length ? `WHERE ${conditions.join(" AND ")}` : "",
    params,
  };
}
