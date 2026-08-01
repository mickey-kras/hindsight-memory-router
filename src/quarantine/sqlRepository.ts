import { HttpError } from "../httpError.js";
import type { BankId } from "../types.js";
import {
  parseStoredItem,
  quarantineEvent,
  toSummary,
  type CleanupFilter,
  type CleanupPreview,
  type NewQuarantineItem,
  type QuarantineEvent,
  type QuarantineRepository,
  type QuarantineStats,
  type StoredQuarantineItem,
} from "./repository.js";

export interface SqlDatabase {
  readonly rowLockClause: string;
  executeScript(script: string): Promise<void>;
  run(statement: string, params?: readonly unknown[]): Promise<void>;
  get<T extends Record<string, unknown>>(
    statement: string,
    params?: readonly unknown[],
  ): Promise<T | undefined>;
  all<T extends Record<string, unknown>>(
    statement: string,
    params?: readonly unknown[],
  ): Promise<T[]>;
  transaction<T>(operation: (database: SqlDatabase) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export class SqlQuarantineRepository implements QuarantineRepository {
  constructor(private readonly database: SqlDatabase) {}

  async initialize(): Promise<void> {
    await this.database.executeScript(`
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
        encrypted_bytes INTEGER NOT NULL DEFAULT 0,
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
    await this.database.close();
  }

  async insert(item: NewQuarantineItem): Promise<void> {
    await this.database.transaction(async (database) => {
      await insertItem(database, item);
      await insertEvent(
        database,
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
    await this.database.transaction(async (database) => {
      const existing = await database.get<{ quarantine_id: string }>(
        `SELECT quarantine_id FROM quarantine_items
         WHERE source_bank = ? AND source_memory_id = ?${database.rowLockClause}`,
        [item.source_bank, item.source_memory_id],
      );
      if (!existing) {
        await insertItem(database, item);
        await insertEvent(
          database,
          quarantineEvent(item.quarantine_id, "quarantined", item.created_at, {
            kind: item.kind,
            reason: item.reason,
            sha256: item.sha256,
          }),
        );
        return;
      }

      await updateItem(database, existing.quarantine_id, item);
      await insertEvent(
        database,
        quarantineEvent(
          existing.quarantine_id,
          "requarantined",
          item.created_at,
          { reason: item.reason, sha256: item.sha256 },
        ),
      );
    });
  }

  async upsertSecurityEvent(item: NewQuarantineItem): Promise<void> {
    if (item.kind !== "security_event") {
      throw new Error("security event item is required");
    }
    await this.database.transaction(async (database) => {
      const existing = await database.get<{ quarantine_id: string }>(
        `SELECT quarantine_id FROM quarantine_items
         WHERE quarantine_id = ?${database.rowLockClause}`,
        [item.quarantine_id],
      );
      if (!existing) {
        await insertItem(database, item);
        await insertEvent(
          database,
          quarantineEvent(item.quarantine_id, "quarantined", item.created_at, {
            kind: item.kind,
            reason: item.reason,
            sha256: item.sha256,
          }),
        );
        return;
      }

      await updateItem(database, item.quarantine_id, item);
      await insertEvent(
        database,
        quarantineEvent(
          item.quarantine_id,
          "requarantined",
          item.created_at,
          { reason: item.reason, sha256: item.sha256 },
        ),
      );
    });
  }

  async get(quarantineId: string): Promise<StoredQuarantineItem | null> {
    const row = await this.database.get<Record<string, unknown>>(
      "SELECT * FROM quarantine_items WHERE quarantine_id = ?",
      [quarantineId],
    );
    return row ? parseStoredItem(row) : null;
  }

  async listReviewable(limit = 100, offset = 0) {
    const rows = await this.database.all<Record<string, unknown>>(
      `SELECT * FROM quarantine_items
       WHERE status IN ('pending', 'postponed')
       ORDER BY created_at ASC LIMIT ? OFFSET ?`,
      [limit, offset],
    );
    return rows.map((row) => toSummary(parseStoredItem(row)));
  }

  async findMemoryState(bankId: BankId, memoryId: string) {
    const row = await this.database.get<Record<string, unknown>>(
      `SELECT * FROM quarantine_items
       WHERE source_bank = ? AND source_memory_id = ?`,
      [bankId, memoryId],
    );
    return row ? parseStoredItem(row) : null;
  }

  async postpone(
    quarantineId: string,
    at: string,
  ): Promise<StoredQuarantineItem> {
    return this.database.transaction(async (database) => {
      const current = await requireReviewable(database, quarantineId);
      await database.run(
        `UPDATE quarantine_items
         SET status = 'postponed', postpone_count = postpone_count + 1, updated_at = ?
         WHERE quarantine_id = ?`,
        [at, quarantineId],
      );
      await insertEvent(
        database,
        quarantineEvent(quarantineId, "postponed", at, {
          postpone_count: current.postpone_count + 1,
        }),
      );
      return requireItem(database, quarantineId);
    });
  }

  async markMemoryReviewed(
    quarantineId: string,
    status: "reviewed_allowed" | "reviewed_blocked",
    at: string,
  ): Promise<void> {
    await this.database.transaction(async (database) => {
      const current = await requireReviewable(database, quarantineId);
      if (current.kind !== "recalled_memory") {
        throw new HttpError(
          409,
          "invalid_review_action",
          "only recalled memories can be marked reviewed",
        );
      }
      await database.run(
        `UPDATE quarantine_items
         SET status = ?, encrypted_envelope = NULL, encrypted_bytes = 0, updated_at = ?
         WHERE quarantine_id = ?`,
        [status, at, quarantineId],
      );
      await insertEvent(
        database,
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
    await this.database.transaction(async (database) => {
      await requireItem(database, quarantineId);
      await database.run(
        "DELETE FROM quarantine_items WHERE quarantine_id = ?",
        [quarantineId],
      );
      await insertEvent(
        database,
        quarantineEvent(quarantineId, eventType, at, details),
      );
    });
  }

  async stats(): Promise<QuarantineStats> {
    const row = await this.database.get<Record<string, unknown>>(`
      SELECT
        COUNT(*) AS total_items,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_items,
        SUM(CASE WHEN status = 'postponed' THEN 1 ELSE 0 END) AS postponed_items,
        SUM(CASE WHEN status = 'reviewed_allowed' THEN 1 ELSE 0 END) AS reviewed_allowed_items,
        SUM(CASE WHEN status = 'reviewed_blocked' THEN 1 ELSE 0 END) AS reviewed_blocked_items,
        COALESCE(SUM(encrypted_bytes), 0) AS encrypted_bytes
      FROM quarantine_items
    `);
    const events = await this.database.get<{ event_count: number }>(
      "SELECT COUNT(*) AS event_count FROM quarantine_events",
    );
    return {
      total_items: Number(row?.total_items ?? 0),
      pending_items: Number(row?.pending_items ?? 0),
      postponed_items: Number(row?.postponed_items ?? 0),
      reviewed_allowed_items: Number(row?.reviewed_allowed_items ?? 0),
      reviewed_blocked_items: Number(row?.reviewed_blocked_items ?? 0),
      encrypted_bytes: Number(row?.encrypted_bytes ?? 0),
      event_count: Number(events?.event_count ?? 0),
    };
  }

  async previewCleanup(filter: CleanupFilter): Promise<CleanupPreview> {
    const { where, params } = cleanupWhere(filter);
    const row = await this.database.get<Record<string, unknown>>(
      `SELECT COUNT(*) AS count,
              COALESCE(SUM(encrypted_bytes), 0) AS encrypted_bytes
       FROM quarantine_items ${where}`,
      params,
    );
    return {
      count: Number(row?.count ?? 0),
      encrypted_bytes: Number(row?.encrypted_bytes ?? 0),
    };
  }

  async cleanup(
    filter: CleanupFilter,
    expectedCount: number,
    at: string,
  ): Promise<CleanupPreview> {
    return this.database.transaction(async (database) => {
      const { where, params } = cleanupWhere(filter);
      const rows = await database.all<{
        quarantine_id: string;
        encrypted_bytes: number;
      }>(
        `SELECT quarantine_id, encrypted_bytes
         FROM quarantine_items ${where}${database.rowLockClause}`,
        params,
      );
      if (rows.length !== expectedCount) {
        throw new HttpError(
          409,
          "quarantine_cleanup_changed",
          "quarantine cleanup selection changed after preview",
        );
      }
      let encryptedBytes = 0;
      for (const row of rows) {
        encryptedBytes += Number(row.encrypted_bytes);
        await database.run(
          "DELETE FROM quarantine_items WHERE quarantine_id = ?",
          [row.quarantine_id],
        );
        await insertEvent(
          database,
          quarantineEvent(row.quarantine_id, "cleanup", at, { filter }),
        );
      }
      return { count: rows.length, encrypted_bytes: encryptedBytes };
    });
  }
}

async function insertItem(
  database: SqlDatabase,
  item: NewQuarantineItem,
): Promise<void> {
  const envelope = JSON.stringify(item.encrypted);
  await database.run(
    `INSERT INTO quarantine_items (
       quarantine_id, created_at, updated_at, kind, reason, writer_id, source,
       source_bank, source_memory_id, source_content_sha256, sha256,
       encrypted_envelope, encrypted_bytes, status, postpone_count
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
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
      envelope,
      Buffer.byteLength(envelope),
      item.status,
      item.postpone_count,
    ],
  );
}

async function updateItem(
  database: SqlDatabase,
  quarantineId: string,
  item: NewQuarantineItem,
): Promise<void> {
  const envelope = JSON.stringify(item.encrypted);
  await database.run(
    `UPDATE quarantine_items SET
       created_at = ?, updated_at = ?, kind = ?, reason = ?, writer_id = ?, source = ?,
       source_bank = ?, source_memory_id = ?, source_content_sha256 = ?, sha256 = ?,
       encrypted_envelope = ?, encrypted_bytes = ?, status = 'pending', postpone_count = 0
     WHERE quarantine_id = ?`,
    [
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
      envelope,
      Buffer.byteLength(envelope),
      quarantineId,
    ],
  );
}

async function insertEvent(
  database: SqlDatabase,
  event: QuarantineEvent,
): Promise<void> {
  await database.run(
    `INSERT INTO quarantine_events
       (event_id, quarantine_id, occurred_at, event_type, details)
     VALUES (?, ?, ?, ?, ?)`,
    [
      event.event_id,
      event.quarantine_id,
      event.occurred_at,
      event.event_type,
      JSON.stringify(event.details),
    ],
  );
}

async function requireItem(
  database: SqlDatabase,
  quarantineId: string,
): Promise<StoredQuarantineItem> {
  const row = await database.get<Record<string, unknown>>(
    `SELECT * FROM quarantine_items
     WHERE quarantine_id = ?${database.rowLockClause}`,
    [quarantineId],
  );
  if (!row) {
    throw new HttpError(
      404,
      "quarantine_not_found",
      "quarantine item not found",
    );
  }
  return parseStoredItem(row);
}

async function requireReviewable(
  database: SqlDatabase,
  quarantineId: string,
): Promise<StoredQuarantineItem> {
  const item = await requireItem(database, quarantineId);
  if (item.status !== "pending" && item.status !== "postponed") {
    throw new HttpError(
      409,
      "quarantine_already_finalized",
      "quarantine item is not pending review",
    );
  }
  return item;
}

function cleanupWhere(filter: CleanupFilter): {
  where: string;
  params: string[];
} {
  const conditions: string[] = [];
  const params: string[] = [];
  if ((filter.scope ?? "pending") === "pending") {
    conditions.push("status IN ('pending', 'postponed')");
  }
  if (filter.reasons?.length) {
    conditions.push(`reason IN (${filter.reasons.map(() => "?").join(", ")})`);
    params.push(...filter.reasons);
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
