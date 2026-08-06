import { HttpError } from "../httpError.js";
import type { BankId, QuarantineStatus } from "../types.js";
import {
  parseStoredItem,
  quarantineEvent,
  RETENTION_EVENT_QUARANTINE_ID,
  RETENTION_SWEEP_BATCH_LIMIT,
  toSummary,
  type CleanupFilter,
  type CleanupPreview,
  type NewQuarantineItem,
  type QuarantineCapacityLimits,
  type QuarantineRepository,
  type QuarantineStats,
  type StoredQuarantineItem,
} from "./repository.js";
import {
  approveRetain,
  deleteWithEvent,
  markMemoryReviewed,
  recoverInterruptedReviews,
  rejectRecalledMemory,
} from "./sqlReviewWorkflow.js";
import {
  assertCapacity,
  cleanupWhere,
  createStoredItem,
  findItemByDedupeKey,
  findItemById,
  findItemBySource,
  initializeSchema,
  insertEvent,
  readStats,
  refreshStoredItem,
  requireItem,
  requireReviewable,
} from "./sqlRepositorySupport.js";

export type SqlDialect = "postgres" | "sqlite";

export interface SqlDatabase {
  readonly dialect: SqlDialect;
  readonly rowLockClause: string;
  placeholder(index: number): string;
  acquireCapacityLock(): Promise<void>;
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

const REQUEST_ITEM_REFRESH_STATUSES = [
  "pending",
  "postponed",
] as const satisfies readonly QuarantineStatus[];

export class SqlQuarantineRepository implements QuarantineRepository {
  constructor(private readonly database: SqlDatabase) {}

  async initialize(): Promise<void> {
    await initializeSchema(this.database);
    await recoverInterruptedReviews(this.database, new Date().toISOString());
  }

  async ping(): Promise<void> {
    await this.database.get("SELECT 1 AS ready");
  }

  async close(): Promise<void> {
    await this.database.close();
  }

  async insert(
    item: NewQuarantineItem,
    capacity?: QuarantineCapacityLimits,
  ): Promise<void> {
    await this.store(item, capacity, async (database) => {
      const existing = await findItemById(database, item.quarantine_id, true);
      if (existing) throw new Error("duplicate quarantine_id");
      return null;
    });
  }

  async upsertRecalledMemory(
    item: NewQuarantineItem,
    capacity?: QuarantineCapacityLimits,
  ): Promise<void> {
    if (!item.source_bank || !item.source_memory_id) {
      throw new Error("recalled memory source identity is required");
    }
    const sourceBank = item.source_bank;
    const sourceMemoryId = item.source_memory_id;
    await this.store(item, capacity, (database) =>
      findItemBySource(database, sourceBank, sourceMemoryId, true),
    );
  }

  async upsertSecurityEvent(
    item: NewQuarantineItem,
    capacity?: QuarantineCapacityLimits,
  ): Promise<void> {
    if (item.kind !== "security_event") {
      throw new Error("security event item is required");
    }
    await this.store(item, capacity, (database) =>
      findItemById(database, item.quarantine_id, true),
    );
  }

  async upsertRequestItem(
    item: NewQuarantineItem,
    capacity?: QuarantineCapacityLimits,
  ): Promise<void> {
    if (
      (item.kind !== "retain_request" && item.kind !== "recall_request") ||
      !item.dedupe_key
    ) {
      throw new Error("request item dedupe identity is required");
    }
    const dedupeKey = item.dedupe_key;
    await this.store(
      item,
      capacity,
      (database) => findItemByDedupeKey(database, dedupeKey, true),
      REQUEST_ITEM_REFRESH_STATUSES,
    );
  }

  get(quarantineId: string): Promise<StoredQuarantineItem | null> {
    return findItemById(this.database, quarantineId);
  }

  async listReviewable(limit = 100, offset = 0) {
    const p = (index: number) => this.database.placeholder(index);
    const rows = await this.database.all<Record<string, unknown>>(
      `SELECT * FROM quarantine_items
       WHERE status IN ('pending', 'postponed')
       ORDER BY created_at ASC LIMIT ${p(1)} OFFSET ${p(2)}`,
      [limit, offset],
    );
    return rows.map((row) => toSummary(parseStoredItem(row)));
  }

  findMemoryState(bankId: BankId, memoryId: string) {
    return findItemBySource(this.database, bankId, memoryId);
  }

  async postpone(
    quarantineId: string,
    at: string,
  ): Promise<StoredQuarantineItem> {
    return this.database.transaction(async (database) => {
      const current = await requireReviewable(database, quarantineId);
      const p = (index: number) => database.placeholder(index);
      await database.run(
        `UPDATE quarantine_items
         SET status = 'postponed', postpone_count = postpone_count + 1,
             updated_at = ${p(1)}
         WHERE quarantine_id = ${p(2)}`,
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

  markMemoryReviewed(
    quarantineId: string,
    status: "reviewed_allowed" | "reviewed_blocked",
    at: string,
  ): Promise<void> {
    return markMemoryReviewed(this.database, quarantineId, status, at);
  }

  approveRetain(
    quarantineId: string,
    at: string,
    details: Record<string, unknown>,
    operation: () => Promise<void>,
  ): Promise<void> {
    return approveRetain(this.database, quarantineId, at, details, operation);
  }

  rejectRecalledMemory(
    quarantineId: string,
    at: string,
    operation: () => Promise<void>,
  ): Promise<void> {
    return rejectRecalledMemory(this.database, quarantineId, at, operation);
  }

  async remove(
    quarantineId: string,
    eventType: "approved" | "rejected" | "cleanup",
    at: string,
    details: Record<string, unknown> = {},
  ): Promise<void> {
    await this.database.transaction(async (database) => {
      await requireItem(database, quarantineId);
      await deleteWithEvent(database, quarantineId, eventType, at, details);
    });
  }

  stats(): Promise<QuarantineStats> {
    return readStats(this.database);
  }

  async previewCleanup(filter: CleanupFilter): Promise<CleanupPreview> {
    const { where, params } = cleanupWhere(this.database, filter);
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
      const { where, params } = cleanupWhere(database, filter);
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
        await deleteWithEvent(database, row.quarantine_id, "cleanup", at, {
          filter,
        });
      }
      return { count: rows.length, encrypted_bytes: encryptedBytes };
    });
  }

  async sweepExpiredItems(at: string): Promise<number> {
    return this.database.transaction(async (database) => {
      const rows = await database.all<{
        quarantine_id: string;
        expires_at: string;
      }>(
        `SELECT quarantine_id, expires_at FROM quarantine_items
         WHERE status IN ('pending', 'postponed')
           AND expires_at IS NOT NULL
           AND expires_at <= ${database.placeholder(1)}
         ORDER BY expires_at
         LIMIT ${database.placeholder(2)}${database.rowLockClause}`,
        [at, RETENTION_SWEEP_BATCH_LIMIT],
      );
      for (const row of rows) {
        await deleteWithEvent(database, row.quarantine_id, "cleanup", at, {
          reason: "expired",
          expires_at: String(row.expires_at),
        });
      }
      return rows.length;
    });
  }

  async pruneEventsBefore(cutoff: string, at: string): Promise<number> {
    return this.database.transaction(async (database) => {
      const pruned = await database.all<{ event_id: string }>(
        `DELETE FROM quarantine_events
         WHERE event_id IN (
           SELECT event_id FROM quarantine_events
           WHERE occurred_at < ${database.placeholder(1)}
           ORDER BY occurred_at
           LIMIT ${database.placeholder(2)}
         )
         RETURNING event_id`,
        [cutoff, RETENTION_SWEEP_BATCH_LIMIT],
      );
      if (pruned.length > 0) {
        await insertEvent(
          database,
          quarantineEvent(
            RETENTION_EVENT_QUARANTINE_ID,
            "retention_pruned",
            at,
            { pruned_events: pruned.length, older_than: cutoff },
          ),
        );
      }
      return pruned.length;
    });
  }

  private async store(
    item: NewQuarantineItem,
    capacity: QuarantineCapacityLimits | undefined,
    findExisting: (
      database: SqlDatabase,
    ) => Promise<StoredQuarantineItem | null>,
    refreshStatuses?: readonly QuarantineStatus[],
  ): Promise<void> {
    await this.database.transaction(async (database) => {
      await database.acquireCapacityLock();
      const existing = await findExisting(database);
      await assertCapacity(database, item, existing, capacity);
      if (existing) {
        if (
          refreshStatuses === undefined ||
          refreshStatuses.includes(existing.status)
        ) {
          await refreshStoredItem(
            database,
            existing.quarantine_id,
            item,
            existing.requarantine_count + 1,
          );
        }
      } else {
        await createStoredItem(database, item);
      }
    });
  }
}
