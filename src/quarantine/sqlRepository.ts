import { HttpError } from "../httpError.js";
import type { BankId } from "../types.js";
import {
  parseStoredItem,
  quarantineEvent,
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
  assertCapacity,
  cleanupWhere,
  createStoredItem,
  findItemById,
  findItemBySource,
  initializeSchema,
  insertEvent,
  readStats,
  refreshStoredItem,
  requireItem,
  requireReviewable,
} from "./sqlRepositorySupport.js";

export interface SqlDatabase {
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

export class SqlQuarantineRepository implements QuarantineRepository {
  constructor(private readonly database: SqlDatabase) {}

  async initialize(): Promise<void> {
    await initializeSchema(this.database);
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

  async findMemoryState(bankId: BankId, memoryId: string) {
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
      await markRecalledReviewed(database, current, status, at);
    });
  }

  async approveRetain(
    quarantineId: string,
    at: string,
    details: Record<string, unknown>,
    operation: () => Promise<void>,
  ): Promise<void> {
    await this.database.transaction(async (database) => {
      const current = await requireReviewable(database, quarantineId);
      if (current.kind !== "retain_request") {
        throw new HttpError(
          409,
          "invalid_review_action",
          "only retain requests can be approved into Hindsight",
        );
      }
      await operation();
      await database.run(
        `DELETE FROM quarantine_items
         WHERE quarantine_id = ${database.placeholder(1)}`,
        [quarantineId],
      );
      await insertEvent(
        database,
        quarantineEvent(quarantineId, "approved", at, details),
      );
    });
  }

  async rejectRecalledMemory(
    quarantineId: string,
    at: string,
    operation: () => Promise<void>,
  ): Promise<void> {
    await this.database.transaction(async (database) => {
      const current = await requireReviewable(database, quarantineId);
      if (current.kind !== "recalled_memory") {
        throw new HttpError(
          409,
          "invalid_review_action",
          "only recalled memories can be invalidated",
        );
      }
      await operation();
      await markRecalledReviewed(database, current, "reviewed_blocked", at);
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
        `DELETE FROM quarantine_items
         WHERE quarantine_id = ${database.placeholder(1)}`,
        [quarantineId],
      );
      await insertEvent(
        database,
        quarantineEvent(quarantineId, eventType, at, details),
      );
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
        await database.run(
          `DELETE FROM quarantine_items
           WHERE quarantine_id = ${database.placeholder(1)}`,
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

  private async store(
    item: NewQuarantineItem,
    capacity: QuarantineCapacityLimits | undefined,
    findExisting: (
      database: SqlDatabase,
    ) => Promise<StoredQuarantineItem | null>,
  ): Promise<void> {
    await this.database.transaction(async (database) => {
      await database.acquireCapacityLock();
      const existing = await findExisting(database);
      await assertCapacity(database, item, existing, capacity);
      if (existing) {
        await refreshStoredItem(database, existing.quarantine_id, item);
      } else {
        await createStoredItem(database, item);
      }
    });
  }
}

async function markRecalledReviewed(
  database: SqlDatabase,
  current: StoredQuarantineItem,
  status: "reviewed_allowed" | "reviewed_blocked",
  at: string,
): Promise<void> {
  const p = (index: number) => database.placeholder(index);
  await database.run(
    `UPDATE quarantine_items
     SET status = ${p(1)}, encrypted_envelope = NULL,
         encrypted_bytes = 0, updated_at = ${p(2)}
     WHERE quarantine_id = ${p(3)}`,
    [status, at, current.quarantine_id],
  );
  await insertEvent(
    database,
    quarantineEvent(
      current.quarantine_id,
      status === "reviewed_allowed" ? "reviewed_allowed" : "reviewed_blocked",
      at,
      {
        source_bank: current.source_bank,
        source_memory_id: current.source_memory_id,
        source_content_sha256: current.source_content_sha256,
      },
    ),
  );
}
