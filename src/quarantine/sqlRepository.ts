import { gatewayErrorKind } from "../hindsightClient.js";
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
  type QuarantineEventType,
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
      const current = await requireReviewableKind(
        database,
        quarantineId,
        "recalled_memory",
        "only recalled memories can be marked reviewed",
      );
      await markRecalledReviewed(database, current, status, at);
    });
  }

  async approveRetain(
    quarantineId: string,
    at: string,
    details: Record<string, unknown>,
    operation: () => Promise<void>,
  ): Promise<void> {
    const claimed = await this.database.transaction(async (database) => {
      const current = await requireReviewableKind(
        database,
        quarantineId,
        "retain_request",
        "only retain requests can be approved into Hindsight",
      );
      await beginReview(database, current, at);
      return current;
    });
    try {
      await operation();
    } catch (error) {
      await this.interruptReview(claimed, at, error);
      throw error;
    }
    await this.database.transaction(async (database) => {
      await requireReviewInProgress(database, quarantineId, at);
      await deleteWithEvent(database, quarantineId, "approved", at, details);
    });
  }

  async rejectRecalledMemory(
    quarantineId: string,
    at: string,
    operation: () => Promise<void>,
  ): Promise<void> {
    const claimed = await this.database.transaction(async (database) => {
      const current = await requireReviewableKind(
        database,
        quarantineId,
        "recalled_memory",
        "only recalled memories can be invalidated",
      );
      await beginReview(database, current, at);
      return current;
    });
    try {
      await operation();
    } catch (error) {
      await this.interruptReview(claimed, at, error);
      throw error;
    }
    await this.database.transaction(async (database) => {
      const current = await requireReviewInProgress(database, quarantineId, at);
      await markRecalledReviewed(database, current, "reviewed_blocked", at);
    });
  }

  private async interruptReview(
    claimed: StoredQuarantineItem,
    at: string,
    error: unknown,
  ): Promise<void> {
    await this.database.transaction(async (database) => {
      const current = await findItemById(database, claimed.quarantine_id, true);
      if (
        !current ||
        current.status !== "review_in_progress" ||
        current.updated_at !== at
      ) {
        return;
      }
      const p = (index: number) => database.placeholder(index);
      await database.run(
        `UPDATE quarantine_items
         SET status = ${p(1)}, updated_at = ${p(2)}
         WHERE quarantine_id = ${p(3)}`,
        [claimed.status, at, claimed.quarantine_id],
      );
      await insertEvent(
        database,
        quarantineEvent(claimed.quarantine_id, "review_interrupted", at, {
          outcome: "restored",
          status: claimed.status,
          error_kind: gatewayErrorKind(error),
        }),
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

async function beginReview(
  database: SqlDatabase,
  current: StoredQuarantineItem,
  at: string,
): Promise<void> {
  const p = (index: number) => database.placeholder(index);
  await database.run(
    `UPDATE quarantine_items
     SET status = 'review_in_progress', updated_at = ${p(1)}
     WHERE quarantine_id = ${p(2)}`,
    [at, current.quarantine_id],
  );
}

async function requireReviewInProgress(
  database: SqlDatabase,
  quarantineId: string,
  at: string,
): Promise<StoredQuarantineItem> {
  const item = await requireItem(database, quarantineId);
  if (item.status !== "review_in_progress" || item.updated_at !== at) {
    throw new HttpError(
      409,
      "quarantine_review_changed",
      "quarantine item changed while the review action was in progress",
    );
  }
  return item;
}

async function recoverInterruptedReviews(
  database: SqlDatabase,
  at: string,
): Promise<void> {
  const interrupted = await database.all<{ quarantine_id: string }>(
    "SELECT quarantine_id FROM quarantine_items WHERE status = 'review_in_progress'",
  );
  if (interrupted.length === 0) return;
  await database.transaction(async (transaction) => {
    const p = (index: number) => transaction.placeholder(index);
    for (const row of interrupted) {
      await transaction.run(
        `UPDATE quarantine_items
         SET status = 'postponed', updated_at = ${p(1)}
         WHERE quarantine_id = ${p(2)} AND status = 'review_in_progress'`,
        [at, row.quarantine_id],
      );
      await insertEvent(
        transaction,
        quarantineEvent(row.quarantine_id, "review_interrupted", at, {
          outcome: "postponed",
          recovered: true,
        }),
      );
    }
  });
}

async function requireReviewableKind(
  database: SqlDatabase,
  quarantineId: string,
  kind: StoredQuarantineItem["kind"],
  message: string,
): Promise<StoredQuarantineItem> {
  const item = await requireReviewable(database, quarantineId);
  if (item.kind !== kind) {
    throw new HttpError(409, "invalid_review_action", message);
  }
  return item;
}

async function deleteWithEvent(
  database: SqlDatabase,
  quarantineId: string,
  eventType: QuarantineEventType,
  at: string,
  details: Record<string, unknown>,
): Promise<void> {
  await database.run(
    `DELETE FROM quarantine_items
     WHERE quarantine_id = ${database.placeholder(1)}`,
    [quarantineId],
  );
  await insertEvent(
    database,
    quarantineEvent(quarantineId, eventType, at, details),
  );
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
