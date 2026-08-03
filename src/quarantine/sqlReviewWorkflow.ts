import { gatewayErrorKind } from "../hindsightClient.js";
import { HttpError } from "../httpError.js";
import {
  parseStoredItem,
  quarantineEvent,
  type QuarantineEventType,
  type StoredQuarantineItem,
} from "./repository.js";
import type { SqlDatabase } from "./sqlRepository.js";
import {
  findItemById,
  insertEvent,
  requireItem,
  requireReviewable,
} from "./sqlRepositorySupport.js";

export async function recoverInterruptedReviews(
  database: SqlDatabase,
  at: string,
): Promise<void> {
  await database.transaction(async (transaction) => {
    const rows = await transaction.all<Record<string, unknown>>(
      `SELECT * FROM quarantine_items
       WHERE status = 'review_in_progress'${transaction.rowLockClause}`,
    );
    for (const row of rows) {
      const item = parseStoredItem(row);
      const p = (index: number) => transaction.placeholder(index);
      await transaction.run(
        `UPDATE quarantine_items
         SET status = 'postponed', updated_at = ${p(1)}
         WHERE quarantine_id = ${p(2)} AND status = 'review_in_progress'`,
        [at, item.quarantine_id],
      );
      await insertEvent(
        transaction,
        quarantineEvent(item.quarantine_id, "review_interrupted", at, {
          outcome: "postponed",
          recovered: true,
        }),
      );
    }
  });
}

export async function markMemoryReviewed(
  database: SqlDatabase,
  quarantineId: string,
  status: "reviewed_allowed" | "reviewed_blocked",
  at: string,
): Promise<void> {
  await database.transaction(async (transaction) => {
    const current = await requireReviewableKind(
      transaction,
      quarantineId,
      "recalled_memory",
      "only recalled memories can be marked reviewed",
    );
    await markRecalledReviewed(transaction, current, status, at);
  });
}

export async function approveRetain(
  database: SqlDatabase,
  quarantineId: string,
  at: string,
  details: Record<string, unknown>,
  operation: () => Promise<void>,
): Promise<void> {
  const claimed = await claimReview(
    database,
    quarantineId,
    "retain_request",
    "only retain requests can be approved into Hindsight",
    at,
  );
  try {
    await operation();
  } catch (error) {
    await interruptReview(database, claimed, at, error);
    throw error;
  }
  await database.transaction(async (transaction) => {
    await requireReviewInProgress(transaction, quarantineId, at);
    await deleteWithEvent(transaction, quarantineId, "approved", at, details);
  });
}

export async function rejectRecalledMemory(
  database: SqlDatabase,
  quarantineId: string,
  at: string,
  operation: () => Promise<void>,
): Promise<void> {
  const claimed = await claimReview(
    database,
    quarantineId,
    "recalled_memory",
    "only recalled memories can be invalidated",
    at,
  );
  try {
    await operation();
  } catch (error) {
    await interruptReview(database, claimed, at, error);
    throw error;
  }
  await database.transaction(async (transaction) => {
    const current = await requireReviewInProgress(
      transaction,
      quarantineId,
      at,
    );
    await markRecalledReviewed(transaction, current, "reviewed_blocked", at);
  });
}

async function claimReview(
  database: SqlDatabase,
  quarantineId: string,
  kind: StoredQuarantineItem["kind"],
  message: string,
  at: string,
): Promise<StoredQuarantineItem> {
  return database.transaction(async (transaction) => {
    const current = await requireReviewableKind(
      transaction,
      quarantineId,
      kind,
      message,
    );
    const p = (index: number) => transaction.placeholder(index);
    await transaction.run(
      `UPDATE quarantine_items
       SET status = 'review_in_progress', updated_at = ${p(1)}
       WHERE quarantine_id = ${p(2)}`,
      [at, current.quarantine_id],
    );
    return current;
  });
}

async function interruptReview(
  database: SqlDatabase,
  claimed: StoredQuarantineItem,
  at: string,
  error: unknown,
): Promise<void> {
  await database.transaction(async (transaction) => {
    const current = await findItemById(transaction, claimed.quarantine_id, true);
    if (
      !current ||
      current.status !== "review_in_progress" ||
      current.updated_at !== at
    ) {
      return;
    }
    const p = (index: number) => transaction.placeholder(index);
    await transaction.run(
      `UPDATE quarantine_items
       SET status = ${p(1)}, updated_at = ${p(2)}
       WHERE quarantine_id = ${p(3)}`,
      [claimed.status, at, claimed.quarantine_id],
    );
    await insertEvent(
      transaction,
      quarantineEvent(claimed.quarantine_id, "review_interrupted", at, {
        outcome: "restored",
        status: claimed.status,
        error_kind: gatewayErrorKind(error),
      }),
    );
  });
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
      "quarantine item changed while review was in progress",
    );
  }
  return item;
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

export async function deleteWithEvent(
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
