import { HttpError } from "../httpError.js";
import {
  parseStoredItem,
  quarantineEvent,
  type CleanupFilter,
  type NewQuarantineItem,
  type QuarantineCapacityLimits,
  type QuarantineEvent,
  type QuarantineStats,
  type StoredQuarantineItem,
} from "./repository.js";
import type { SqlDatabase } from "./sqlRepository.js";

export async function initializeSchema(database: SqlDatabase): Promise<void> {
  await database.executeScript(`
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
      dedupe_key TEXT,
      sha256 TEXT NOT NULL,
      encrypted_envelope TEXT,
      encrypted_bytes INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL,
      postpone_count INTEGER NOT NULL DEFAULT 0,
      requarantine_count INTEGER NOT NULL DEFAULT 0
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
  // Databases created before request-item deduplication lack these columns.
  // CREATE TABLE IF NOT EXISTS leaves them untouched, so add the columns when
  // a probe shows they are missing, then build the partial unique index that
  // deduplication relies on. Legacy rows keep a NULL dedupe key.
  await ensureColumn(
    database,
    "dedupe_key",
    "ALTER TABLE quarantine_items ADD COLUMN dedupe_key TEXT",
  );
  await ensureColumn(
    database,
    "requarantine_count",
    "ALTER TABLE quarantine_items ADD COLUMN requarantine_count INTEGER NOT NULL DEFAULT 0",
  );
  await database.executeScript(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_items_dedupe_key
      ON quarantine_items(dedupe_key)
      WHERE dedupe_key IS NOT NULL;
  `);
}

async function ensureColumn(
  database: SqlDatabase,
  column: "dedupe_key" | "requarantine_count",
  alterStatement: string,
): Promise<void> {
  try {
    await database.get(
      `SELECT ${column} FROM quarantine_items WHERE 1 = 0 LIMIT 1`,
    );
  } catch {
    // Both backends reject selects of unknown columns; the table itself is
    // guaranteed to exist because CREATE TABLE IF NOT EXISTS ran above.
    await database.run(alterStatement);
  }
}

export async function findItemById(
  database: SqlDatabase,
  quarantineId: string,
  lock = false,
): Promise<StoredQuarantineItem | null> {
  const row = await database.get<Record<string, unknown>>(
    `SELECT * FROM quarantine_items
     WHERE quarantine_id = ${database.placeholder(1)}${lock ? database.rowLockClause : ""}`,
    [quarantineId],
  );
  return row ? parseStoredItem(row) : null;
}

export async function findItemBySource(
  database: SqlDatabase,
  sourceBank: string,
  sourceMemoryId: string,
  lock = false,
): Promise<StoredQuarantineItem | null> {
  const row = await database.get<Record<string, unknown>>(
    `SELECT * FROM quarantine_items
     WHERE source_bank = ${database.placeholder(1)}
       AND source_memory_id = ${database.placeholder(2)}${lock ? database.rowLockClause : ""}`,
    [sourceBank, sourceMemoryId],
  );
  return row ? parseStoredItem(row) : null;
}

export async function findItemByDedupeKey(
  database: SqlDatabase,
  dedupeKey: string,
  lock = false,
): Promise<StoredQuarantineItem | null> {
  const row = await database.get<Record<string, unknown>>(
    `SELECT * FROM quarantine_items
     WHERE dedupe_key = ${database.placeholder(1)}${lock ? database.rowLockClause : ""}`,
    [dedupeKey],
  );
  return row ? parseStoredItem(row) : null;
}

export async function createStoredItem(
  database: SqlDatabase,
  item: NewQuarantineItem,
): Promise<void> {
  await insertItem(database, item);
  await insertItemEvent(database, item, "quarantined");
}

export async function refreshStoredItem(
  database: SqlDatabase,
  quarantineId: string,
  item: NewQuarantineItem,
  requarantineCount: number,
): Promise<void> {
  await updateItem(database, quarantineId, item);
  await insertItemEvent(
    database,
    item,
    "requarantined",
    quarantineId,
    requarantineCount,
  );
}

export async function assertCapacity(
  database: SqlDatabase,
  item: NewQuarantineItem,
  existing: StoredQuarantineItem | null,
  limits?: QuarantineCapacityLimits,
): Promise<void> {
  if (!limits) return;
  const stats = await readItemStats(database);
  const existingReviewable =
    existing?.status === "pending" || existing?.status === "postponed" ? 1 : 0;
  const existingEncryptedBytes = encryptedBytes(existing);
  const nextPendingItems =
    stats.pending_items + stats.postponed_items - existingReviewable + 1;
  const nextEncryptedBytes =
    stats.encrypted_bytes - existingEncryptedBytes + encryptedBytes(item);

  if (
    nextPendingItems > limits.maxPendingItems ||
    nextEncryptedBytes > limits.maxEncryptedBytes
  ) {
    throw new HttpError(
      507,
      "quarantine_capacity_exceeded",
      "quarantine capacity is exhausted",
    );
  }
}

export async function readStats(
  database: SqlDatabase,
): Promise<QuarantineStats> {
  const stats = await readItemStats(database);
  const events = await database.get<{ event_count: number }>(
    "SELECT COUNT(*) AS event_count FROM quarantine_events",
  );
  return {
    ...stats,
    event_count: Number(events?.event_count ?? 0),
  };
}

export async function insertEvent(
  database: SqlDatabase,
  event: QuarantineEvent,
): Promise<void> {
  await database.run(
    `INSERT INTO quarantine_events
       (event_id, quarantine_id, occurred_at, event_type, details)
     VALUES (${placeholders(database, 5)})`,
    [
      event.event_id,
      event.quarantine_id,
      event.occurred_at,
      event.event_type,
      JSON.stringify(event.details),
    ],
  );
}

export async function requireItem(
  database: SqlDatabase,
  quarantineId: string,
): Promise<StoredQuarantineItem> {
  const item = await findItemById(database, quarantineId, true);
  if (!item) {
    throw new HttpError(
      404,
      "quarantine_not_found",
      "quarantine item not found",
    );
  }
  return item;
}

export async function requireReviewable(
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

export function cleanupWhere(
  database: SqlDatabase,
  filter: CleanupFilter,
): { where: string; params: string[] } {
  const conditions: string[] = [];
  const params: string[] = [];
  let parameterIndex = 1;

  if ((filter.scope ?? "pending") === "pending") {
    conditions.push("status IN ('pending', 'postponed')");
  } else {
    conditions.push("status <> 'review_in_progress'");
  }
  if (filter.reasons?.length) {
    const reasonPlaceholders = filter.reasons.map(() =>
      database.placeholder(parameterIndex++),
    );
    conditions.push(`reason IN (${reasonPlaceholders.join(", ")})`);
    params.push(...filter.reasons);
  }
  if (filter.older_than) {
    conditions.push(`created_at < ${database.placeholder(parameterIndex)}`);
    params.push(filter.older_than);
  }
  return {
    where: conditions.length ? `WHERE ${conditions.join(" AND ")}` : "",
    params,
  };
}

function placeholders(database: SqlDatabase, count: number): string {
  return Array.from({ length: count }, (_, index) =>
    database.placeholder(index + 1),
  ).join(", ");
}

async function insertItem(
  database: SqlDatabase,
  item: NewQuarantineItem,
): Promise<void> {
  const envelope = JSON.stringify(item.encrypted);
  await database.run(
    `INSERT INTO quarantine_items (
       quarantine_id, created_at, updated_at, kind, reason, writer_id, source,
       source_bank, source_memory_id, source_content_sha256, dedupe_key, sha256,
       encrypted_envelope, encrypted_bytes, status, postpone_count,
       requarantine_count
     ) VALUES (${placeholders(database, 17)})`,
    itemParameters(item, envelope),
  );
}

async function updateItem(
  database: SqlDatabase,
  quarantineId: string,
  item: NewQuarantineItem,
): Promise<void> {
  const p = (index: number) => database.placeholder(index);
  const envelope = JSON.stringify(item.encrypted);
  await database.run(
    `UPDATE quarantine_items SET
       created_at = ${p(1)}, updated_at = ${p(2)}, kind = ${p(3)},
       reason = ${p(4)}, writer_id = ${p(5)}, source = ${p(6)},
       source_bank = ${p(7)}, source_memory_id = ${p(8)},
       source_content_sha256 = ${p(9)}, dedupe_key = ${p(10)},
       sha256 = ${p(11)},
       encrypted_envelope = ${p(12)}, encrypted_bytes = ${p(13)},
       status = 'pending', postpone_count = 0,
       requarantine_count = requarantine_count + 1
     WHERE quarantine_id = ${p(14)}`,
    [...itemParameters(item, envelope).slice(1, 14), quarantineId],
  );
}

async function insertItemEvent(
  database: SqlDatabase,
  item: NewQuarantineItem,
  eventType: "quarantined" | "requarantined",
  quarantineId = item.quarantine_id,
  requarantineCount?: number,
): Promise<void> {
  await insertEvent(
    database,
    quarantineEvent(quarantineId, eventType, item.created_at, {
      kind: item.kind,
      reason: item.reason,
      sha256: item.sha256,
      ...(requarantineCount === undefined
        ? {}
        : { requarantine_count: requarantineCount }),
    }),
  );
}

function itemParameters(
  item: NewQuarantineItem,
  envelope: string,
): readonly unknown[] {
  return [
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
    item.dedupe_key ?? null,
    item.sha256,
    envelope,
    Buffer.byteLength(envelope),
    item.status,
    item.postpone_count,
    item.requarantine_count ?? 0,
  ];
}

async function readItemStats(
  database: SqlDatabase,
): Promise<Omit<QuarantineStats, "event_count">> {
  const row = await database.get<Record<string, unknown>>(`
    SELECT
      COUNT(*) AS total_items,
      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_items,
      SUM(CASE WHEN status = 'postponed' THEN 1 ELSE 0 END) AS postponed_items,
      SUM(CASE WHEN status = 'reviewed_allowed' THEN 1 ELSE 0 END)
        AS reviewed_allowed_items,
      SUM(CASE WHEN status = 'reviewed_blocked' THEN 1 ELSE 0 END)
        AS reviewed_blocked_items,
      COALESCE(SUM(encrypted_bytes), 0) AS encrypted_bytes
    FROM quarantine_items
  `);
  return {
    total_items: Number(row?.total_items ?? 0),
    pending_items: Number(row?.pending_items ?? 0),
    postponed_items: Number(row?.postponed_items ?? 0),
    reviewed_allowed_items: Number(row?.reviewed_allowed_items ?? 0),
    reviewed_blocked_items: Number(row?.reviewed_blocked_items ?? 0),
    encrypted_bytes: Number(row?.encrypted_bytes ?? 0),
  };
}

function encryptedBytes(
  item: NewQuarantineItem | StoredQuarantineItem | null,
): number {
  return item?.encrypted
    ? Buffer.byteLength(JSON.stringify(item.encrypted))
    : 0;
}
