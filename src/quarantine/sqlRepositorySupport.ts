import { HttpError } from "../httpError.js";
import {
  parseStoredItem,
  quarantineEvent,
  sameCapacityScope,
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
      requarantine_count INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT
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
  await ensureColumn(database, "dedupe_key", "ALTER TABLE quarantine_items ADD COLUMN dedupe_key TEXT");
  await ensureColumn(database, "requarantine_count", "ALTER TABLE quarantine_items ADD COLUMN requarantine_count INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(database, "expires_at", "ALTER TABLE quarantine_items ADD COLUMN expires_at TEXT");
  await database.executeScript(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_items_dedupe_key
      ON quarantine_items(dedupe_key)
      WHERE dedupe_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_quarantine_items_expires_at
      ON quarantine_items(expires_at)
      WHERE expires_at IS NOT NULL;
  `);
}

async function ensureColumn(database: SqlDatabase, column: "dedupe_key" | "requarantine_count" | "expires_at", alterStatement: string): Promise<void> {
  try {
    await database.get(`SELECT ${column} FROM quarantine_items WHERE 1 = 0 LIMIT 1`);
  } catch {
    await database.run(alterStatement);
  }
}

export async function findItemById(database: SqlDatabase, quarantineId: string, lock = false): Promise<StoredQuarantineItem | null> {
  const row = await database.get<Record<string, unknown>>(
    `SELECT * FROM quarantine_items
     WHERE quarantine_id = ${database.placeholder(1)}${lock ? database.rowLockClause : ""}`,
    [quarantineId],
  );
  return row ? parseStoredItem(row) : null;
}

export async function findItemBySource(database: SqlDatabase, sourceBank: string, sourceMemoryId: string, lock = false): Promise<StoredQuarantineItem | null> {
  const row = await database.get<Record<string, unknown>>(
    `SELECT * FROM quarantine_items
     WHERE source_bank = ${database.placeholder(1)}
       AND source_memory_id = ${database.placeholder(2)}${lock ? database.rowLockClause : ""}`,
    [sourceBank, sourceMemoryId],
  );
  return row ? parseStoredItem(row) : null;
}

export async function findItemByDedupeKey(database: SqlDatabase, dedupeKey: string, lock = false): Promise<StoredQuarantineItem | null> {
  const row = await database.get<Record<string, unknown>>(
    `SELECT * FROM quarantine_items
     WHERE dedupe_key = ${database.placeholder(1)}${lock ? database.rowLockClause : ""}`,
    [dedupeKey],
  );
  return row ? parseStoredItem(row) : null;
}

export async function createStoredItem(database: SqlDatabase, item: NewQuarantineItem): Promise<void> {
  await insertItem(database, item);
  await insertItemEvent(database, item, "quarantined");
}

export async function refreshStoredItem(database: SqlDatabase, quarantineId: string, item: NewQuarantineItem, requarantineCount: number): Promise<void> {
  await updateItem(database, quarantineId, item);
  await insertItemEvent(database, item, "requarantined", quarantineId, requarantineCount);
}

export async function assertCapacity(database: SqlDatabase, item: NewQuarantineItem, existing: StoredQuarantineItem | null, limits?: QuarantineCapacityLimits): Promise<void> {
  if (!limits) return;
  const at = new Date().toISOString();
  const stats = await readItemStats(database, at);
  const existingLive = existing && !isExpired(existing, at) ? existing : null;
  const existingReviewable = existingLive?.status === "pending" || existingLive?.status === "postponed" ? 1 : 0;
  const existingScopedReviewable = existingReviewable && existingLive && sameCapacityScope(item, existingLive) ? 1 : 0;
  const nextPendingItems = stats.pending_items + stats.postponed_items - existingReviewable + 1;
  const nextEncryptedBytes = stats.encrypted_bytes - encryptedBytes(existingLive) + encryptedBytes(item);

  if (nextPendingItems > limits.maxPendingItems || nextEncryptedBytes > limits.maxEncryptedBytes) {
    throw new HttpError(507, "quarantine_capacity_exceeded", "quarantine capacity is exhausted");
  }
  if (limits.maxPendingItemsPerWriter > 0) {
    const scoped = await readScopedReviewableCount(database, item, at);
    if (scoped - existingScopedReviewable + 1 > limits.maxPendingItemsPerWriter) {
      throw new HttpError(507, "quarantine_writer_capacity_exceeded", "writer quarantine capacity is exhausted");
    }
  }
}

async function readScopedReviewableCount(database: SqlDatabase, item: NewQuarantineItem, at: string): Promise<number> {
  const p = (index: number) => database.placeholder(index);
  let scope: string;
  let params: unknown[];
  if (item.reason === "unknown_writer") {
    scope = `reason = ${p(2)}`;
    params = [at, "unknown_writer"];
  } else if (item.writer_id !== undefined) {
    scope = `reason <> 'unknown_writer' AND writer_id = ${p(2)}`;
    params = [at, item.writer_id];
  } else {
    scope = `reason <> 'unknown_writer' AND writer_id IS NULL AND kind = ${p(2)}`;
    params = [at, item.kind];
  }
  const row = await database.get<{ count: number }>(
    `SELECT COUNT(*) AS count FROM quarantine_items
     WHERE status IN ('pending', 'postponed')
       AND NOT (expires_at IS NOT NULL AND expires_at <= ${p(1)})
       AND ${scope}`,
    params,
  );
  return Number(row?.count ?? 0);
}

export async function readStats(database: SqlDatabase, at = new Date().toISOString()): Promise<QuarantineStats> {
  const stats = await readItemStats(database, at);
  const events = await database.get<{ event_count: number }>("SELECT COUNT(*) AS event_count FROM quarantine_events");
  return { ...stats, event_count: Number(events?.event_count ?? 0) };
}

export async function insertEvent(database: SqlDatabase, event: QuarantineEvent): Promise<void> {
  await database.run(
    `INSERT INTO quarantine_events
       (event_id, quarantine_id, occurred_at, event_type, details)
     VALUES (${placeholders(database, 5)})`,
    [event.event_id, event.quarantine_id, event.occurred_at, event.event_type, JSON.stringify(event.details)],
  );
}

export async function requireItem(database: SqlDatabase, quarantineId: string): Promise<StoredQuarantineItem> {
  const item = await findItemById(database, quarantineId, true);
  if (!item) throw new HttpError(404, "quarantine_not_found", "quarantine item not found");
  return item;
}

export async function requireReviewable(database: SqlDatabase, quarantineId: string): Promise<StoredQuarantineItem> {
  const item = await requireItem(database, quarantineId);
  if (item.status !== "pending" && item.status !== "postponed") {
    throw new HttpError(409, "quarantine_already_finalized", "quarantine item is not pending review");
  }
  return item;
}

export function cleanupWhere(database: SqlDatabase, filter: CleanupFilter): { where: string; params: string[] } {
  const conditions: string[] = [];
  const params: string[] = [];
  let parameterIndex = 1;
  conditions.push((filter.scope ?? "pending") === "pending" ? "status IN ('pending', 'postponed')" : "status <> 'review_in_progress'");
  if (filter.reasons?.length) {
    conditions.push(`reason IN (${filter.reasons.map(() => database.placeholder(parameterIndex++)).join(", ")})`);
    params.push(...filter.reasons);
  }
  if (filter.older_than) {
    conditions.push(`created_at < ${database.placeholder(parameterIndex)}`);
    params.push(filter.older_than);
  }
  return { where: conditions.length ? `WHERE ${conditions.join(" AND ")}` : "", params };
}

function placeholders(database: SqlDatabase, count: number): string {
  return Array.from({ length: count }, (_, index) => database.placeholder(index + 1)).join(", ");
}

async function insertItem(database: SqlDatabase, item: NewQuarantineItem): Promise<void> {
  const envelope = JSON.stringify(item.encrypted);
  await database.run(
    `INSERT INTO quarantine_items (
       quarantine_id, created_at, updated_at, kind, reason, writer_id, source,
       source_bank, source_memory_id, source_content_sha256, dedupe_key, sha256,
       encrypted_envelope, encrypted_bytes, status, postpone_count,
       requarantine_count, expires_at
     ) VALUES (${placeholders(database, 18)})`,
    itemParameters(item, envelope),
  );
}

async function updateItem(database: SqlDatabase, quarantineId: string, item: NewQuarantineItem): Promise<void> {
  const p = (index: number) => database.placeholder(index);
  const envelope = JSON.stringify(item.encrypted);
  await database.run(
    `UPDATE quarantine_items SET
       created_at = ${p(1)}, updated_at = ${p(2)}, kind = ${p(3)},
       reason = ${p(4)}, writer_id = ${p(5)}, source = ${p(6)},
       source_bank = ${p(7)}, source_memory_id = ${p(8)},
       source_content_sha256 = ${p(9)}, dedupe_key = ${p(10)},
       sha256 = ${p(11)}, encrypted_envelope = ${p(12)},
       encrypted_bytes = ${p(13)}, expires_at = ${p(14)},
       status = 'pending', postpone_count = 0,
       requarantine_count = requarantine_count + 1
     WHERE quarantine_id = ${p(15)}`,
    [...itemParameters(item, envelope).slice(1, 14), item.expires_at ?? null, quarantineId],
  );
}

async function insertItemEvent(database: SqlDatabase, item: NewQuarantineItem, eventType: "quarantined" | "requarantined", quarantineId = item.quarantine_id, requarantineCount?: number): Promise<void> {
  await insertEvent(
    database,
    quarantineEvent(quarantineId, eventType, item.created_at, {
      kind: item.kind,
      reason: item.reason,
      sha256: item.sha256,
      ...(requarantineCount === undefined ? {} : { requarantine_count: requarantineCount }),
    }),
  );
}

function itemParameters(item: NewQuarantineItem, envelope: string): readonly unknown[] {
  return [
    item.quarantine_id, item.created_at, item.updated_at, item.kind, item.reason,
    item.writer_id ?? null, item.source ?? null, item.source_bank ?? null,
    item.source_memory_id ?? null, item.source_content_sha256 ?? null,
    item.dedupe_key ?? null, item.sha256, envelope, Buffer.byteLength(envelope),
    item.status, item.postpone_count, item.requarantine_count ?? 0,
    item.expires_at ?? null,
  ];
}

async function readItemStats(database: SqlDatabase, at: string): Promise<Omit<QuarantineStats, "event_count">> {
  let parameterIndex = 0;
  const expiredClause = () => `(status IN ('pending', 'postponed') AND expires_at IS NOT NULL AND expires_at <= ${database.placeholder(++parameterIndex)})`;
  const row = await database.get<Record<string, unknown>>(
    `SELECT
      COUNT(*) AS total_items,
      SUM(CASE WHEN status = 'pending' AND NOT ${expiredClause()} THEN 1 ELSE 0 END) AS pending_items,
      SUM(CASE WHEN status = 'postponed' AND NOT ${expiredClause()} THEN 1 ELSE 0 END) AS postponed_items,
      SUM(CASE WHEN ${expiredClause()} THEN 1 ELSE 0 END) AS expired_items,
      SUM(CASE WHEN status = 'reviewed_allowed' THEN 1 ELSE 0 END) AS reviewed_allowed_items,
      SUM(CASE WHEN status = 'reviewed_blocked' THEN 1 ELSE 0 END) AS reviewed_blocked_items,
      COALESCE(SUM(CASE WHEN ${expiredClause()} THEN 0 ELSE encrypted_bytes END), 0) AS encrypted_bytes
    FROM quarantine_items`,
    [at, at, at, at],
  );
  return {
    total_items: Number(row?.total_items ?? 0),
    pending_items: Number(row?.pending_items ?? 0),
    postponed_items: Number(row?.postponed_items ?? 0),
    expired_items: Number(row?.expired_items ?? 0),
    reviewed_allowed_items: Number(row?.reviewed_allowed_items ?? 0),
    reviewed_blocked_items: Number(row?.reviewed_blocked_items ?? 0),
    encrypted_bytes: Number(row?.encrypted_bytes ?? 0),
  };
}

function encryptedBytes(item: NewQuarantineItem | StoredQuarantineItem | null): number {
  return item?.encrypted ? Buffer.byteLength(JSON.stringify(item.encrypted)) : 0;
}

function isExpired(item: StoredQuarantineItem, at: string): boolean {
  return (item.status === "pending" || item.status === "postponed") && item.expires_at !== undefined && item.expires_at <= at;
}
