import postgres, { type Sql } from "postgres";
import { HttpError } from "../httpError.js";
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

export class PostgresQuarantineRepository implements QuarantineRepository {
  private readonly sql: Sql;

  constructor(connectionString: string) {
    this.sql = postgres(connectionString, { max: 5 });
  }

  async initialize(): Promise<void> {
    await this.sql.unsafe(`
      CREATE TABLE IF NOT EXISTS quarantine_items (
        quarantine_id TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
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
        occurred_at TIMESTAMPTZ NOT NULL,
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
    await this.sql.end();
  }

  async insert(item: NewQuarantineItem): Promise<void> {
    await this.sql.begin(async (sql) => {
      await insertItem(sql, item);
      await insertEvent(
        sql,
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
    await this.sql.begin(async (sql) => {
      const existing = await sql<Record<string, unknown>[]>`
        SELECT quarantine_id FROM quarantine_items
        WHERE source_bank = ${item.source_bank}
          AND source_memory_id = ${item.source_memory_id}
        FOR UPDATE
      `;
      if (!existing[0]) {
        await insertItem(sql, item);
        await insertEvent(
          sql,
          quarantineEvent(item.quarantine_id, "quarantined", item.created_at, {
            kind: item.kind,
            reason: item.reason,
            sha256: item.sha256,
          }),
        );
        return;
      }
      const quarantineId = String(existing[0].quarantine_id);
      await sql`
        UPDATE quarantine_items SET
          created_at = ${item.created_at},
          updated_at = ${item.updated_at},
          kind = ${item.kind},
          reason = ${item.reason},
          writer_id = ${item.writer_id ?? null},
          source = ${item.source ?? null},
          source_content_sha256 = ${item.source_content_sha256 ?? null},
          sha256 = ${item.sha256},
          encrypted_envelope = ${JSON.stringify(item.encrypted)},
          status = 'pending',
          postpone_count = 0
        WHERE quarantine_id = ${quarantineId}
      `;
      await insertEvent(
        sql,
        quarantineEvent(quarantineId, "requarantined", item.created_at, {
          reason: item.reason,
          sha256: item.sha256,
        }),
      );
    });
  }

  async get(quarantineId: string): Promise<StoredQuarantineItem | null> {
    const rows = await this.sql<Record<string, unknown>[]>`
      SELECT *, created_at::text, updated_at::text
      FROM quarantine_items WHERE quarantine_id = ${quarantineId}
    `;
    return rows[0] ? parseStoredItem(rows[0]) : null;
  }

  async listReviewable(limit = 100, offset = 0) {
    const rows = await this.sql<Record<string, unknown>[]>`
      SELECT *, created_at::text, updated_at::text
      FROM quarantine_items
      WHERE status IN ('pending', 'postponed')
      ORDER BY created_at ASC LIMIT ${limit} OFFSET ${offset}
    `;
    return rows.map((row) => toSummary(parseStoredItem(row)));
  }

  async findMemoryState(bankId: string, memoryId: string) {
    const rows = await this.sql<Record<string, unknown>[]>`
      SELECT *, created_at::text, updated_at::text
      FROM quarantine_items
      WHERE source_bank = ${bankId} AND source_memory_id = ${memoryId}
    `;
    return rows[0] ? parseStoredItem(rows[0]) : null;
  }

  async postpone(
    quarantineId: string,
    at: string,
  ): Promise<StoredQuarantineItem> {
    return this.sql.begin(async (sql) => {
      const current = await requireReviewable(sql, quarantineId);
      await sql`
        UPDATE quarantine_items SET
          status = 'postponed',
          postpone_count = postpone_count + 1,
          updated_at = ${at}
        WHERE quarantine_id = ${quarantineId}
      `;
      await insertEvent(
        sql,
        quarantineEvent(quarantineId, "postponed", at, {
          postpone_count: current.postpone_count + 1,
        }),
      );
      return requireItem(sql, quarantineId);
    });
  }

  async markMemoryReviewed(
    quarantineId: string,
    status: "reviewed_allowed" | "reviewed_blocked",
    at: string,
  ): Promise<void> {
    await this.sql.begin(async (sql) => {
      const current = await requireReviewable(sql, quarantineId);
      if (current.kind !== "recalled_memory") {
        throw new HttpError(
          409,
          "invalid_review_action",
          "only recalled memories can be marked reviewed",
        );
      }
      await sql`
        UPDATE quarantine_items SET
          status = ${status}, encrypted_envelope = NULL, updated_at = ${at}
        WHERE quarantine_id = ${quarantineId}
      `;
      await insertEvent(
        sql,
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
    await this.sql.begin(async (sql) => {
      await requireItem(sql, quarantineId);
      await sql`DELETE FROM quarantine_items WHERE quarantine_id = ${quarantineId}`;
      await insertEvent(
        sql,
        quarantineEvent(quarantineId, eventType, at, details),
      );
    });
  }

  async stats(): Promise<QuarantineStats> {
    const [row] = await this.sql<Record<string, unknown>[]>`
      SELECT
        COUNT(*)::int AS total_items,
        COUNT(*) FILTER (WHERE status = 'pending')::int AS pending_items,
        COUNT(*) FILTER (WHERE status = 'postponed')::int AS postponed_items,
        COUNT(*) FILTER (WHERE status = 'reviewed_allowed')::int AS reviewed_allowed_items,
        COUNT(*) FILTER (WHERE status = 'reviewed_blocked')::int AS reviewed_blocked_items,
        COALESCE(SUM(OCTET_LENGTH(encrypted_envelope)), 0)::bigint AS encrypted_bytes
      FROM quarantine_items
    `;
    const [events] = await this.sql<Record<string, unknown>[]>`
      SELECT COUNT(*)::int AS event_count FROM quarantine_events
    `;
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
    const { clause, params } = cleanupWhere(filter);
    const rows = await this.sql.unsafe<Record<string, unknown>[]>(
      `SELECT COUNT(*)::int AS count,
              COALESCE(SUM(OCTET_LENGTH(encrypted_envelope)), 0)::bigint AS encrypted_bytes
       FROM quarantine_items ${clause}`,
      params,
    );
    return {
      count: Number(rows[0].count),
      encrypted_bytes: Number(rows[0].encrypted_bytes),
    };
  }

  async cleanup(
    filter: CleanupFilter,
    expectedCount: number,
    at: string,
  ): Promise<CleanupPreview> {
    return this.sql.begin(async (sql) => {
      const { clause, params } = cleanupWhere(filter);
      const rows = await sql.unsafe<Record<string, unknown>[]>(
        `SELECT quarantine_id, COALESCE(OCTET_LENGTH(encrypted_envelope), 0) AS encrypted_bytes
         FROM quarantine_items ${clause} FOR UPDATE`,
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
        const quarantineId = String(row.quarantine_id);
        encryptedBytes += Number(row.encrypted_bytes);
        await sql`DELETE FROM quarantine_items WHERE quarantine_id = ${quarantineId}`;
        await insertEvent(
          sql,
          quarantineEvent(quarantineId, "cleanup", at, { filter }),
        );
      }
      return { count: rows.length, encrypted_bytes: encryptedBytes };
    });
  }
}

async function insertItem(sql: Sql, item: NewQuarantineItem): Promise<void> {
  await sql`
    INSERT INTO quarantine_items (
      quarantine_id, created_at, updated_at, kind, reason, writer_id, source,
      source_bank, source_memory_id, source_content_sha256, sha256,
      encrypted_envelope, status, postpone_count
    ) VALUES (
      ${item.quarantine_id}, ${item.created_at}, ${item.updated_at}, ${item.kind},
      ${item.reason}, ${item.writer_id ?? null}, ${item.source ?? null},
      ${item.source_bank ?? null}, ${item.source_memory_id ?? null},
      ${item.source_content_sha256 ?? null}, ${item.sha256},
      ${JSON.stringify(item.encrypted)}, ${item.status}, ${item.postpone_count}
    )
  `;
}

async function insertEvent(sql: Sql, event: QuarantineEvent): Promise<void> {
  await sql`
    INSERT INTO quarantine_events
      (event_id, quarantine_id, occurred_at, event_type, details)
    VALUES (
      ${event.event_id}, ${event.quarantine_id}, ${event.occurred_at},
      ${event.event_type}, ${JSON.stringify(event.details)}
    )
  `;
}

async function requireItem(
  sql: Sql,
  quarantineId: string,
): Promise<StoredQuarantineItem> {
  const rows = await sql<Record<string, unknown>[]>`
    SELECT *, created_at::text, updated_at::text
    FROM quarantine_items WHERE quarantine_id = ${quarantineId} FOR UPDATE
  `;
  if (!rows[0]) {
    throw new HttpError(
      404,
      "quarantine_not_found",
      "quarantine item not found",
    );
  }
  return parseStoredItem(rows[0]);
}

async function requireReviewable(
  sql: Sql,
  quarantineId: string,
): Promise<StoredQuarantineItem> {
  const item = await requireItem(sql, quarantineId);
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
  clause: string;
  params: unknown[];
} {
  const conditions: string[] = [];
  const params: unknown[] = [];
  const bind = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  if ((filter.scope ?? "pending") === "pending") {
    conditions.push("status IN ('pending', 'postponed')");
  }
  if (filter.reasons?.length) {
    conditions.push(
      `reason IN (${filter.reasons.map((reason) => bind(reason)).join(", ")})`,
    );
  }
  if (filter.older_than) {
    conditions.push(`created_at < ${bind(filter.older_than)}::timestamptz`);
  }
  return {
    clause: conditions.length ? `WHERE ${conditions.join(" AND ")}` : "",
    params,
  };
}
