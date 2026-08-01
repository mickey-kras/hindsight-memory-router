import { HttpError } from "../httpError.js";
import type { BankId } from "../types.js";
import {
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

export class MemoryQuarantineRepository implements QuarantineRepository {
  readonly items = new Map<string, StoredQuarantineItem>();
  readonly events: QuarantineEvent[] = [];

  async initialize(): Promise<void> {}
  async close(): Promise<void> {}

  async insert(item: NewQuarantineItem): Promise<void> {
    if (this.items.has(item.quarantine_id))
      throw new Error("duplicate quarantine_id");
    this.items.set(item.quarantine_id, { ...item });
    this.events.push(
      quarantineEvent(item.quarantine_id, "quarantined", item.created_at, {
        kind: item.kind,
        reason: item.reason,
        sha256: item.sha256,
      }),
    );
  }

  async upsertRecalledMemory(item: NewQuarantineItem): Promise<void> {
    const existing = [...this.items.values()].find(
      (entry) =>
        entry.source_bank === item.source_bank &&
        entry.source_memory_id === item.source_memory_id,
    );
    if (!existing) return this.insert(item);
    this.items.set(existing.quarantine_id, {
      ...item,
      quarantine_id: existing.quarantine_id,
    });
    this.events.push(
      quarantineEvent(
        existing.quarantine_id,
        "requarantined",
        item.created_at,
        {
          reason: item.reason,
          sha256: item.sha256,
        },
      ),
    );
  }

  async upsertSecurityEvent(item: NewQuarantineItem): Promise<void> {
    const existing = this.items.get(item.quarantine_id);
    if (!existing) return this.insert(item);
    this.items.set(item.quarantine_id, { ...item });
    this.events.push(
      quarantineEvent(item.quarantine_id, "requarantined", item.created_at, {
        reason: item.reason,
        sha256: item.sha256,
      }),
    );
  }

  async get(quarantineId: string): Promise<StoredQuarantineItem | null> {
    return this.items.get(quarantineId) ?? null;
  }

  async listReviewable(limit = 100, offset = 0) {
    return [...this.items.values()]
      .filter(
        (item) => item.status === "pending" || item.status === "postponed",
      )
      .sort((left, right) => left.created_at.localeCompare(right.created_at))
      .slice(offset, offset + limit)
      .map(toSummary);
  }

  async findMemoryState(bankId: BankId, memoryId: string) {
    return (
      [...this.items.values()].find(
        (item) =>
          item.source_bank === bankId && item.source_memory_id === memoryId,
      ) ?? null
    );
  }

  async postpone(
    quarantineId: string,
    at: string,
  ): Promise<StoredQuarantineItem> {
    const item = this.requireReviewable(quarantineId);
    const next: StoredQuarantineItem = {
      ...item,
      status: "postponed",
      postpone_count: item.postpone_count + 1,
      updated_at: at,
    };
    this.items.set(quarantineId, next);
    this.events.push(
      quarantineEvent(quarantineId, "postponed", at, {
        postpone_count: next.postpone_count,
      }),
    );
    return next;
  }

  async markMemoryReviewed(
    quarantineId: string,
    status: "reviewed_allowed" | "reviewed_blocked",
    at: string,
  ): Promise<void> {
    const item = this.requireReviewable(quarantineId);
    if (item.kind !== "recalled_memory") {
      throw new HttpError(
        409,
        "invalid_review_action",
        "only recalled memories can be marked reviewed",
      );
    }
    this.items.set(quarantineId, {
      ...item,
      status,
      encrypted: null,
      updated_at: at,
    });
    this.events.push(
      quarantineEvent(
        quarantineId,
        status === "reviewed_allowed" ? "reviewed_allowed" : "reviewed_blocked",
        at,
        {
          source_bank: item.source_bank,
          source_memory_id: item.source_memory_id,
          source_content_sha256: item.source_content_sha256,
        },
      ),
    );
  }

  async remove(
    quarantineId: string,
    eventType: "approved" | "rejected" | "cleanup",
    at: string,
    details: Record<string, unknown> = {},
  ): Promise<void> {
    this.requireItem(quarantineId);
    this.items.delete(quarantineId);
    this.events.push(quarantineEvent(quarantineId, eventType, at, details));
  }

  async stats(): Promise<QuarantineStats> {
    const values = [...this.items.values()];
    const encryptedBytes = values.reduce(
      (total, item) =>
        total +
        (item.encrypted
          ? Buffer.byteLength(JSON.stringify(item.encrypted))
          : 0),
      0,
    );
    return {
      total_items: values.length,
      pending_items: values.filter((item) => item.status === "pending").length,
      postponed_items: values.filter((item) => item.status === "postponed")
        .length,
      reviewed_allowed_items: values.filter(
        (item) => item.status === "reviewed_allowed",
      ).length,
      reviewed_blocked_items: values.filter(
        (item) => item.status === "reviewed_blocked",
      ).length,
      encrypted_bytes: encryptedBytes,
      event_count: this.events.length,
    };
  }

  async previewCleanup(filter: CleanupFilter): Promise<CleanupPreview> {
    const items = this.filtered(filter);
    return {
      count: items.length,
      encrypted_bytes: items.reduce(
        (total, item) =>
          total +
          (item.encrypted
            ? Buffer.byteLength(JSON.stringify(item.encrypted))
            : 0),
        0,
      ),
    };
  }

  async cleanup(
    filter: CleanupFilter,
    expectedCount: number,
    at: string,
  ): Promise<CleanupPreview> {
    const preview = await this.previewCleanup(filter);
    if (preview.count !== expectedCount) {
      throw new HttpError(
        409,
        "quarantine_cleanup_changed",
        "quarantine cleanup selection changed after preview",
      );
    }
    for (const item of this.filtered(filter)) {
      await this.remove(item.quarantine_id, "cleanup", at, { filter });
    }
    return preview;
  }

  private filtered(filter: CleanupFilter): StoredQuarantineItem[] {
    return [...this.items.values()].filter((item) => {
      if (
        (filter.scope ?? "pending") === "pending" &&
        item.status !== "pending" &&
        item.status !== "postponed"
      ) {
        return false;
      }
      if (filter.reasons?.length && !filter.reasons.includes(item.reason)) {
        return false;
      }
      return !filter.older_than || item.created_at < filter.older_than;
    });
  }

  private requireItem(quarantineId: string): StoredQuarantineItem {
    const item = this.items.get(quarantineId);
    if (!item) {
      throw new HttpError(
        404,
        "quarantine_not_found",
        "quarantine item not found",
      );
    }
    return item;
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
}
