import { HttpError } from "../httpError.js";
import type { BankId } from "../types.js";
import { MemoryReviewWorkflow } from "./memoryReviewWorkflow.js";
import {
  quarantineEvent,
  RETENTION_EVENT_QUARANTINE_ID,
  RETENTION_SWEEP_BATCH_LIMIT,
  sameCapacityScope,
  toSummary,
  type CleanupFilter,
  type CleanupPreview,
  type NewQuarantineItem,
  type QuarantineCapacityLimits,
  type QuarantineEvent,
  type QuarantineRepository,
  type QuarantineStats,
  type StoredQuarantineItem,
} from "./repository.js";

export class MemoryQuarantineRepository implements QuarantineRepository {
  readonly items = new Map<string, StoredQuarantineItem>();
  readonly events: QuarantineEvent[] = [];
  private readonly reviews = new MemoryReviewWorkflow(this.items, this.events);

  async initialize(): Promise<void> { await this.reviews.recover(new Date().toISOString()); }
  async ping(): Promise<void> {}
  async close(): Promise<void> {}

  async insert(item: NewQuarantineItem, capacity?: QuarantineCapacityLimits): Promise<void> {
    if (this.items.has(item.quarantine_id)) throw new Error("duplicate quarantine_id");
    this.store(item, null, capacity);
  }

  async upsertRecalledMemory(item: NewQuarantineItem, capacity?: QuarantineCapacityLimits): Promise<void> {
    if (!item.source_bank || !item.source_memory_id) throw new Error("recalled memory source identity is required");
    const existing = [...this.items.values()].find((entry) => entry.source_bank === item.source_bank && entry.source_memory_id === item.source_memory_id) ?? null;
    this.store(item, existing, capacity);
  }

  async upsertSecurityEvent(item: NewQuarantineItem, capacity?: QuarantineCapacityLimits): Promise<void> {
    if (item.kind !== "security_event") throw new Error("security event item is required");
    this.store(item, this.items.get(item.quarantine_id) ?? null, capacity);
  }

  async upsertRequestItem(item: NewQuarantineItem, capacity?: QuarantineCapacityLimits): Promise<void> {
    if ((item.kind !== "retain_request" && item.kind !== "recall_request") || !item.dedupe_key) throw new Error("request item dedupe identity is required");
    const existing = [...this.items.values()].find((entry) => entry.dedupe_key === item.dedupe_key) ?? null;
    if (existing && existing.status !== "pending" && existing.status !== "postponed") return;
    this.store(item, existing, capacity);
  }

  async get(quarantineId: string): Promise<StoredQuarantineItem | null> { return this.items.get(quarantineId) ?? null; }
  async listReviewable(limit = 100, offset = 0) { return [...this.items.values()].filter((item) => item.status === "pending" || item.status === "postponed").sort((a,b) => a.created_at.localeCompare(b.created_at)).slice(offset, offset + limit).map(toSummary); }
  async findMemoryState(bankId: BankId, memoryId: string) { return [...this.items.values()].find((item) => item.source_bank === bankId && item.source_memory_id === memoryId) ?? null; }

  async postpone(quarantineId: string, at: string): Promise<StoredQuarantineItem> {
    const item = this.requireReviewable(quarantineId);
    const next: StoredQuarantineItem = { ...item, status: "postponed", postpone_count: item.postpone_count + 1, updated_at: at };
    this.items.set(quarantineId, next);
    this.events.push(quarantineEvent(quarantineId, "postponed", at, { postpone_count: next.postpone_count }));
    return next;
  }

  markMemoryReviewed(quarantineId: string, status: "reviewed_allowed" | "reviewed_blocked", at: string): Promise<void> { return this.reviews.markMemoryReviewed(quarantineId, status, at); }
  approveRetain(quarantineId: string, at: string, details: Record<string, unknown>, operation: () => Promise<void>): Promise<void> { return this.reviews.approveRetain(quarantineId, at, details, operation); }
  rejectRecalledMemory(quarantineId: string, at: string, operation: () => Promise<void>): Promise<void> { return this.reviews.rejectRecalledMemory(quarantineId, at, operation); }

  async remove(quarantineId: string, eventType: "approved" | "rejected" | "cleanup", at: string, details: Record<string, unknown> = {}): Promise<void> { this.requireItem(quarantineId); this.removeCurrent(quarantineId, eventType, at, details); }

  async stats(): Promise<QuarantineStats> {
    const at = new Date().toISOString(); const values = [...this.items.values()]; const expired = values.filter((item) => isExpired(item, at)); const active = values.filter((item) => !isExpired(item, at));
    return { total_items: values.length, pending_items: active.filter((i) => i.status === "pending").length, postponed_items: active.filter((i) => i.status === "postponed").length, expired_items: expired.length, reviewed_allowed_items: active.filter((i) => i.status === "reviewed_allowed").length, reviewed_blocked_items: active.filter((i) => i.status === "reviewed_blocked").length, encrypted_bytes: active.reduce((n,i) => n + encryptedBytes(i), 0), event_count: this.events.length };
  }

  async previewCleanup(filter: CleanupFilter): Promise<CleanupPreview> { const items = this.filtered(filter); return { count: items.length, encrypted_bytes: items.reduce((n,i) => n + encryptedBytes(i), 0) }; }
  async cleanup(filter: CleanupFilter, expectedCount: number, at: string): Promise<CleanupPreview> { const preview = await this.previewCleanup(filter); if (preview.count !== expectedCount) throw new HttpError(409, "quarantine_cleanup_changed", "quarantine cleanup selection changed after preview"); for (const item of this.filtered(filter)) await this.remove(item.quarantine_id, "cleanup", at, { filter }); return preview; }
  async sweepExpiredItems(at: string): Promise<number> { const expired = [...this.items.values()].filter((item) => isExpired(item, at)).slice(0, RETENTION_SWEEP_BATCH_LIMIT); for (const item of expired) this.removeCurrent(item.quarantine_id, "cleanup", at, { reason: "expired", expires_at: item.expires_at }); return expired.length; }
  async pruneEventsBefore(cutoff: string, at: string): Promise<number> { const batch = new Set(this.events.filter((e) => e.occurred_at < cutoff).slice(0, RETENTION_SWEEP_BATCH_LIMIT)); const kept = this.events.filter((e) => !batch.has(e)); this.events.length = 0; this.events.push(...kept); if (batch.size > 0) this.events.push(quarantineEvent(RETENTION_EVENT_QUARANTINE_ID, "retention_pruned", at, { pruned_events: batch.size, older_than: cutoff })); return batch.size; }

  private store(item: NewQuarantineItem, existing: StoredQuarantineItem | null, capacity?: QuarantineCapacityLimits): void {
    this.assertCapacity(item, existing, capacity);
    const quarantineId = existing?.quarantine_id ?? item.quarantine_id;
    const requarantineCount = existing ? existing.requarantine_count + 1 : (item.requarantine_count ?? 0);
    this.items.set(quarantineId, { ...item, quarantine_id: quarantineId, requarantine_count: requarantineCount });
    this.events.push(quarantineEvent(quarantineId, existing ? "requarantined" : "quarantined", item.created_at, { kind: item.kind, reason: item.reason, sha256: item.sha256, ...(existing ? { requarantine_count: requarantineCount } : {}) }));
  }

  private assertCapacity(item: NewQuarantineItem, existing: StoredQuarantineItem | null, limits?: QuarantineCapacityLimits): void {
    if (!limits) return;
    const at = new Date().toISOString();
    const values = [...this.items.values()].filter((entry) => !isExpired(entry, at));
    const reviewable = values.filter((entry) => entry.status === "pending" || entry.status === "postponed");
    const existingLive = existing && !isExpired(existing, at) ? existing : null;
    const existingReviewable = existingLive?.status === "pending" || existingLive?.status === "postponed" ? 1 : 0;
    const existingScoped = existingReviewable && existingLive && sameCapacityScope(item, existingLive) ? 1 : 0;
    const nextPending = reviewable.length - existingReviewable + 1;
    const nextScoped = reviewable.filter((entry) => sameCapacityScope(item, entry)).length - existingScoped + 1;
    const nextEncrypted = values.reduce((n,e) => n + encryptedBytes(e), 0) - encryptedBytes(existingLive) + encryptedBytes(item);
    if (nextPending > limits.maxPendingItems || nextEncrypted > limits.maxEncryptedBytes) throw new HttpError(507, "quarantine_capacity_exceeded", "quarantine capacity is exhausted");
    if (limits.maxPendingItemsPerWriter > 0 && nextScoped > limits.maxPendingItemsPerWriter) throw new HttpError(507, "quarantine_writer_capacity_exceeded", "writer quarantine capacity is exhausted");
  }

  private filtered(filter: CleanupFilter): StoredQuarantineItem[] { return [...this.items.values()].filter((item) => item.status !== "review_in_progress" && ((filter.scope ?? "pending") !== "pending" || item.status === "pending" || item.status === "postponed") && (!filter.reasons?.length || filter.reasons.includes(item.reason)) && (!filter.older_than || item.created_at < filter.older_than)); }
  private requireItem(id: string): StoredQuarantineItem { const item = this.items.get(id); if (!item) throw new HttpError(404, "quarantine_not_found", "quarantine item not found"); return item; }
  private requireReviewable(id: string): StoredQuarantineItem { const item = this.requireItem(id); if (item.status !== "pending" && item.status !== "postponed") throw new HttpError(409, "quarantine_already_finalized", "quarantine item is not pending review"); return item; }
  private removeCurrent(id: string, eventType: "approved" | "rejected" | "cleanup", at: string, details: Record<string, unknown>): void { this.items.delete(id); this.events.push(quarantineEvent(id, eventType, at, details)); }
}

function encryptedBytes(item: NewQuarantineItem | StoredQuarantineItem | null): number { return item?.encrypted ? Buffer.byteLength(JSON.stringify(item.encrypted)) : 0; }
function isExpired(item: StoredQuarantineItem, at: string): boolean { return (item.status === "pending" || item.status === "postponed") && item.expires_at !== undefined && item.expires_at <= at; }
