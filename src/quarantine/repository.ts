import { randomUUID } from "node:crypto";
import type { EncryptedQuarantineEnvelope } from "./envelopeCrypto.js";
import type {
  BankId,
  QuarantineItemSummary,
  QuarantineKind,
  QuarantineStatus,
  ReviewReason,
} from "../types.js";

export interface StoredQuarantineItem extends QuarantineItemSummary {
  encrypted: EncryptedQuarantineEnvelope | null;
  source_content_sha256?: string;
  expires_at?: string;
}

export interface NewQuarantineItem {
  quarantine_id: string;
  created_at: string;
  updated_at: string;
  kind: QuarantineKind;
  reason: ReviewReason;
  writer_id?: string;
  source?: string;
  source_bank?: BankId;
  source_memory_id?: string;
  source_content_sha256?: string;
  dedupe_key?: string;
  requarantine_count?: number;
  expires_at?: string;
  sha256: string;
  encrypted: EncryptedQuarantineEnvelope;
  status: "pending";
  postpone_count: 0;
}

export interface QuarantineCapacityLimits {
  maxPendingItems: number;
  maxEncryptedBytes: number;
}

export type QuarantineEventType =
  | "quarantined"
  | "requarantined"
  | "postponed"
  | "approved"
  | "reviewed_allowed"
  | "reviewed_blocked"
  | "review_interrupted"
  | "rejected"
  | "cleanup"
  | "retention_pruned";

export const RETENTION_EVENT_QUARANTINE_ID = "quarantine_retention";
export const RETENTION_SWEEP_BATCH_LIMIT = 1000;

export interface QuarantineEvent {
  event_id: string;
  quarantine_id: string;
  occurred_at: string;
  event_type: QuarantineEventType;
  details: Record<string, unknown>;
}

export interface QuarantineStats {
  total_items: number;
  pending_items: number;
  postponed_items: number;
  expired_items: number;
  reviewed_allowed_items: number;
  reviewed_blocked_items: number;
  encrypted_bytes: number;
  event_count: number;
}

export interface CleanupFilter {
  scope?: "pending" | "all";
  reasons?: ReviewReason[];
  older_than?: string;
}

export interface CleanupPreview {
  count: number;
  encrypted_bytes: number;
}

export interface QuarantineRepository {
  initialize(): Promise<void>;
  ping(): Promise<void>;
  close(): Promise<void>;
  insert(
    item: NewQuarantineItem,
    capacity?: QuarantineCapacityLimits,
  ): Promise<void>;
  upsertRecalledMemory(
    item: NewQuarantineItem,
    capacity?: QuarantineCapacityLimits,
  ): Promise<void>;
  upsertSecurityEvent(
    item: NewQuarantineItem,
    capacity?: QuarantineCapacityLimits,
  ): Promise<void>;
  upsertRequestItem(
    item: NewQuarantineItem,
    capacity?: QuarantineCapacityLimits,
  ): Promise<void>;
  get(quarantineId: string): Promise<StoredQuarantineItem | null>;
  listReviewable(
    limit?: number,
    offset?: number,
  ): Promise<QuarantineItemSummary[]>;
  findMemoryState(
    bankId: BankId,
    memoryId: string,
  ): Promise<StoredQuarantineItem | null>;
  postpone(quarantineId: string, at: string): Promise<StoredQuarantineItem>;
  markMemoryReviewed(
    quarantineId: string,
    status: "reviewed_allowed" | "reviewed_blocked",
    at: string,
  ): Promise<void>;
  approveRetain(
    quarantineId: string,
    at: string,
    details: Record<string, unknown>,
    operation: () => Promise<void>,
  ): Promise<void>;
  rejectRecalledMemory(
    quarantineId: string,
    at: string,
    operation: () => Promise<void>,
  ): Promise<void>;
  remove(
    quarantineId: string,
    eventType: "approved" | "rejected" | "cleanup",
    at: string,
    details?: Record<string, unknown>,
  ): Promise<void>;
  stats(): Promise<QuarantineStats>;
  previewCleanup(filter: CleanupFilter): Promise<CleanupPreview>;
  cleanup(
    filter: CleanupFilter,
    expectedCount: number,
    at: string,
  ): Promise<CleanupPreview>;
  sweepExpiredItems(at: string): Promise<number>;
  pruneEventsBefore(cutoff: string, at: string): Promise<number>;
}

export function toSummary(item: StoredQuarantineItem): QuarantineItemSummary {
  return {
    quarantine_id: item.quarantine_id,
    created_at: item.created_at,
    updated_at: item.updated_at,
    kind: item.kind,
    reason: item.reason,
    ...(item.writer_id === undefined ? {} : { writer_id: item.writer_id }),
    ...(item.source === undefined ? {} : { source: item.source }),
    ...(item.source_bank === undefined
      ? {}
      : { source_bank: item.source_bank }),
    ...(item.source_memory_id === undefined
      ? {}
      : { source_memory_id: item.source_memory_id }),
    ...(item.dedupe_key === undefined ? {} : { dedupe_key: item.dedupe_key }),
    sha256: item.sha256,
    status: item.status,
    postpone_count: item.postpone_count,
    requarantine_count: item.requarantine_count,
  };
}

export function quarantineEvent(
  quarantineId: string,
  eventType: QuarantineEventType,
  occurredAt: string,
  details: Record<string, unknown> = {},
): QuarantineEvent {
  return {
    event_id: randomUUID(),
    quarantine_id: quarantineId,
    occurred_at: occurredAt,
    event_type: eventType,
    details,
  };
}

export function parseStoredItem(
  row: Record<string, unknown>,
): StoredQuarantineItem {
  return {
    quarantine_id: String(row.quarantine_id),
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
    kind: row.kind as QuarantineKind,
    reason: row.reason as ReviewReason,
    ...(row.writer_id == null ? {} : { writer_id: String(row.writer_id) }),
    ...(row.source == null ? {} : { source: String(row.source) }),
    ...(row.source_bank == null
      ? {}
      : { source_bank: row.source_bank as BankId }),
    ...(row.source_memory_id == null
      ? {}
      : { source_memory_id: String(row.source_memory_id) }),
    ...(row.source_content_sha256 == null
      ? {}
      : { source_content_sha256: String(row.source_content_sha256) }),
    ...(row.dedupe_key == null ? {} : { dedupe_key: String(row.dedupe_key) }),
    ...(row.expires_at == null ? {} : { expires_at: String(row.expires_at) }),
    sha256: String(row.sha256),
    encrypted:
      row.encrypted_envelope == null
        ? null
        : (JSON.parse(
            String(row.encrypted_envelope),
          ) as EncryptedQuarantineEnvelope),
    status: row.status as QuarantineStatus,
    postpone_count: Number(row.postpone_count),
    requarantine_count: Number(row.requarantine_count ?? 0),
  };
}
