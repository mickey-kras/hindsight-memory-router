import { timingSafeEqual } from "node:crypto";
import type { HindsightGateway } from "../hindsightClient.js";
import { HttpError } from "../httpError.js";
import { getWriter } from "../registry.js";
import {
  BANK_IDS,
  type BankId,
  type MemoryItem,
  type RecallResult,
  type RetainBody,
  type ReviewReason,
  type WriterRegistry,
} from "../types.js";
import {
  canonicalizeDecryptedQuarantineObject,
  parseDecryptedQuarantineObject,
  sha256Hex,
  type DecryptedQuarantineObject,
} from "./envelopeCrypto.js";
import type {
  CleanupFilter,
  QuarantineRepository,
  StoredQuarantineItem,
} from "./repository.js";

export interface QuarantineAdminServiceOptions {
  repository: QuarantineRepository;
  hindsight: HindsightGateway;
  registry: WriterRegistry;
  maxPostpones?: number;
  now?: () => Date;
}

export interface ApproveBody {
  decrypted?: unknown;
}

export interface CleanupBody {
  scope?: "pending" | "all";
  reasons?: ReviewReason[];
  older_than?: string;
  dry_run?: boolean;
  expected_count?: number;
}

export class QuarantineAdminService {
  constructor(private readonly options: QuarantineAdminServiceOptions) {}

  async listQueue(limit = 100, offset = 0) {
    return {
      items: await this.options.repository.listReviewable(limit, offset),
    };
  }

  async readItem(quarantineId: string): Promise<unknown> {
    const item = await this.requireReviewable(quarantineId);
    if (!item.encrypted) {
      throw new HttpError(
        409,
        "quarantine_payload_unavailable",
        "quarantine payload is no longer available",
      );
    }
    const { encrypted, ...record } = item;
    return { record, encrypted };
  }

  async approve(
    quarantineId: string,
    body: ApproveBody,
  ): Promise<Record<string, unknown>> {
    const item = await this.requireReviewable(quarantineId);
    const decrypted = this.verifyExactDecryptedItem(item, body.decrypted);

    if (item.kind === "retain_request") {
      const payload = requireObject(decrypted.payload, "quarantine payload");
      if (payload.action !== "retain") {
        throw new HttpError(
          409,
          "invalid_quarantine_payload",
          "retain approval requires a retain request",
        );
      }
      const writerId = requireString(payload.writer_id, "writer_id");
      const writer = getWriter(this.options.registry, writerId);
      if (!writer) {
        throw new HttpError(
          409,
          "writer_not_registered",
          "register the writer before approving its original retain request",
        );
      }
      const retainBody = parseRetainBody(payload.body);
      await this.options.hindsight.retain(writer.write_bank, retainBody);
      await this.options.repository.remove(
        quarantineId,
        "approved",
        this.nowIso(),
        { writer_id: writerId, target_bank: writer.write_bank },
      );
      return {
        approved: true,
        quarantine_id: quarantineId,
        target_bank: writer.write_bank,
      };
    }

    if (item.kind === "recalled_memory") {
      const recalled = parseRecalledMemoryPayload(decrypted.payload);
      if (
        recalled.bank_id !== item.source_bank ||
        recalled.result.id !== item.source_memory_id
      ) {
        throw new HttpError(
          409,
          "quarantine_source_mismatch",
          "recalled memory source does not match quarantine metadata",
        );
      }
      await this.options.repository.markMemoryReviewed(
        quarantineId,
        "reviewed_allowed",
        this.nowIso(),
      );
      return {
        reviewed: true,
        allowed: true,
        quarantine_id: quarantineId,
        source_bank: recalled.bank_id,
        source_memory_id: recalled.result.id,
      };
    }

    throw new HttpError(
      409,
      "invalid_review_action",
      "this quarantine item cannot be approved into memory",
    );
  }

  async reject(quarantineId: string): Promise<Record<string, unknown>> {
    const item = await this.requireReviewable(quarantineId);
    if (item.kind === "recalled_memory") {
      if (!item.source_bank || !item.source_memory_id) {
        throw new HttpError(
          409,
          "quarantine_source_missing",
          "recalled memory source metadata is missing",
        );
      }
      await this.options.hindsight.invalidateMemory(
        item.source_bank,
        item.source_memory_id,
        `Rejected by memory-router quarantine review ${quarantineId}`,
      );
      await this.options.repository.markMemoryReviewed(
        quarantineId,
        "reviewed_blocked",
        this.nowIso(),
      );
      return {
        reviewed: true,
        allowed: false,
        quarantine_id: quarantineId,
        source_bank: item.source_bank,
        source_memory_id: item.source_memory_id,
      };
    }

    await this.options.repository.remove(
      quarantineId,
      "rejected",
      this.nowIso(),
    );
    return { rejected: true, quarantine_id: quarantineId };
  }

  async postpone(quarantineId: string) {
    const item = await this.requireReviewable(quarantineId);
    const maxPostpones = this.options.maxPostpones ?? 3;
    if (item.postpone_count >= maxPostpones) {
      throw new HttpError(
        409,
        "postpone_limit_reached",
        "maximum postpone count reached",
      );
    }
    const next = await this.options.repository.postpone(
      quarantineId,
      this.nowIso(),
    );
    return {
      postponed: true,
      quarantine_id: quarantineId,
      count: next.postpone_count,
    };
  }

  async stats() {
    return this.options.repository.stats();
  }

  async cleanup(body: CleanupBody) {
    const filter = parseCleanupFilter(body);
    const preview = await this.options.repository.previewCleanup(filter);
    if (body.dry_run !== false) {
      return { dry_run: true, ...preview };
    }
    const expectedCount = body.expected_count;
    if (
      typeof expectedCount !== "number" ||
      !Number.isSafeInteger(expectedCount) ||
      expectedCount < 0
    ) {
      throw new HttpError(
        400,
        "expected_count_required",
        "expected_count from a dry run is required",
      );
    }
    const result = await this.options.repository.cleanup(
      filter,
      expectedCount,
      this.nowIso(),
    );
    return { dry_run: false, ...result };
  }

  private verifyExactDecryptedItem(
    item: StoredQuarantineItem,
    value: unknown,
  ): DecryptedQuarantineObject {
    if (!item.encrypted) {
      throw new HttpError(
        409,
        "quarantine_payload_unavailable",
        "quarantine payload is no longer available",
      );
    }
    let decrypted: DecryptedQuarantineObject;
    try {
      decrypted = parseDecryptedQuarantineObject(value);
    } catch (error) {
      throw new HttpError(
        400,
        "invalid_decrypted_quarantine",
        error instanceof Error ? error.message : "invalid decrypted quarantine",
      );
    }
    const actual = sha256Hex(canonicalizeDecryptedQuarantineObject(decrypted));
    if (!sameDigest(actual, item.sha256)) {
      throw new HttpError(
        409,
        "quarantine_hash_mismatch",
        "decrypted quarantine content differs from the original item",
      );
    }
    if (
      decrypted.quarantine_id !== item.quarantine_id ||
      decrypted.created_at !== item.created_at ||
      decrypted.reason !== item.reason ||
      decrypted.writer_id !== item.writer_id ||
      decrypted.source !== item.source
    ) {
      throw new HttpError(
        409,
        "quarantine_metadata_mismatch",
        "decrypted quarantine metadata differs from the stored item",
      );
    }
    return decrypted;
  }

  private async requireReviewable(
    quarantineId: string,
  ): Promise<StoredQuarantineItem> {
    if (!/^q_[0-9A-Za-z]+_[0-9a-f]{16}$/.test(quarantineId)) {
      throw new HttpError(
        400,
        "invalid_quarantine_id",
        "invalid quarantine_id",
      );
    }
    const item = await this.options.repository.get(quarantineId);
    if (!item) {
      throw new HttpError(
        404,
        "quarantine_not_found",
        "quarantine item not found",
      );
    }
    if (item.status !== "pending" && item.status !== "postponed") {
      throw new HttpError(
        409,
        "quarantine_already_finalized",
        "quarantine item is not pending review",
      );
    }
    return item;
  }

  private nowIso(): string {
    return (this.options.now?.() ?? new Date()).toISOString();
  }
}

function parseRetainBody(value: unknown): RetainBody {
  const object = requireObject(value, "retain body");
  if (!isRetainBody(object)) {
    throw new HttpError(
      400,
      "invalid_retain_body",
      "retain body items with string content are required",
    );
  }
  return object;
}

function isRetainBody(value: Record<string, unknown>): value is RetainBody {
  return Array.isArray(value.items) && value.items.every(isMemoryItem);
}

function isMemoryItem(value: unknown): value is MemoryItem {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    "content" in value &&
    typeof value.content === "string"
  );
}

function parseRecalledMemoryPayload(value: unknown): {
  bank_id: BankId;
  result: RecallResult;
} {
  const object = requireObject(value, "recalled memory payload");
  if (object.action !== "recalled_memory") {
    throw new HttpError(
      409,
      "invalid_quarantine_payload",
      "recalled memory approval requires a recalled memory payload",
    );
  }
  const bankIdValue = requireString(object.bank_id, "bank_id");
  const bankId = BANK_IDS.find((candidate) => candidate === bankIdValue);
  if (!bankId) {
    throw new HttpError(400, "invalid_request", "bank_id is invalid");
  }
  const result = requireObject(object.result, "recalled result");
  return {
    bank_id: bankId,
    result: {
      ...result,
      id: requireString(result.id, "memory id"),
      text: requireString(result.text, "memory text"),
    },
  };
}

function parseCleanupFilter(body: CleanupBody): CleanupFilter {
  if (body.older_than && Number.isNaN(Date.parse(body.older_than))) {
    throw new HttpError(
      400,
      "invalid_cleanup_time",
      "older_than must be an ISO timestamp",
    );
  }
  return {
    scope: body.scope ?? "pending",
    ...(body.reasons?.length ? { reasons: body.reasons } : {}),
    ...(body.older_than ? { older_than: body.older_than } : {}),
  };
}

function sameDigest(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_request", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) {
    throw new HttpError(400, "invalid_request", `${label} is required`);
  }
  return value;
}
