import type { HindsightGateway } from "./hindsightClient.js";
import { HttpError } from "./httpError.js";
import {
  assertSafeQuarantineId,
  deleteEncryptedQuarantineObject,
  readDecryptedQuarantineObject,
} from "./quarantineStore.js";
import { readReviewQueue, writeReviewQueue } from "./reviewQueue.js";
import { scanContent } from "./safety.js";
import { BANK_IDS, type BankId, type ReviewRecord } from "./types.js";

export interface QuarantineAdminServiceOptions {
  reviewQueuePath: string;
  quarantineObjectDir: string;
  quarantinePrivateKey?: string;
  hindsight: HindsightGateway;
  maxPostpones?: number;
  now?: () => Date;
}

export interface PromoteBody {
  target_bank?: string;
  content?: string;
  context?: string | null;
  document_id?: string | null;
  metadata?: Record<string, string> | null;
  tags?: string[] | null;
}

export class QuarantineAdminService {
  constructor(private readonly options: QuarantineAdminServiceOptions) {}

  listQueue(): { items: ReviewRecord[] } {
    return {
      items: readReviewQueue(this.options.reviewQueuePath).filter(
        (record) => record.quarantine_id && record.decision === "pending",
      ),
    };
  }

  readItem(quarantineId: string): unknown {
    const record = this.requirePendingRecord(quarantineId);
    const decrypted = readDecryptedQuarantineObject(
      this.options.quarantineObjectDir,
      quarantineId,
      this.options.quarantinePrivateKey,
    );
    return { record, item: decrypted };
  }

  reject(quarantineId: string): { rejected: true; quarantine_id: string } {
    this.requirePendingRecord(quarantineId);
    this.updateRecord(quarantineId, (record) => ({
      ...record,
      decision: "rejected",
      decided_at: this.nowIso(),
    }));
    deleteEncryptedQuarantineObject(
      this.options.quarantineObjectDir,
      quarantineId,
    );
    return { rejected: true, quarantine_id: quarantineId };
  }

  postpone(quarantineId: string): {
    postponed: true;
    quarantine_id: string;
    count: number;
  } {
    const maxPostpones = this.options.maxPostpones ?? 3;
    const record = this.requirePendingRecord(quarantineId);
    const count = record.postpone_count ?? 0;
    if (count >= maxPostpones) {
      throw new HttpError(
        409,
        "postpone_limit_reached",
        "maximum postpone count reached",
      );
    }
    const next = {
      ...record,
      decision: "pending" as const,
      postpone_count: count + 1,
      timestamp: this.nowIso(),
    };
    const records = readReviewQueue(this.options.reviewQueuePath).filter(
      (item) => item.quarantine_id !== quarantineId,
    );
    records.push(next);
    writeReviewQueue(this.options.reviewQueuePath, records);
    return { postponed: true, quarantine_id: quarantineId, count: count + 1 };
  }

  async promote(
    quarantineId: string,
    body: PromoteBody,
  ): Promise<{ promoted: true; quarantine_id: string; target_bank: BankId }> {
    this.requirePendingRecord(quarantineId);
    const targetBank = parseBankId(body.target_bank);
    if (targetBank === "quarantine") {
      throw new HttpError(
        400,
        "invalid_target_bank",
        "cannot promote to quarantine bank",
      );
    }
    const content = body.content?.trim();
    if (!content) {
      throw new HttpError(
        400,
        "approved_content_required",
        "approved content is required",
      );
    }
    const scan = scanContent(content);
    if (!scan.safe) {
      throw new HttpError(
        400,
        "approved_content_rejected",
        "approved content failed safety scan",
      );
    }

    const metadata: Record<string, string> = body.metadata
      ? { ...body.metadata }
      : {};
    metadata.router_decision = "promoted_from_quarantine";
    metadata.quarantine_id = quarantineId;

    await this.options.hindsight.retain(targetBank, {
      async: true,
      items: [
        {
          content,
          context: body.context ?? "memory-router quarantine promotion",
          document_id: body.document_id ?? `promoted:${quarantineId}`,
          metadata,
          tags: body.tags ?? ["quarantine-promoted"],
          update_mode: "append",
        },
      ],
    });

    this.updateRecord(quarantineId, (record) => ({
      ...record,
      decision: "promoted",
      decided_at: this.nowIso(),
      target_bank: targetBank,
    }));
    deleteEncryptedQuarantineObject(
      this.options.quarantineObjectDir,
      quarantineId,
    );
    return {
      promoted: true,
      quarantine_id: quarantineId,
      target_bank: targetBank,
    };
  }

  private requirePendingRecord(quarantineId: string): ReviewRecord {
    try {
      assertSafeQuarantineId(quarantineId);
    } catch {
      throw new HttpError(
        400,
        "invalid_quarantine_id",
        "invalid quarantine_id",
      );
    }
    const record = readReviewQueue(this.options.reviewQueuePath).find(
      (item) => item.quarantine_id === quarantineId,
    );
    if (!record)
      throw new HttpError(
        404,
        "quarantine_not_found",
        "quarantine item not found",
      );
    if (record.decision !== "pending") {
      throw new HttpError(
        409,
        "quarantine_already_finalized",
        "quarantine item is not pending",
      );
    }
    return record;
  }

  private updateRecord(
    quarantineId: string,
    update: (record: ReviewRecord) => ReviewRecord,
  ): void {
    const records = readReviewQueue(this.options.reviewQueuePath);
    writeReviewQueue(
      this.options.reviewQueuePath,
      records.map((record) =>
        record.quarantine_id === quarantineId ? update(record) : record,
      ),
    );
  }

  private nowIso(): string {
    return (this.options.now?.() ?? new Date()).toISOString();
  }
}

function parseBankId(value: string | undefined): BankId {
  if (!value)
    throw new HttpError(400, "target_bank_required", "target_bank is required");
  if (!BANK_IDS.includes(value as BankId))
    throw new HttpError(400, "invalid_target_bank", "invalid target_bank");
  return value as BankId;
}
