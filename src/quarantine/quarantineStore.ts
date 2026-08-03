import { randomBytes } from "node:crypto";
import { sha256Hex } from "../canonicalJson.js";
import { HttpError } from "../httpError.js";
import type { BankId, QuarantineKind, ReviewReason } from "../types.js";
import {
  createEncryptedQuarantineEnvelope,
  decodePublicKey,
  type DecryptedQuarantineObject,
} from "./envelopeCrypto.js";
import {
  InMemorySlidingWindowRateLimiter,
  type QuarantineRateLimiter,
} from "./rateLimiter.js";
import type {
  NewQuarantineItem,
  QuarantineCapacityLimits,
  QuarantineRepository,
} from "./repository.js";

export interface QuarantineInput {
  timestamp: string;
  kind: QuarantineKind;
  reason: ReviewReason;
  writerId?: string;
  source?: string;
  sourceBank?: BankId;
  sourceMemoryId?: string;
  sourceContentSha256?: string;
  dedupeKey?: string;
  payload: unknown;
}

export interface QuarantineResult {
  quarantine_id: string;
  sha256: string;
}

export interface QuarantineStore {
  put(input: QuarantineInput): Promise<QuarantineResult>;
}

export interface QuarantineStoreLimits {
  maxItemBytes: number;
  maxPendingItems: number;
  maxEncryptedBytes: number;
  /** Maximum new quarantine identities per writer per window; 0 disables new-identity rate limiting (per-writer and global backstop). */
  rateLimitMax: number;
  rateLimitWindowMs: number;
  /** Global backstop: maximum new quarantine identities across all writers per window. */
  rateLimitGlobalMax: number;
  /** Safety ceiling on requarantine operations (already-tracked identities) per window. */
  requarantineOpsMax: number;
}

export const DEFAULT_QUARANTINE_LIMITS: QuarantineStoreLimits = {
  maxItemBytes: 1_048_576,
  maxPendingItems: 1_000,
  maxEncryptedBytes: 104_857_600,
  rateLimitMax: 30,
  rateLimitWindowMs: 60_000,
  rateLimitGlobalMax: 300,
  requarantineOpsMax: 1_000,
};

const GLOBAL_WRITES_BUCKET = "quarantine-writes";
const REQUARANTINE_OPS_BUCKET = "quarantine-requarantine-ops";
const UNKNOWN_WRITER_BUCKET = "unknown-writer";

export class EncryptedDatabaseQuarantineStore implements QuarantineStore {
  private readonly publicKey: string;
  private readonly capacity: QuarantineCapacityLimits;
  private readonly rateLimiter: QuarantineRateLimiter;

  constructor(
    publicKey: string,
    readonly repository: QuarantineRepository,
    private readonly limits: QuarantineStoreLimits = DEFAULT_QUARANTINE_LIMITS,
    rateLimiter?: QuarantineRateLimiter,
  ) {
    this.publicKey = decodePublicKey(publicKey);
    this.capacity = {
      maxPendingItems: limits.maxPendingItems,
      maxEncryptedBytes: limits.maxEncryptedBytes,
    };
    this.rateLimiter = rateLimiter ?? new InMemorySlidingWindowRateLimiter();
  }

  async put(input: QuarantineInput): Promise<QuarantineResult> {
    // Resolve the dedupe identity first so quota is charged per unique
    // identity event, not per raw request.
    const quarantineId = await this.resolveQuarantineId(input);
    const knownIdentity = await this.isKnownIdentity(input, quarantineId);

    const decrypted: DecryptedQuarantineObject = {
      quarantine_id: quarantineId,
      created_at: input.timestamp,
      reason: input.reason,
      ...(input.writerId === undefined ? {} : { writer_id: input.writerId }),
      ...(input.source === undefined ? {} : { source: input.source }),
      payload: input.payload,
    };
    const encrypted = createEncryptedQuarantineEnvelope(
      decrypted,
      this.publicKey,
    );
    const encryptedBytes = Buffer.byteLength(JSON.stringify(encrypted));
    if (encryptedBytes > this.limits.maxItemBytes) {
      throw new HttpError(
        413,
        "quarantine_item_too_large",
        "encrypted quarantine item exceeds configured size limit",
      );
    }

    await this.chargeRateQuota(input, knownIdentity);

    const item: NewQuarantineItem = {
      quarantine_id: quarantineId,
      created_at: input.timestamp,
      updated_at: input.timestamp,
      kind: input.kind,
      reason: input.reason,
      ...(input.writerId === undefined ? {} : { writer_id: input.writerId }),
      ...(input.source === undefined ? {} : { source: input.source }),
      ...(input.sourceBank === undefined
        ? {}
        : { source_bank: input.sourceBank }),
      ...(input.sourceMemoryId === undefined
        ? {}
        : { source_memory_id: input.sourceMemoryId }),
      ...(input.sourceContentSha256 === undefined
        ? {}
        : { source_content_sha256: input.sourceContentSha256 }),
      sha256: encrypted.sha256,
      encrypted,
      status: "pending",
      postpone_count: 0,
    };

    if (input.kind === "recalled_memory") {
      await this.repository.upsertRecalledMemory(item, this.capacity);
    } else if (input.kind === "security_event") {
      await this.repository.upsertSecurityEvent(item, this.capacity);
    } else {
      await this.repository.insert(item, this.capacity);
    }
    return { quarantine_id: quarantineId, sha256: encrypted.sha256 };
  }

  private async chargeRateQuota(
    input: QuarantineInput,
    knownIdentity: boolean,
  ): Promise<void> {
    const windowMs = this.limits.rateLimitWindowMs;
    if (knownIdentity) {
      // Requarantines of an already-tracked identity never burn request
      // quota. They are still bounded by a much higher global ops ceiling so
      // a replay loop cannot flood the database with writes.
      await this.rateLimiter.consume(REQUARANTINE_OPS_BUCKET, {
        max: this.limits.requarantineOpsMax,
        windowMs,
      });
      return;
    }
    if (this.limits.rateLimitMax <= 0) {
      // Legacy semantics: a zero per-writer limit disables new-identity rate
      // limiting entirely, including the global backstop. The requarantine
      // ops ceiling above is controlled separately.
      return;
    }
    if (await this.capacityExhausted()) {
      // New identities that cannot be stored (507) do not consume quota
      // either; the repository enforces capacity precisely inside its
      // transaction. The stats read is an approximation used only to decide
      // whether charging quota is worthwhile.
      return;
    }
    const writerBucket = `${GLOBAL_WRITES_BUCKET}:writer:${input.writerId ?? UNKNOWN_WRITER_BUCKET}`;
    await this.rateLimiter.consume(writerBucket, {
      max: this.limits.rateLimitMax,
      windowMs,
    });
    await this.rateLimiter.consume(GLOBAL_WRITES_BUCKET, {
      max: this.limits.rateLimitGlobalMax,
      windowMs,
    });
  }

  private async isKnownIdentity(
    input: QuarantineInput,
    quarantineId: string,
  ): Promise<boolean> {
    if (input.kind === "security_event" && input.dedupeKey) {
      return (await this.repository.get(quarantineId)) !== null;
    }
    if (
      input.kind === "recalled_memory" &&
      input.sourceBank !== undefined &&
      input.sourceMemoryId !== undefined
    ) {
      return (
        (await this.repository.findMemoryState(
          input.sourceBank,
          input.sourceMemoryId,
        )) !== null
      );
    }
    return false;
  }

  private async capacityExhausted(): Promise<boolean> {
    const stats = await this.repository.stats();
    return (
      stats.pending_items + stats.postponed_items >=
        this.capacity.maxPendingItems ||
      stats.encrypted_bytes >= this.capacity.maxEncryptedBytes
    );
  }

  private async resolveQuarantineId(input: QuarantineInput): Promise<string> {
    if (input.kind === "security_event" && input.dedupeKey) {
      const digest = sha256Hex(input.dedupeKey);
      return `q_security${digest.slice(0, 48)}_${digest.slice(48)}`;
    }
    if (
      input.kind === "recalled_memory" &&
      input.sourceBank !== undefined &&
      input.sourceMemoryId !== undefined
    ) {
      const digest = sha256Hex(`${input.sourceBank}:${input.sourceMemoryId}`);
      return `q_memory${digest.slice(0, 48)}_${digest.slice(48)}`;
    }
    return `q_${input.timestamp.replace(/[^0-9A-Za-z]/g, "")}_${randomBytes(8).toString("hex")}`;
  }
}
