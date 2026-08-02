import { randomBytes } from "node:crypto";
import { sha256Hex } from "../canonicalJson.js";
import { HttpError } from "../httpError.js";
import type { BankId, QuarantineKind, ReviewReason } from "../types.js";
import {
  createEncryptedQuarantineEnvelope,
  decodePublicKey,
  type DecryptedQuarantineObject,
} from "./envelopeCrypto.js";
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
  rateLimitMax: number;
  rateLimitWindowMs: number;
}

export const DEFAULT_QUARANTINE_LIMITS: QuarantineStoreLimits = {
  maxItemBytes: 1_048_576,
  maxPendingItems: 1_000,
  maxEncryptedBytes: 104_857_600,
  rateLimitMax: 30,
  rateLimitWindowMs: 60_000,
};

export class EncryptedDatabaseQuarantineStore implements QuarantineStore {
  private readonly limiter: PerProcessFixedWindowLimiter;
  private readonly publicKey: string;
  private readonly capacity: QuarantineCapacityLimits;

  constructor(
    publicKey: string,
    readonly repository: QuarantineRepository,
    private readonly limits: QuarantineStoreLimits = DEFAULT_QUARANTINE_LIMITS,
  ) {
    this.publicKey = decodePublicKey(publicKey);
    this.capacity = {
      maxPendingItems: limits.maxPendingItems,
      maxEncryptedBytes: limits.maxEncryptedBytes,
    };
    this.limiter = new PerProcessFixedWindowLimiter(
      limits.rateLimitMax,
      limits.rateLimitWindowMs,
    );
  }

  async put(input: QuarantineInput): Promise<QuarantineResult> {
    this.limiter.consume("quarantine-writes");

    const quarantineId = await this.resolveQuarantineId(input);
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

// This protects one router process. Multi-instance deployments need a shared edge limit.
class PerProcessFixedWindowLimiter {
  private readonly windows = new Map<
    string,
    { startedAt: number; count: number }
  >();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  consume(key: string, now = Date.now()): void {
    if (this.max <= 0 || this.windowMs <= 0) return;
    const current = this.windows.get(key);
    if (!current || now - current.startedAt >= this.windowMs) {
      this.windows.set(key, { startedAt: now, count: 1 });
      return;
    }
    if (current.count >= this.max) {
      throw new HttpError(
        429,
        "quarantine_rate_limited",
        "too many quarantine writes",
      );
    }
    current.count += 1;
  }
}
