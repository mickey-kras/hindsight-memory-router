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
  type RateLimitSession,
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
  rateLimitMax: number;
  rateLimitWindowMs: number;
  rateLimitGlobalMax: number;
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
const AUTH_AUDIT_WRITES_BUCKET = "quarantine-writes:auth-audit";
const AUTH_AUDIT_REQUARANTINE_OPS_BUCKET =
  "quarantine-requarantine-ops:auth-audit";
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
    const quarantineId = await this.resolveQuarantineId(input);
    const encrypted = this.encrypt(input, quarantineId);
    const encryptedBytes = Buffer.byteLength(JSON.stringify(encrypted));
    if (encryptedBytes > this.limits.maxItemBytes) {
      throw new HttpError(
        413,
        "quarantine_item_too_large",
        "encrypted quarantine item exceeds configured size limit",
      );
    }

    return this.rateLimiter.withIdentityLock(
      quarantineId,
      async (rateLimitSession) => {
        const knownIdentity = await this.isKnownIdentity(input, quarantineId);
        await this.chargeRateQuota(input, knownIdentity, rateLimitSession);

        const item = this.buildItem(input, quarantineId, encrypted);
        if (input.kind === "recalled_memory") {
          await this.repository.upsertRecalledMemory(item, this.capacity);
        } else if (input.kind === "security_event") {
          await this.repository.upsertSecurityEvent(item, this.capacity);
        } else if (item.dedupe_key) {
          await this.repository.upsertRequestItem(item, this.capacity);
        } else {
          await this.repository.insert(item, this.capacity);
        }

        return { quarantine_id: quarantineId, sha256: encrypted.sha256 };
      },
    );
  }

  private encrypt(input: QuarantineInput, quarantineId: string) {
    const decrypted: DecryptedQuarantineObject = {
      quarantine_id: quarantineId,
      created_at: input.timestamp,
      reason: input.reason,
      ...(input.writerId === undefined ? {} : { writer_id: input.writerId }),
      ...(input.source === undefined ? {} : { source: input.source }),
      payload: input.payload,
    };
    return createEncryptedQuarantineEnvelope(decrypted, this.publicKey);
  }

  private buildItem(
    input: QuarantineInput,
    quarantineId: string,
    encrypted: ReturnType<typeof createEncryptedQuarantineEnvelope>,
  ): NewQuarantineItem {
    return {
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
      ...(input.dedupeKey === undefined ? {} : { dedupe_key: input.dedupeKey }),
      sha256: encrypted.sha256,
      encrypted,
      status: "pending",
      postpone_count: 0,
    };
  }

  private async chargeRateQuota(
    input: QuarantineInput,
    knownIdentity: boolean,
    rateLimitSession: RateLimitSession,
  ): Promise<void> {
    const windowMs = this.limits.rateLimitWindowMs;
    // Auth-failure audits use dedicated buckets so unauthenticated probing
    // can never share budget with security quarantines or their refreshes.
    const authAudit = input.reason === "auth_failed";
    if (knownIdentity) {
      await rateLimitSession.consume(
        authAudit
          ? AUTH_AUDIT_REQUARANTINE_OPS_BUCKET
          : REQUARANTINE_OPS_BUCKET,
        { max: this.limits.requarantineOpsMax, windowMs },
      );
      return;
    }
    if (this.limits.rateLimitMax <= 0 || (await this.capacityExhausted())) {
      return;
    }
    if (authAudit) {
      await rateLimitSession.consume(AUTH_AUDIT_WRITES_BUCKET, {
        max: this.limits.rateLimitGlobalMax,
        windowMs,
      });
      return;
    }

    const writer = input.writerId ?? UNKNOWN_WRITER_BUCKET;
    await rateLimitSession.consumeMany([
      {
        key: `${GLOBAL_WRITES_BUCKET}:writer:${writer}`,
        rule: { max: this.limits.rateLimitMax, windowMs },
      },
      {
        key: GLOBAL_WRITES_BUCKET,
        rule: { max: this.limits.rateLimitGlobalMax, windowMs },
      },
    ]);
  }

  private async isKnownIdentity(
    input: QuarantineInput,
    quarantineId: string,
  ): Promise<boolean> {
    if (input.kind === "security_event" && input.dedupeKey) {
      return (await this.repository.get(quarantineId)) !== null;
    }
    if (
      (input.kind === "retain_request" || input.kind === "recall_request") &&
      input.dedupeKey
    ) {
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
      (input.kind === "retain_request" || input.kind === "recall_request") &&
      input.dedupeKey
    ) {
      const digest = sha256Hex(input.dedupeKey);
      return `q_request${digest.slice(0, 48)}_${digest.slice(48)}`;
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
