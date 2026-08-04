import { createHash, timingSafeEqual } from "node:crypto";
import { hostname } from "node:os";
import {
  canonicalJson,
  sha256Hex,
} from "./canonicalJson.js";
import type { HindsightGateway } from "./hindsightClient.js";
import { HttpError } from "./httpError.js";
import type { QuarantineRepository } from "./quarantine/repository.js";
import {
  SecurityEventIdentityCap,
  requestDedupeKey,
  securityEventDedupeKey,
} from "./quarantine/dedupeKey.js";
import type { QuarantineStore } from "./quarantine/quarantineStore.js";
import type { WriterRegistry } from "./types.js";
import { scanContent } from "./safety.js";
import type {
  BankId,
  PolicyAction,
  RecallBody,
  RecallResponse,
  RecallResult,
  RetainBody,
  RetainResponse,
  WriterConfig,
} from "./types.js";

export interface RouterPolicyDeps {
  registry: WriterRegistry;
  hindsight: HindsightGateway;
  quarantineStore: QuarantineStore;
  quarantineRepository: QuarantineRepository;
  now?: () => Date;
}

interface QuarantineRecallInput {
  writerId: string;
  source: string;
  reason: "unknown_writer" | "suspicious_query";
  body: RecallBody;
  targetBanks?: readonly BankId[];
}

// Recall stays fail-closed on content but fail-open on availability: an
// exhausted (507) or rate-limited (429) quarantine queue must not turn an
// otherwise answerable recall into an error. Neither must a 409 repeat of a
// suspicious request that is already quarantined and under review — the
// content is contained either way.
function isQuarantineUnavailable(error: unknown): boolean {
  return (
    error instanceof HttpError &&
    (error.status === 507 ||
      error.status === 429 ||
      (error.status === 409 && error.code === "quarantine_request_in_review"))
  );}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class RouterPolicy {
  private readonly securityEventIdentities = new SecurityEventIdentityCap();

  constructor(private readonly deps: RouterPolicyDeps) {}

  async retain(
    writerId: string,
    body: RetainBody,
    source = "openclaw",
  ): Promise<RetainResponse> {
    const writer = this.lookupWriter(writerId);
    if (!writer) {
      await this.quarantineRetain({
        writerId,
        source,
        reason: "unknown_writer",
        body,
      });
      return { error: "writer is not registered with memory-router" };
    }

    const items = body.items ?? [];
    const suspicious: { index: number; categories: string[] }[] = [];
    items.forEach((item, index) => {
      const scan = scanContent(item.content);
      if (!scan.safe) {
        suspicious.push({ index, categories: scan.categories });
      }
    });

    if (suspicious.length > 0) {
      await this.quarantineRetain({
        writerId,
        source,
        reason: "suspicious_content",
        body,
        targetBank: writer.write_bank,
      });
      return { error: "retain content requires memory-router review" };
    }

    await this.deps.hindsight.retain(writer.write_bank, body);
    return { ok: true };
  }

  async recall(
    writerId: string,
    body: RecallBody,
    source = "openclaw",
  ): Promise<RecallResponse> {
    const writer = this.lookupWriter(writerId);
    if (!writer) {
      await this.quarantineRecallOrDegrade({
        writerId,
        source,
        reason: "unknown_writer",
        body,
      });
      return { results: [] };
    }

    const queryScan = scanContent(body.query ?? "");
    if (!queryScan.safe) {
      await this.quarantineRecallOrDegrade({
        writerId,
        source,
        reason: "suspicious_query",
        body,
        targetBanks: writer.read_banks,
      });
      return { results: [] };
    }

    const responses = await this.recallFromBanks(writerId, writer.read_banks, body);
    const results: RecallResult[] = [];
    for (const { bankId, response } of responses) {
      for (const result of response.results ?? []) {
        if (await this.allowRecalledResultOrDegrade(writerId, source, bankId, result)) {
          results.push(result);
        }
      }
    }
    return { results };
  }

  async denyEndpoint(
    method: string,
    path: string,
    writerId?: string,
    source = "openclaw",
  ): Promise<{ error: string }> {
    const dedupeKey = this.securityEventIdentities.resolve(
      writerId,
      securityEventDedupeKey(method, path),
    );
    await this.deps.quarantineStore.put({
      timestamp: this.timestamp(),
      kind: "security_event",
      reason: "denied_endpoint",
      writerId,
      source,
      dedupeKey,
      payload: { action: "denied_endpoint", method, path },
    });
    return { error: "endpoint denied by memory-router policy" };
  }

  // Fans out to all configured read banks, but isolates failures: a bank that
  // errors contributes zero results instead of rejecting the whole recall.
  // After PR-6 (typed HindsightGatewayError kinds) lands, this can refine
  // handling per error kind; today any bank error degrades the same way.
  private async recallFromBanks(
    writerId: string,
    readBanks: readonly BankId[],
    body: RecallBody,
  ): Promise<{ bankId: BankId; response: RecallResponse }[]> {
    const settled = await Promise.allSettled(
      readBanks.map(async (bankId) => ({
        bankId,
        response: await this.deps.hindsight.recall(bankId, body),
      })),
    );
    const responses: { bankId: BankId; response: RecallResponse }[] = [];
    settled.forEach((outcome, index) => {
      if (outcome.status === "fulfilled") {
        responses.push(outcome.value);
        return;
      }
      this.logRecallDegradation("bank_unavailable", {
        writer_id: writerId,
        bank_id: readBanks[index],
        error: describeError(outcome.reason),
      });
    });
    return responses;
  }

  private async allowRecalledResultOrDegrade(
    writerId: string,
    source: string,
    bankId: BankId,
    result: RecallResult,
  ): Promise<boolean> {
    try {
      return await this.allowRecalledResult(writerId, source, bankId, result);
    } catch (error) {
      if (!isQuarantineUnavailable(error)) throw error;
      this.logRecallDegradation("quarantine_write_unavailable", {
        writer_id: writerId,
        bank_id: bankId,
        memory_id: result.id,
        error: describeError(error),
      });
      return false;
    }
  }

  private async quarantineRecallOrDegrade(
    input: QuarantineRecallInput,
  ): Promise<void> {
    try {
      await this.quarantineRecall(input);
    } catch (error) {
      if (!isQuarantineUnavailable(error)) throw error;
      this.logRecallDegradation("quarantine_write_unavailable", {
        writer_id: input.writerId,
        reason: input.reason,
        error: describeError(error),
      });
    }
  }

  private logRecallDegradation(
    event: string,
    details: Record<string, unknown>,
  ): void {
    process.stderr.write(
      `memory-router recall degraded: ${JSON.stringify({ event, ...details })}\n`,
    );
  }

  private async allowRecalledResult(
    writerId: string,
    source: string,
    bankId: BankId,
    result: RecallResult,
  ): Promise<boolean> {
    const state = await this.deps.quarantineRepository.findMemoryState(
      bankId,
      result.id,
    );
    const sourceContentSha256 = sha256Hex(result.text ?? "");

    if (state?.status === "reviewed_blocked") return false;
    if (state?.status === "reviewed_allowed") {
      if (state.source_content_sha256 === sourceContentSha256) return true;
      await this.quarantineRecalledResult(
        writerId,
        source,
        bankId,
        result,
        sourceContentSha256,
      );
      return false;
    }
    if (state?.status === "pending" || state?.status === "postponed") {
      if (state.source_content_sha256 === sourceContentSha256) return false;
      await this.quarantineRecalledResult(
        writerId,
        source,
        bankId,
        result,
        sourceContentSha256,
      );
      return false;
    }

    const resultScan = scanContent(result.text ?? "");
    if (resultScan.safe) return true;

    await this.quarantineRecalledResult(
      writerId,
      source,
      bankId,
      result,
      sourceContentSha256,
    );
    return false;
  }

  private async quarantineRecalledResult(
    writerId: string,
    source: string,
    bankId: BankId,
    result: RecallResult,
    sourceContentSha256: string,
  ): Promise<void> {
    await this.quarantine({
      writerId,
      source,
      kind: "recalled_memory",
      reason: "recalled_suspicious_memory",
      sourceBank: bankId,
      sourceMemoryId: result.id,
      sourceContentSha256,
      payload: {
        action: "recalled_memory",
        bank_id: bankId,
        result,
      },
    });
  }

  private async quarantineRecall(input: QuarantineRecallInput): Promise<void> {
    const payload = {
      action: "recall",
      body: input.body,
    };
    await this.quarantine({
      writerId: input.writerId,
      source: input.source,
      kind: "recall_request",
      reason: input.reason,
      dedupeKey: requestDedupeKey({
        kind: "recall_request",
        writerId: input.writerId,
        target: input.targetBanks?.slice().sort().join(","),
        payload,
      }),
      payload,
    });
  }

  private async quarantineRetain(input: {
    writerId: string;
    source: string;
    reason: "unknown_writer" | "suspicious_content";
    body: RetainBody;
    targetBank?: BankId;
  }): Promise<void> {
    const payload = {
      action: "retain",
      body: input.body,
    };
    await this.quarantine({
      writerId: input.writerId,
      source: input.source,
      kind: "retain_request",
      reason: input.reason,
      dedupeKey: requestDedupeKey({
        kind: "retain_request",
        writerId: input.writerId,
        target: input.targetBank,
        payload,
      }),
      payload,
    });
  }

  private async quarantine(input: {
    writerId: string;
    source: string;
    kind:
      | "retain_request"
      | "recall_request"
      | "recalled_memory"
      | "security_event";
    reason: string;
    dedupeKey?: string;
    sourceBank?: BankId;
    sourceMemoryId?: string;
    sourceContentSha256?: string;
    payload: Record<string, unknown>;
  }): Promise<void> {
    await this.deps.quarantineStore.put({
      timestamp: this.timestamp(),
      kind: input.kind,
      reason: input.reason,
      writerId: input.writerId,
      source: input.source,
      dedupeKey: input.dedupeKey,
      sourceBank: input.sourceBank,
      sourceMemoryId: input.sourceMemoryId,
      sourceContentSha256: input.sourceContentSha256,
      payload: input.payload,
    });
  }

  private lookupWriter(writerId: string): WriterConfig | undefined {
    const writers = this.deps.registry.writers as Record<string, WriterConfig>;
    return writers[writerId];
  }

  private timestamp(): string {
    return (this.deps.now?.() ?? new Date()).toISOString();
  }
}
