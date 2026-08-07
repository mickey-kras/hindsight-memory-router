import { sha256Hex } from "./canonicalJson.js";
import {
  hindsightGatewayErrorDetails,
  HindsightGatewayError,
  type HindsightGateway,
} from "./hindsightClient.js";
import type { HindsightLimits } from "./hindsightLimits.js";
import { HttpError } from "./httpError.js";
import {
  requestDedupeKey,
  SecurityEventIdentityCap,
  securityEventDedupeKey,
} from "./quarantine/dedupeKey.js";
import { getWriter } from "./registry.js";
import type { QuarantineRepository } from "./quarantine/repository.js";
import type { QuarantineStore } from "./quarantine/quarantineStore.js";
import {
  scanContent,
  scanRecallResult,
  scanRetainBody,
  type SafetyFinding,
  type SafetyResult,
} from "./safety.js";
import type {
  BankId,
  RecallBody,
  RecallResponse,
  RecallResult,
  RetainBody,
  WriterRegistry,
} from "./types.js";

export interface RouterPolicyDeps {
  registry: WriterRegistry;
  hindsight: HindsightGateway;
  hindsightLimits?: HindsightLimits;
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
  transformations?: SafetyResult["transformations"];
}

function isQuarantineUnavailable(error: unknown): error is HttpError {
  return (
    error instanceof HttpError &&
    (error.status === 507 ||
      error.status === 429 ||
      (error.status === 409 && error.code === "quarantine_request_in_review"))
  );
}

function quarantineErrorDetails(error: HttpError): Record<string, unknown> {
  return { status: error.status, code: error.code };
}

export class RouterPolicy {
  private readonly securityEventIdentities = new SecurityEventIdentityCap();

  constructor(private readonly deps: RouterPolicyDeps) {}

  async retain(
    writerId: string,
    body: RetainBody,
    source = "openclaw",
  ): Promise<unknown> {
    const writer = getWriter(this.deps.registry, writerId);
    if (!writer) {
      return this.quarantineRetain({
        writerId,
        source,
        reason: "unknown_writer",
        body,
      });
    }

    const scan = scanRetainBody(body);
    if (!scan.safe) {
      return this.quarantineRetain({
        writerId,
        source,
        reason: "suspicious_content",
        body,
        targetBank: writer.write_bank,
        findings: scan.findings,
        transformations: scan.transformations,
      });
    }

    const rewritten: RetainBody = {
      ...body,
      items: body.items.map((item) => ({
        ...item,
        metadata: {
          ...item.metadata,
          router_writer_id: writerId,
          router_source: source,
          router_decision: "allowed",
          router_target_bank: writer.write_bank,
        },
      })),
    };

    await this.deps.hindsightLimits?.consumeRetain(writerId);
    return this.deps.hindsight.retain(writer.write_bank, rewritten);
  }

  async recall(
    writerId: string,
    body: RecallBody,
    source = "openclaw",
  ): Promise<RecallResponse> {
    const writer = getWriter(this.deps.registry, writerId);
    if (!writer) {
      await this.quarantineRecallOrDegrade({
        writerId,
        source,
        reason: "unknown_writer",
        body,
      });
      return { results: [] };
    }

    const scan = scanContent(body.query ?? "");
    if (!scan.safe) {
      await this.quarantineRecallOrDegrade({
        writerId,
        source,
        reason: "suspicious_query",
        body,
        targetBanks: writer.read_banks,
        transformations: scan.transformations,
      });
      return { results: [] };
    }

    await this.deps.hindsightLimits?.consumeRecall(writerId);
    const responses = await this.recallFromBanks(
      writerId,
      writer.read_banks,
      body,
    );
    const results: RecallResult[] = [];
    for (const { bankId, response } of responses) {
      for (const result of response.results ?? []) {
        if (
          await this.allowRecalledResultOrDegrade(
            writerId,
            source,
            bankId,
            result,
          )
        ) {
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
  ): Promise<{ error: string }> {
    const dedupeKey = this.securityEventIdentities.resolve(
      writerId,
      securityEventDedupeKey(method, path),
    );
    await this.quarantine({
      writerId,
      source: "http",
      kind: "security_event",
      reason: "denied_endpoint",
      dedupeKey,
      payload: { action: "denied_endpoint", method, path },
    });
    return { error: "endpoint denied by memory-router policy" };
  }

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
    for (let index = 0; index < settled.length; index += 1) {
      const outcome = settled[index];
      if (!outcome) continue;
      if (outcome.status === "fulfilled") {
        responses.push(outcome.value);
        continue;
      }
      if (!(outcome.reason instanceof HindsightGatewayError)) {
        throw outcome.reason;
      }
      this.logRecallDegradation("bank_unavailable", {
        writer_id: writerId,
        bank_id: readBanks[index],
        ...hindsightGatewayErrorDetails(outcome.reason),
      });
    }
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
        ...quarantineErrorDetails(error),
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
        ...quarantineErrorDetails(error),
      });
    }
  }

  private logRecallDegradation(
    event: "bank_unavailable" | "quarantine_write_unavailable",
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
    const scan = scanRecallResult(result);

    if (state?.status === "reviewed_blocked") return false;
    if (state?.status === "reviewed_allowed") {
      if (state.source_content_sha256 === sourceContentSha256) return true;
      await this.quarantineRecalledResult(
        writerId,
        source,
        bankId,
        result,
        sourceContentSha256,
        scan.transformations,
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
        scan.transformations,
      );
      return false;
    }

    if (scan.safe) return true;

    await this.quarantineRecalledResult(
      writerId,
      source,
      bankId,
      result,
      sourceContentSha256,
      scan.transformations,
    );
    return false;
  }

  private async quarantineRecalledResult(
    writerId: string,
    source: string,
    bankId: BankId,
    result: RecallResult,
    sourceContentSha256: string,
    transformations: SafetyResult["transformations"],
  ): Promise<void> {
    const payload = {
      action: "recalled_memory",
      bank_id: bankId,
      result,
    };
    await this.quarantine({
      writerId,
      source,
      kind: "recalled_memory",
      reason: "recalled_suspicious_memory",
      sourceBank: bankId,
      sourceMemoryId: result.id,
      sourceContentSha256,
      payload: addTransformationEvidence(payload, transformations),
    });
  }

  private async quarantineRecall(input: QuarantineRecallInput): Promise<void> {
    const payload = {
      action: "recall",
      writer_id: input.writerId,
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
        target: input.targetBanks
          ? [...input.targetBanks].sort().join(",")
          : undefined,
        payload,
      }),
      payload: addTransformationEvidence(payload, input.transformations),
    });
  }

  private async quarantineRetain(input: {
    writerId: string;
    source: string;
    reason: "unknown_writer" | "suspicious_content";
    body: RetainBody;
    targetBank?: BankId;
    findings?: SafetyFinding[];
    transformations?: SafetyResult["transformations"];
  }): Promise<unknown> {
    const payload = {
      action: "retain",
      writer_id: input.writerId,
      body: input.body,
    };
    const quarantine = await this.quarantine({
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
      payload: addTransformationEvidence(payload, input.transformations),
    });

    return {
      queued: true,
      reason: input.reason,
      quarantine_id: quarantine.quarantine_id,
      ...(input.findings ? { findings: input.findings } : {}),
    };
  }

  private async quarantine(input: {
    writerId?: string;
    source?: string;
    kind:
      | "retain_request"
      | "recall_request"
      | "recalled_memory"
      | "security_event";
    reason:
      | "unknown_writer"
      | "suspicious_content"
      | "suspicious_query"
      | "recalled_suspicious_memory"
      | "denied_endpoint";
    sourceBank?: BankId;
    sourceMemoryId?: string;
    sourceContentSha256?: string;
    dedupeKey?: string;
    payload: unknown;
  }) {
    const timestamp = (this.deps.now?.() ?? new Date()).toISOString();
    return this.deps.quarantineStore.put({
      timestamp,
      kind: input.kind,
      writerId: input.writerId,
      source: input.source,
      reason: input.reason,
      sourceBank: input.sourceBank,
      sourceMemoryId: input.sourceMemoryId,
      sourceContentSha256: input.sourceContentSha256,
      dedupeKey: input.dedupeKey,
      payload: input.payload,
    });
  }
}

function addTransformationEvidence<T extends Record<string, unknown>>(
  payload: T,
  transformations?: SafetyResult["transformations"],
): T | (T & { safety: { transformations: SafetyResult["transformations"] } }) {
  return transformations?.length
    ? { ...payload, safety: { transformations } }
    : payload;
}
