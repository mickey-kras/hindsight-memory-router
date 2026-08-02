import { sha256Hex } from "./canonicalJson.js";
import type { HindsightGateway } from "./hindsightClient.js";
import { getWriter } from "./registry.js";
import type { QuarantineRepository } from "./quarantine/repository.js";
import type { QuarantineStore } from "./quarantine/quarantineStore.js";
import { scanContent, type SafetyFinding } from "./safety.js";
import type {
  BankId,
  MemoryItem,
  RecallBody,
  RecallResponse,
  RecallResult,
  RetainBody,
  WriterRegistry,
} from "./types.js";

export interface RouterPolicyDeps {
  registry: WriterRegistry;
  hindsight: HindsightGateway;
  quarantineStore: QuarantineStore;
  quarantineRepository: QuarantineRepository;
  now?: () => Date;
}

export class RouterPolicy {
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

    for (const item of body.items ?? []) {
      const scan = scanMemoryItem(item);
      if (!scan.safe) {
        return this.quarantineRetain({
          writerId,
          source,
          reason: "suspicious_content",
          body,
          findings: scan.findings,
        });
      }
    }

    const rewritten: RetainBody = {
      ...body,
      items: body.items.map((item) => ({
        ...item,
        metadata: {
          ...(item.metadata ?? {}),
          router_writer_id: writerId,
          router_source: source,
          router_decision: "allowed",
          router_target_bank: writer.write_bank,
        },
      })),
    };

    return this.deps.hindsight.retain(writer.write_bank, rewritten);
  }

  async recall(
    writerId: string,
    body: RecallBody,
    source = "openclaw",
  ): Promise<RecallResponse> {
    const writer = getWriter(this.deps.registry, writerId);
    if (!writer) {
      await this.quarantine({
        writerId,
        source,
        kind: "recall_request",
        reason: "unknown_writer",
        payload: { action: "recall", writer_id: writerId, body },
      });
      return { results: [] };
    }

    const scan = scanContent(body.query ?? "");
    if (!scan.safe) {
      await this.quarantine({
        writerId,
        source,
        kind: "recall_request",
        reason: "suspicious_query",
        payload: { action: "recall", writer_id: writerId, body },
      });
      return { results: [] };
    }

    const responses = await Promise.all(
      writer.read_banks.map(async (bankId) => ({
        bankId,
        response: await this.deps.hindsight.recall(bankId, body),
      })),
    );
    const results: RecallResult[] = [];
    for (const { bankId, response } of responses) {
      for (const result of response.results ?? []) {
        if (await this.allowRecalledResult(writerId, source, bankId, result)) {
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
    await this.quarantine({
      writerId,
      source: "http",
      kind: "security_event",
      reason: "denied_endpoint",
      dedupeKey: `${method}:${path}`,
      payload: { action: "denied_endpoint", method, path },
    });
    return { error: "endpoint denied by memory-router policy" };
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

  private async quarantineRetain(input: {
    writerId: string;
    source: string;
    reason: "unknown_writer" | "suspicious_content";
    body: RetainBody;
    findings?: SafetyFinding[];
  }): Promise<unknown> {
    const quarantine = await this.quarantine({
      writerId: input.writerId,
      source: input.source,
      kind: "retain_request",
      reason: input.reason,
      payload: {
        action: "retain",
        writer_id: input.writerId,
        body: input.body,
      },
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

function scanMemoryItem(item: MemoryItem): {
  safe: boolean;
  findings: SafetyFinding[];
} {
  const fields = [
    item.content,
    item.context ?? "",
    item.document_id ?? "",
    ...(item.tags ?? []),
    ...Object.values(item.metadata ?? {}),
  ].filter((value): value is string => typeof value === "string");

  const findings = fields.flatMap((value) => scanContent(value).findings);
  return { safe: findings.length === 0, findings };
}
