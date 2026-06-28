import type { HindsightGateway } from "./hindsightClient.js";
import type {
  MemoryItem,
  RecallBody,
  RecallResponse,
  RetainBody,
  ReviewRecord,
  WriterRegistry,
} from "./types.js";
import { getWriter } from "./registry.js";
import type { ReviewQueue } from "./reviewQueue.js";
import {
  MemoryQuarantineStore,
  type QuarantineStore,
} from "./quarantineStore.js";
import { scanContent, type SafetyFinding } from "./safety.js";

export interface RouterPolicyDeps {
  registry: WriterRegistry;
  hindsight: HindsightGateway;
  reviewQueue: ReviewQueue;
  quarantineStore?: QuarantineStore;
  now?: () => Date;
}

export class RouterPolicy {
  private readonly quarantineStore: QuarantineStore;

  constructor(private readonly deps: RouterPolicyDeps) {
    this.quarantineStore = deps.quarantineStore ?? new MemoryQuarantineStore();
  }

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
        reason: "suspicious_query",
        payload: { action: "recall", writer_id: writerId, body },
      });
      return { results: [] };
    }

    const responses = await Promise.all(
      writer.read_banks.map((bankId) =>
        this.deps.hindsight.recall(bankId, body),
      ),
    );
    const results = responses
      .flatMap((response) => response.results ?? [])
      .filter((result) => scanContent(result.text ?? "").safe);

    return { results };
  }

  denyEndpoint(
    method: string,
    path: string,
    writerId?: string,
  ): { error: string } {
    this.enqueueReview({
      writerId,
      source: "http",
      reason: "denied_endpoint",
      preview: `${method} ${path}`,
      method,
      path,
    });
    return { error: "endpoint denied by memory-router policy" };
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
    reason: ReviewRecord["reason"];
    payload: unknown;
  }) {
    const now = this.deps.now?.() ?? new Date();
    const timestamp = now.toISOString();
    const stored = this.quarantineStore.put({
      timestamp,
      writerId: input.writerId,
      source: input.source,
      reason: input.reason,
      payload: input.payload,
    });

    this.enqueueReview({
      writerId: input.writerId,
      source: input.source,
      reason: input.reason,
      quarantineId: stored.quarantine_id,
      sha256: stored.sha256,
      preview: `encrypted quarantine item ${stored.quarantine_id}`,
    });

    await this.deps.hindsight.retain("quarantine", {
      async: true,
      items: [
        {
          content: `Encrypted quarantine item ${stored.quarantine_id} pending review.`,
          context: "memory-router quarantine index",
          document_id: `quarantine:${stored.quarantine_id}`,
          metadata: {
            router_decision: "quarantined",
            quarantine_id: stored.quarantine_id,
            quarantine_reason: input.reason,
            quarantine_sha256: stored.sha256,
            writer_id: input.writerId ?? "unknown",
          },
          tags: ["quarantine", input.reason],
          update_mode: "append",
        },
      ],
    });

    return stored;
  }

  private enqueueReview(input: {
    writerId?: string;
    source?: string;
    reason: ReviewRecord["reason"];
    quarantineId?: string;
    sha256?: string;
    preview: string;
    method?: string;
    path?: string;
  }): void {
    const now = this.deps.now?.() ?? new Date();
    this.deps.reviewQueue.enqueue({
      timestamp: now.toISOString(),
      writer_id: input.writerId,
      source: input.source,
      reason: input.reason,
      quarantine_id: input.quarantineId,
      sha256: input.sha256,
      preview: input.preview,
      decision: "pending",
      postpone_count: input.quarantineId ? 0 : undefined,
      method: input.method,
      path: input.path,
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
