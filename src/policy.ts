import type { HindsightGateway } from "./hindsightClient.js";
import type {
  RecallBody,
  RecallResponse,
  RetainBody,
  ReviewRecord,
  WriterRegistry,
} from "./types.js";
import { getWriter } from "./registry.js";
import type { ReviewQueue } from "./reviewQueue.js";
import { safePreview, scanContent, sha256 } from "./safety.js";

export interface RouterPolicyDeps {
  registry: WriterRegistry;
  hindsight: HindsightGateway;
  reviewQueue: ReviewQueue;
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
      this.enqueueReview({
        writerId,
        source,
        reason: "unknown_writer",
        preview: `unknown writer ${writerId}`,
      });
      return { queued: true, reason: "unknown_writer" };
    }

    for (const item of body.items ?? []) {
      const scan = scanContent(item.content ?? "");
      if (!scan.safe) {
        this.enqueueReview({
          writerId,
          source,
          reason: "suspicious_content",
          content: item.content ?? "",
          preview: safePreview(item.content ?? ""),
        });
        return {
          queued: true,
          reason: "suspicious_content",
          findings: scan.findings,
        };
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
      this.enqueueReview({
        writerId,
        source,
        reason: "unknown_writer",
        preview: `unknown writer ${writerId}`,
      });
      return { results: [] };
    }

    const scan = scanContent(body.query ?? "");
    if (!scan.safe) {
      this.enqueueReview({
        writerId,
        source,
        reason: "suspicious_query",
        content: body.query ?? "",
        preview: safePreview(body.query ?? ""),
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

  private enqueueReview(input: {
    writerId?: string;
    source?: string;
    reason: ReviewRecord["reason"];
    content?: string;
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
      sha256: input.content ? sha256(input.content) : undefined,
      preview: input.preview,
      decision: "pending",
      method: input.method,
      path: input.path,
    });
  }
}
