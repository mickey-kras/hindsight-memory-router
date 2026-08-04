import { HttpError } from "../httpError.js";
import {
  quarantineEvent,
  type QuarantineEvent,
  type StoredQuarantineItem,
} from "./repository.js";
import {
  reviewClaimIsStale,
  reviewInterruptionDetails,
  runReviewOperation,
} from "./reviewWorkflowSupport.js";

export class MemoryReviewWorkflow {
  private tail: Promise<void> = Promise.resolve();

  constructor(
    private readonly items: Map<string, StoredQuarantineItem>,
    private readonly events: QuarantineEvent[],
  ) {}

  async recover(at: string): Promise<void> {
    for (const item of this.items.values()) {
      if (
        item.status !== "review_in_progress" ||
        !reviewClaimIsStale(item.updated_at, at)
      ) {
        continue;
      }
      this.restoreStaleClaim(item, at);
    }
  }

  async markMemoryReviewed(
    quarantineId: string,
    status: "reviewed_allowed" | "reviewed_blocked",
    at: string,
  ): Promise<void> {
    const item = this.requireReviewableKind(
      quarantineId,
      "recalled_memory",
      "only recalled memories can be marked reviewed",
    );
    this.setReviewed(item, status, at);
  }

  async approveRetain(
    quarantineId: string,
    at: string,
    details: Record<string, unknown>,
    operation: () => Promise<void>,
  ): Promise<void> {
    const claimed = await this.exclusive(() =>
      this.beginReview(
        quarantineId,
        "retain_request",
        "only retain requests can be approved into Hindsight",
        at,
      ),
    );
    await runReviewOperation(operation, (error) =>
      this.exclusive(() => this.interruptReview(claimed, at, error)),
    );
    await this.exclusive(() => {
      this.requireReviewInProgress(quarantineId, at);
      this.items.delete(quarantineId);
      this.events.push(quarantineEvent(quarantineId, "approved", at, details));
    });
  }

  async rejectRecalledMemory(
    quarantineId: string,
    at: string,
    operation: () => Promise<void>,
  ): Promise<void> {
    const claimed = await this.exclusive(() =>
      this.beginReview(
        quarantineId,
        "recalled_memory",
        "only recalled memories can be invalidated",
        at,
      ),
    );
    await runReviewOperation(operation, (error) =>
      this.exclusive(() => this.interruptReview(claimed, at, error)),
    );
    await this.exclusive(() => {
      const current = this.requireReviewInProgress(quarantineId, at);
      this.setReviewed(current, "reviewed_blocked", at);
    });
  }

  private requireItem(quarantineId: string): StoredQuarantineItem {
    const item = this.items.get(quarantineId);
    if (!item) {
      throw new HttpError(
        404,
        "quarantine_not_found",
        "quarantine item not found",
      );
    }
    return item;
  }

  private requireReviewable(quarantineId: string): StoredQuarantineItem {
    const item = this.requireItem(quarantineId);
    this.assertReviewable(item);
    return item;
  }

  private assertReviewable(item: StoredQuarantineItem): void {
    if (item.status !== "pending" && item.status !== "postponed") {
      throw new HttpError(
        409,
        "quarantine_already_finalized",
        "quarantine item is not pending review",
      );
    }
  }

  private requireReviewableKind(
    quarantineId: string,
    kind: StoredQuarantineItem["kind"],
    message: string,
  ): StoredQuarantineItem {
    const item = this.requireReviewable(quarantineId);
    if (item.kind !== kind) {
      throw new HttpError(409, "invalid_review_action", message);
    }
    return item;
  }

  private beginReview(
    quarantineId: string,
    kind: StoredQuarantineItem["kind"],
    message: string,
    at: string,
  ): StoredQuarantineItem {
    let item = this.requireItem(quarantineId);
    if (
      item.status === "review_in_progress" &&
      reviewClaimIsStale(item.updated_at, at)
    ) {
      item = this.restoreStaleClaim(item, at);
    }
    this.assertReviewable(item);
    if (item.kind !== kind) {
      throw new HttpError(409, "invalid_review_action", message);
    }
    this.items.set(quarantineId, {
      ...item,
      status: "review_in_progress",
      updated_at: at,
    });
    return item;
  }

  private restoreStaleClaim(
    item: StoredQuarantineItem,
    at: string,
  ): StoredQuarantineItem {
    const restored: StoredQuarantineItem = {
      ...item,
      status: "postponed",
      updated_at: at,
    };
    this.items.set(item.quarantine_id, restored);
    this.events.push(
      quarantineEvent(item.quarantine_id, "review_interrupted", at, {
        outcome: "postponed",
        recovered: true,
      }),
    );
    return restored;
  }

  private interruptReview(
    claimed: StoredQuarantineItem,
    at: string,
    error: unknown,
  ): void {
    const current = this.items.get(claimed.quarantine_id);
    if (
      !current ||
      current.status !== "review_in_progress" ||
      current.updated_at !== at
    ) {
      return;
    }
    this.items.set(claimed.quarantine_id, {
      ...current,
      status: claimed.status,
      updated_at: at,
    });
    this.events.push(
      quarantineEvent(
        claimed.quarantine_id,
        "review_interrupted",
        at,
        reviewInterruptionDetails(claimed.status, error),
      ),
    );
  }

  private requireReviewInProgress(
    quarantineId: string,
    at: string,
  ): StoredQuarantineItem {
    const item = this.requireItem(quarantineId);
    if (item.status !== "review_in_progress" || item.updated_at !== at) {
      throw new HttpError(
        409,
        "quarantine_review_changed",
        "quarantine item changed while review was in progress",
      );
    }
    return item;
  }

  private setReviewed(
    item: StoredQuarantineItem,
    status: "reviewed_allowed" | "reviewed_blocked",
    at: string,
  ): void {
    this.items.set(item.quarantine_id, {
      ...item,
      status,
      encrypted: null,
      updated_at: at,
    });
    this.events.push(
      quarantineEvent(
        item.quarantine_id,
        status === "reviewed_allowed" ? "reviewed_allowed" : "reviewed_blocked",
        at,
        {
          source_bank: item.source_bank,
          source_memory_id: item.source_memory_id,
          source_content_sha256: item.source_content_sha256,
        },
      ),
    );
  }

  private async exclusive<T>(operation: () => T | Promise<T>): Promise<T> {
    const current = this.tail.then(operation);
    this.tail = current.then(
      () => undefined,
      () => undefined,
    );
    return current;
  }
}
