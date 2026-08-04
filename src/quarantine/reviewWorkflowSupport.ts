import { gatewayErrorKind } from "../hindsightClient.js";
import type { QuarantineStatus } from "../types.js";

export const DEFAULT_REVIEW_STALE_MS = 60_000;

type RestorableReviewStatus = "pending" | "postponed";

export interface ReviewInterruptionDetails extends Record<string, unknown> {
  outcome: "restored";
  status: RestorableReviewStatus;
  error_kind: ReturnType<typeof gatewayErrorKind>;
}

export async function runReviewOperation(
  operation: () => Promise<void>,
  onError: (error: unknown) => Promise<void>,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    await onError(error);
    throw error;
  }
}

export function reviewInterruptionDetails(
  status: QuarantineStatus,
  error: unknown,
): ReviewInterruptionDetails {
  if (status !== "pending" && status !== "postponed") {
    throw new Error(`cannot restore review to ${status}`);
  }
  return {
    outcome: "restored",
    status,
    error_kind: gatewayErrorKind(error),
  };
}

export function reviewClaimIsStale(
  updatedAt: string,
  at: string,
  staleMs = DEFAULT_REVIEW_STALE_MS,
): boolean {
  const updated = Date.parse(updatedAt);
  const current = Date.parse(at);
  if (!Number.isFinite(updated) || !Number.isFinite(current)) return false;
  return current - updated >= staleMs;
}
