import { gatewayErrorKind } from "../hindsightClient.js";

export interface ReviewInterruptionDetails {
  outcome: "restored";
  status: "pending" | "postponed";
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
  status: "pending" | "postponed",
  error: unknown,
): ReviewInterruptionDetails {
  return {
    outcome: "restored",
    status,
    error_kind: gatewayErrorKind(error),
  };
}
