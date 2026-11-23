import {
  approveItem,
  postponeItem,
  reconcileItem,
  rejectItem,
  type AdminSession,
} from "../lib/api";
import { DecryptError, decryptEnvelope } from "../lib/quarantineCrypto";
import { decryptWithReviewAgent } from "../lib/reviewAgent";
import type {
  DecryptedQuarantineObject,
  QuarantineItemResponse,
  QuarantineItemSummary,
  ReconcileAction,
} from "../lib/types";

// State-free ItemDetail logic, kept out of the component so it is unit-testable
// without a DOM.

export type PendingAction = "approve" | "reject" | ReconcileAction | null;
export type OpenAction = "approve" | "reject" | ReconcileAction;
export type RunnableAction = OpenAction | "postpone";

export interface ActionContext {
  readonly tokens: AdminSession;
  readonly item: QuarantineItemSummary;
  readonly detail: QuarantineItemResponse | null;
  readonly decrypted: DecryptedQuarantineObject | null;
  readonly onAction: (message: string) => void;
}

export async function executeAction(action: RunnableAction, ctx: ActionContext): Promise<void> {
  if (action === "approve") {
    await approveAction(ctx);
    return;
  }
  if (action === "reject") {
    await rejectAction(ctx);
    return;
  }
  if (action === "postpone") {
    await postponeAction(ctx);
    return;
  }
  await reconcileAction(action, ctx);
}

export async function approveAction(ctx: ActionContext): Promise<void> {
  if (!ctx.decrypted) throw new Error("decrypt the item before approving");
  const result = await approveItem(ctx.tokens, ctx.item.quarantine_id, ctx.decrypted);
  ctx.onAction(approvalMessage(ctx.item, result));
}

export function approvalMessage(item: QuarantineItemSummary, result: Record<string, unknown>): string {
  if (item.kind !== "blocked_content") return `approved ${item.quarantine_id}`;
  if (result.exception_active === true) {
    return `approved exact exception ${item.quarantine_id}; applies to matching later calls`;
  }
  return `classified ${item.quarantine_id} as false positive; content remains blocked`;
}

export async function rejectAction(ctx: ActionContext): Promise<void> {
  await rejectItem(ctx.tokens, ctx.item.quarantine_id);
  ctx.onAction(rejectionMessage(ctx.item));
}

export function rejectionMessage(item: QuarantineItemSummary): string {
  if (item.kind === "blocked_content") {
    return `classified ${item.quarantine_id} as true positive; content remains blocked`;
  }
  return `rejected ${item.quarantine_id}`;
}

export async function postponeAction(ctx: ActionContext): Promise<void> {
  await postponeItem(ctx.tokens, ctx.item.quarantine_id);
  ctx.onAction(`postponed ${ctx.item.quarantine_id}`);
}

export async function reconcileAction(action: ReconcileAction, ctx: ActionContext): Promise<void> {
  const current = ctx.detail?.record ?? ctx.item;
  await reconcileItem(ctx.tokens, ctx.item.quarantine_id, {
    action,
    ...reconcileDecision(ctx.item.kind),
    expected_sha256: current.sha256,
    expected_updated_at: current.updated_at,
  });
  ctx.onAction(`reconciled ${ctx.item.quarantine_id} (${action})`);
}

export function reconcileDecision(
  kind: QuarantineItemSummary["kind"],
): { decision: "approve" } | { decision: "reject" } | Record<string, never> {
  if (kind === "retain_request") return { decision: "approve" };
  if (kind === "recalled_memory") return { decision: "reject" };
  return {};
}

export function extractJoinedText(decrypted: DecryptedQuarantineObject | null): string | null {
  if (!decrypted || typeof decrypted.payload !== "object" || decrypted.payload === null) {
    return null;
  }
  if (!("joined_text" in decrypted.payload)) return null;
  return typeof decrypted.payload.joined_text === "string" ? decrypted.payload.joined_text : null;
}

export function extractOrderedPayload(decrypted: DecryptedQuarantineObject | null): string | null {
  if (!decrypted || typeof decrypted.payload !== "object" || decrypted.payload === null) {
    return null;
  }
  if (!("ordered_payload_json" in decrypted.payload)) return null;
  return typeof decrypted.payload.ordered_payload_json === "string"
    ? decrypted.payload.ordered_payload_json
    : null;
}

export function approveLabel(canFinalize: boolean, reviewOnly: boolean): string {
  if (canFinalize) return "Finalize approval";
  if (reviewOnly) return "Mark false positive";
  return "Approve";
}

export function rejectLabel(canFinalize: boolean, reviewOnly: boolean): string {
  if (canFinalize) return "Finalize rejection";
  if (reviewOnly) return "Mark true positive";
  return "Reject";
}

export function approveTitle(hasDecrypted: boolean, authorized: boolean): string {
  if (!hasDecrypted) return "decrypt first";
  if (!authorized) return "review token required";
  return "";
}

export function reviewTokenTitle(authorized: boolean): string {
  return authorized ? "" : "review token required";
}

export function confirmPrompt(pendingAction: OpenAction, reviewOnly: boolean): string {
  if (pendingAction === "approve") {
    return reviewOnly
      ? "Mark this exact finding as false positive? Eligible approvals permit matching later calls until expiry or revocation. Older review items remain blocked. Other findings still block."
      : "Approve into memory? The exact decrypted object is submitted for hash verification.";
  }
  if (pendingAction === "reject") {
    return reviewOnly
      ? "Mark this finding as true positive? Content stays blocked and source memories do not change."
      : "Reject this item?";
  }
  if (pendingAction === "confirmed_applied") {
    return "Confirm the side effect reached Hindsight? The original decision is finalized without re-calling Hindsight.";
  }
  return "Confirm the side effect never reached Hindsight? The item returns to postponed for normal retry.";
}

export function confirmLabel(busy: boolean, pendingAction: OpenAction): string {
  if (busy) return "working...";
  if (pendingAction === "approve" || pendingAction === "reject") return `Confirm ${pendingAction}`;
  return "Confirm reconcile";
}

export function confirmButtonClass(pendingAction: OpenAction): string {
  if (pendingAction === "approve" || pendingAction === "confirmed_applied") {
    return "bg-emerald-600 hover:bg-emerald-500";
  }
  if (pendingAction === "reject") return "bg-red-600 hover:bg-red-500";
  return "bg-zinc-600 hover:bg-zinc-500";
}

export function needsReviewAgent(detail: QuarantineItemResponse, useAgent: boolean): boolean {
  return detail.encrypted.encryption.provider !== undefined || useAgent;
}

export interface DecryptOptions {
  readonly useAgent: boolean;
  readonly agentCredential: string;
  readonly tokens: AdminSession;
  readonly localKey: CryptoKey | null;
}

// Returns null when no local key is loaded yet; nothing to decrypt with.
export async function decryptItem(
  detail: QuarantineItemResponse,
  options: DecryptOptions,
): Promise<DecryptedQuarantineObject | null> {
  if (needsReviewAgent(detail, options.useAgent)) {
    if (options.tokens !== "host" && !options.tokens.review) {
      throw new DecryptError("review token required");
    }
    return decryptWithReviewAgent(detail.encrypted, options.agentCredential);
  }
  if (!options.localKey) return null;
  return decryptEnvelope(detail.encrypted, options.localKey);
}
