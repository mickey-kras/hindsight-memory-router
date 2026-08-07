import { z } from "zod";
import { HttpError } from "../httpError.js";
import { REVIEW_REASONS } from "../types.js";

const approveBodySchema = z
  .object({
    decrypted: z.unknown().optional(),
  })
  .passthrough();

const cleanupBodySchema = z
  .object({
    scope: z.enum(["pending", "all"]).optional(),
    reasons: z.array(z.enum(REVIEW_REASONS)).optional(),
    older_than: z.string().optional(),
    dry_run: z.boolean().optional(),
    expected_count: z.unknown().optional(),
  })
  .passthrough();

export type ApproveBody = z.infer<typeof approveBodySchema>;
export type CleanupBody = z.infer<typeof cleanupBodySchema>;

export function parseApproveBody(value: unknown): ApproveBody {
  const parsed = approveBodySchema.safeParse(value);
  if (!parsed.success) {
    throw new HttpError(400, "invalid_request", "approve body must be an object");
  }
  return parsed.data;
}

export function parseCleanupBody(value: unknown): CleanupBody {
  const parsed = cleanupBodySchema.safeParse(value);
  if (!parsed.success) {
    throw new HttpError(400, "invalid_request", cleanupValidationMessage(parsed.error.issues[0]));
  }
  return parsed.data;
}

function cleanupValidationMessage(issue: z.core.$ZodIssue | undefined): string {
  switch (issue?.path[0]) {
    case "scope":
      return "scope must be pending or all";
    case "reasons":
      return "reasons must contain valid review reasons";
    case "older_than":
      return "older_than must be a string";
    case "dry_run":
      return "dry_run must be a boolean";
    default:
      return "cleanup body must be an object";
  }
}
