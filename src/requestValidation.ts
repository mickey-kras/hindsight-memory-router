import { z } from "zod";
import { HttpError } from "./httpError.js";
import type { RecallBody, RetainBody } from "./types.js";

const nonEmptyStringSchema = z.string().refine((value) => value.trim().length > 0);

const memoryItemSchema = z
  .object({
    content: nonEmptyStringSchema,
    context: z.string().nullable().optional(),
    document_id: z.string().nullable().optional(),
    metadata: z.record(z.string(), z.string()).nullable().optional(),
    tags: z.array(z.string()).nullable().optional(),
    timestamp: z.string().nullable().optional(),
    update_mode: z.enum(["replace", "append"]).nullable().optional(),
  })
  .passthrough();

const retainBodySchema = z
  .object({
    items: z.array(memoryItemSchema).min(1),
    async: z.boolean().optional(),
    document_tags: z.array(z.string()).optional(),
  })
  .passthrough();

const recallBodySchema = z
  .object({
    query: nonEmptyStringSchema,
    max_tokens: z
      .number()
      .refine((value) => Number.isSafeInteger(value) && value > 0)
      .optional(),
    budget: z.enum(["low", "mid", "high"]).optional(),
    types: z.array(z.string()).nullable().optional(),
    tags: z.array(z.string()).nullable().optional(),
    tags_match: z.string().optional(),
    trace: z.boolean().optional(),
  })
  .passthrough();

export function parseRetainBody(value: unknown): RetainBody {
  const parsed = retainBodySchema.safeParse(value);
  if (!parsed.success) {
    throw invalidRetain(retainValidationMessage(value, parsed.error.issues[0]));
  }
  return parsed.data;
}

export function parseRecallBody(value: unknown): RecallBody {
  const parsed = recallBodySchema.safeParse(value);
  if (!parsed.success) {
    throw invalidRecall(recallValidationMessage(value, parsed.error.issues[0]));
  }
  return parsed.data;
}

function retainValidationMessage(
  value: unknown,
  issue: z.core.$ZodIssue | undefined,
): string {
  if (!isObject(value)) return "retain body must be an object";
  const path = issue?.path ?? [];
  if (path[0] === "items") {
    if (path.length === 1) {
      return "retain body requires at least one memory item";
    }
    const index = typeof path[1] === "number" ? path[1] : 0;
    if (path.length === 2) return `memory item ${index} must be an object`;
    switch (path[2]) {
      case "content":
        return `memory item ${index} content must be a non-empty string`;
      case "context":
        return "context must be a string or null";
      case "document_id":
        return "document_id must be a string or null";
      case "timestamp":
        return "timestamp must be a string or null";
      case "tags":
        return "tags must contain strings";
      case "metadata":
        return "metadata must map strings to strings";
      case "update_mode":
        return "update_mode must be replace or append";
    }
  }
  if (path[0] === "async") return "async must be a boolean";
  if (path[0] === "document_tags") {
    return "document_tags must contain strings";
  }
  return "retain body is invalid";
}

function recallValidationMessage(
  value: unknown,
  issue: z.core.$ZodIssue | undefined,
): string {
  if (!isObject(value)) return "recall body must be an object";
  switch (issue?.path[0]) {
    case "query":
      return "recall query must be a non-empty string";
    case "max_tokens":
      return "max_tokens must be a positive integer";
    case "budget":
      return "budget must be low, mid, or high";
    case "types":
      return "types must contain strings";
    case "tags":
      return "tags must contain strings";
    case "tags_match":
      return "tags_match must be a string";
    case "trace":
      return "trace must be a boolean";
    default:
      return "recall body is invalid";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidRetain(message: string): HttpError {
  return new HttpError(400, "invalid_retain_body", message);
}

function invalidRecall(message: string): HttpError {
  return new HttpError(400, "invalid_recall_body", message);
}
