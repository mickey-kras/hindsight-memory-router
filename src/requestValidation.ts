import { HttpError } from "./httpError.js";
import type { MemoryItem, RecallBody, RetainBody } from "./types.js";

export function parseRetainBody(value: unknown): RetainBody {
  const object = requireObject(value, "retain body", "invalid_retain_body");
  if (!Array.isArray(object.items) || object.items.length === 0) {
    throw invalidRetain("retain body requires at least one memory item");
  }

  const items = object.items.map((item, index) => parseMemoryItem(item, index));
  optionalBoolean(object.async, "async", invalidRetain);
  optionalStringArray(object.document_tags, "document_tags", invalidRetain);

  const result: RetainBody = { items };
  for (const [key, entry] of Object.entries(object)) {
    if (key !== "items") result[key] = entry;
  }
  return result;
}

export function parseRecallBody(value: unknown): RecallBody {
  const object = requireObject(value, "recall body", "invalid_recall_body");
  const query = requireNonEmptyString(
    object.query,
    "recall query",
    invalidRecall,
  );

  if (
    object.max_tokens !== undefined &&
    (!Number.isSafeInteger(object.max_tokens) || Number(object.max_tokens) <= 0)
  ) {
    throw invalidRecall("max_tokens must be a positive integer");
  }
  if (
    object.budget !== undefined &&
    object.budget !== "low" &&
    object.budget !== "mid" &&
    object.budget !== "high"
  ) {
    throw invalidRecall("budget must be low, mid, or high");
  }
  optionalNullableStringArray(object.types, "types", invalidRecall);
  optionalNullableStringArray(object.tags, "tags", invalidRecall);
  optionalString(object.tags_match, "tags_match", invalidRecall);
  optionalBoolean(object.trace, "trace", invalidRecall);

  const result: RecallBody = { query };
  for (const [key, entry] of Object.entries(object)) {
    if (key !== "query") result[key] = entry;
  }
  return result;
}

function parseMemoryItem(value: unknown, index: number): MemoryItem {
  const object = requireObject(
    value,
    `memory item ${index}`,
    "invalid_retain_body",
  );
  const content = requireNonEmptyString(
    object.content,
    `memory item ${index} content`,
    invalidRetain,
  );

  optionalNullableString(object.context, "context", invalidRetain);
  optionalNullableString(object.document_id, "document_id", invalidRetain);
  optionalNullableString(object.timestamp, "timestamp", invalidRetain);
  optionalNullableStringArray(object.tags, "tags", invalidRetain);
  optionalNullableStringRecord(object.metadata, "metadata", invalidRetain);
  if (
    object.update_mode !== undefined &&
    object.update_mode !== null &&
    object.update_mode !== "replace" &&
    object.update_mode !== "append"
  ) {
    throw invalidRetain("update_mode must be replace or append");
  }

  const result: MemoryItem = { content };
  for (const [key, entry] of Object.entries(object)) {
    if (key !== "content") result[key] = entry;
  }
  return result;
}

function requireObject(
  value: unknown,
  label: string,
  code: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, code, `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireNonEmptyString(
  value: unknown,
  label: string,
  error: (message: string) => HttpError,
): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw error(`${label} must be a non-empty string`);
  }
  return value;
}

function optionalString(
  value: unknown,
  label: string,
  error: (message: string) => HttpError,
): void {
  if (value !== undefined && typeof value !== "string") {
    throw error(`${label} must be a string`);
  }
}

function optionalNullableString(
  value: unknown,
  label: string,
  error: (message: string) => HttpError,
): void {
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw error(`${label} must be a string or null`);
  }
}

function optionalBoolean(
  value: unknown,
  label: string,
  error: (message: string) => HttpError,
): void {
  if (value !== undefined && typeof value !== "boolean") {
    throw error(`${label} must be a boolean`);
  }
}

function optionalStringArray(
  value: unknown,
  label: string,
  error: (message: string) => HttpError,
): void {
  if (
    value !== undefined &&
    (!Array.isArray(value) || value.some((entry) => typeof entry !== "string"))
  ) {
    throw error(`${label} must contain strings`);
  }
}

function optionalNullableStringArray(
  value: unknown,
  label: string,
  error: (message: string) => HttpError,
): void {
  if (value === null) return;
  optionalStringArray(value, label, error);
}

function optionalNullableStringRecord(
  value: unknown,
  label: string,
  error: (message: string) => HttpError,
): void {
  if (value === undefined || value === null) return;
  if (
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.values(value).some((entry) => typeof entry !== "string")
  ) {
    throw error(`${label} must map strings to strings`);
  }
}

function invalidRetain(message: string): HttpError {
  return new HttpError(400, "invalid_retain_body", message);
}

function invalidRecall(message: string): HttpError {
  return new HttpError(400, "invalid_recall_body", message);
}
