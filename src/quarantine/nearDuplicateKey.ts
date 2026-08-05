import { canonicalJson, sha256Hex } from "../canonicalJson.js";
import type { QuarantineKind, ReviewReason } from "../types.js";

const ORDER_INSENSITIVE_ARRAY_KEYS = new Set([
  "document_tags",
  "tags",
  "types",
]);

export interface RequestFamilyIdentity {
  scope: string;
  family: string;
}

export function requestFamilyIdentity(input: {
  kind: QuarantineKind;
  reason: ReviewReason;
  writerId?: string;
  payload: unknown;
}): RequestFamilyIdentity | null {
  if (input.kind !== "retain_request" && input.kind !== "recall_request") {
    return null;
  }
  const scope =
    input.reason === "unknown_writer"
      ? "unknown-writer"
      : (input.writerId ?? "anonymous");
  const base = {
    kind: input.kind,
    reason: input.reason,
  };
  const normalized = sha256Hex(
    canonicalJson({ ...base, payload: normalizeValue(input.payload) }),
  );
  const structural = sha256Hex(
    canonicalJson({ ...base, payload: shapeValue(input.payload) }),
  );
  return {
    scope: `${input.kind}:${input.reason}:${scope}`,
    family: sha256Hex(`${normalized}:${structural}`),
  };
}

function normalizeValue(value: unknown, key?: string): unknown {
  if (typeof value === "string") return normalizeText(value);
  if (Array.isArray(value)) {
    const normalized = value.map((entry) => normalizeValue(entry));
    return key && ORDER_INSENSITIVE_ARRAY_KEYS.has(key)
      ? [...normalized].sort(compareCanonical)
      : normalized;
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(
        ([entryKey, entry]) => [entryKey, normalizeValue(entry, entryKey)],
      ),
    );
  }
  return value;
}

function shapeValue(value: unknown, key?: string): unknown {
  if (typeof value === "string") {
    const normalized = normalizeText(value);
    return {
      text_length_bucket: Math.floor(normalized.length / 32),
      token_count_bucket: Math.floor(tokenCount(normalized) / 4),
    };
  }
  if (Array.isArray(value)) {
    const shaped = value.map((entry) => shapeValue(entry));
    return key && ORDER_INSENSITIVE_ARRAY_KEYS.has(key)
      ? [...shaped].sort(compareCanonical)
      : shaped;
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(
        ([entryKey, entry]) => [entryKey, shapeValue(entry, entryKey)],
      ),
    );
  }
  return typeof value;
}

function normalizeText(value: string): string {
  return value.normalize("NFKC").trim().toLowerCase().replace(/\s+/gu, " ");
}

function tokenCount(value: string): number {
  return value === "" ? 0 : value.split(/\s+/u).length;
}

function compareCanonical(left: unknown, right: unknown): number {
  return canonicalJson(left).localeCompare(canonicalJson(right));
}
