import { canonicalJson, sha256Hex } from "../canonicalJson.js";

/**
 * Maximum number of distinct security-event identities tracked per writer and
 * router process before events collapse into one aggregate identity. This is a
 * per-process best effort, consistent with the per-process write-rate limiter;
 * multi-instance deployments share the quarantine database but not this map.
 */
export const MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER = 64;

/**
 * Normalization rules for dedupe hashing. Only the hashed form is normalized;
 * the stored (encrypted) payload always keeps the original bytes.
 *
 * - strings: leading/trailing whitespace is trimmed and every internal
 *   whitespace run collapses to a single space;
 * - objects: keys are sorted by the canonical JSON serialization (key names
 *   themselves are not normalized) and values are normalized recursively;
 * - arrays: order is preserved and elements are normalized recursively;
 * - numbers, booleans, and null: unchanged (numbers must be finite).
 */
export function normalizeForDedupe(value: unknown): unknown {
  if (typeof value === "string") {
    return value.trim().replace(/\s+/g, " ");
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeForDedupe(entry));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
        key,
        normalizeForDedupe(entry),
      ]),
    );
  }
  return value;
}

/**
 * Deterministic dedupe identity for retain/recall request items: SHA-256 over
 * the canonical JSON of {kind, writer_id, target, normalized payload}. The
 * target scopes the identity to the policy destination (write bank for
 * retains, sorted read banks for recalls) when the writer is registered.
 */
export function requestDedupeKey(input: {
  kind: "retain_request" | "recall_request";
  writerId?: string;
  target?: string;
  payload: unknown;
}): string {
  return sha256Hex(
    canonicalJson({
      kind: input.kind,
      writer_id: input.writerId ?? null,
      target: input.target ?? null,
      payload: normalizeForDedupe(input.payload),
    }),
  );
}

/**
 * Normalizes an HTTP path for security-event dedupe identity: query string and
 * fragment are stripped, casing is lowered, and trailing slashes collapse to
 * the bare path (the root stays "/"). This prevents probing variants such as
 * `/Admin/?id=1` from minting fresh quarantine item identities.
 */
export function normalizeSecurityEventPath(path: string): string {
  const withoutQuery = path.split(/[?#]/, 1)[0] ?? "";
  const withoutTrailingSlashes = withoutQuery.toLowerCase().replace(/\/+$/, "");
  return withoutTrailingSlashes === "" ? "/" : withoutTrailingSlashes;
}

export function securityEventDedupeKey(method: string, path: string): string {
  return `${method.toUpperCase()}:${normalizeSecurityEventPath(path)}`;
}

/**
 * Per-process, per-writer cap on distinct security-event identities. The first
 * MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER distinct method:path keys per writer
 * keep their own identity; anything beyond that buckets into one aggregate
 * identity per writer, so path fuzzing cannot exhaust pending-item capacity.
 */
export class SecurityEventIdentityCap {
  private readonly seenByWriter = new Map<string, Set<string>>();

  resolve(writerId: string | undefined, baseKey: string): string {
    const scope = writerId ?? "anonymous";
    let seen = this.seenByWriter.get(scope);
    if (!seen) {
      seen = new Set<string>();
      this.seenByWriter.set(scope, seen);
    }
    if (seen.has(baseKey)) return baseKey;
    if (seen.size >= MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER) {
      return `aggregate:${scope}`;
    }
    seen.add(baseKey);
    return baseKey;
  }
}
