import { canonicalJson, sha256Hex } from "../canonicalJson.js";

export const MAX_SECURITY_EVENT_IDENTITIES = 64;
const AGGREGATE_SECURITY_EVENT_KEY = "aggregate";

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
      payload: input.payload,
    }),
  );
}

export function normalizeSecurityEventPath(path: string): string {
  const withoutQuery = path.split(/[?#]/, 1)[0] ?? "";
  const normalized = withoutQuery.toLowerCase().replace(/\/+$/, "");
  return normalized || "/";
}

export function securityEventDedupeKey(method: string, path: string): string {
  return `${method.toUpperCase()}:${normalizeSecurityEventPath(path)}`;
}

export class SecurityEventIdentityCap {
  private readonly seen = new Set<string>();

  resolve(writerId: string | undefined, baseKey: string): string {
    const scopedKey = `${writerId ?? "anonymous"}:${baseKey}`;
    if (this.seen.has(scopedKey)) return scopedKey;
    if (this.seen.size >= MAX_SECURITY_EVENT_IDENTITIES) {
      return AGGREGATE_SECURITY_EVENT_KEY;
    }
    this.seen.add(scopedKey);
    return scopedKey;
  }
}
