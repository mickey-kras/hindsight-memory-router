// RFC 8785 (JCS) canonical JSON, matching memory_router/canonical.py.
// Key order: UTF-16 code units, which is exactly Array.prototype.sort default.
// Number format: JSON.stringify already implements ECMAScript Number::toString,
// which is what RFC 8785 requires.

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

function assertJcsSafe(value: unknown): asserts value is JsonValue {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite JSON number");
    // Python's canonical.py rejects ints beyond 2^53-1. JS cannot distinguish
    // large ints from floats (every double above 2^53 is integer-valued), so
    // that guard is unenforceable here; JSON.parse has already lost the
    // precision by the time we see the value.
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) assertJcsSafe(entry);
    return;
  }
  if (typeof value === "object") {
    for (const key of Object.keys(value as object)) {
      assertJcsSafe((value as Record<string, unknown>)[key]);
    }
    return;
  }
  throw new Error("value must contain JSON values only");
}

function serialize(value: JsonValue): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  const keys = Object.keys(value).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${serialize(value[key] as JsonValue)}`);
  return `{${parts.join(",")}}`;
}

export function canonicalJson(value: unknown): string {
  assertJcsSafe(value);
  return serialize(value);
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
