import { describe, expect, it } from "vitest";
import {
  MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER,
  normalizeForDedupe,
  normalizeSecurityEventPath,
  requestDedupeKey,
  SecurityEventIdentityCap,
  securityEventDedupeKey,
} from "../src/quarantine/dedupeKey.js";

describe("normalizeForDedupe", () => {
  it("trims strings and collapses internal whitespace runs", () => {
    expect(normalizeForDedupe("  a \n\t b  ")).toBe("a b");
    expect(
      normalizeForDedupe({ text: " x  y ", nested: [" z ", 1, null, true] }),
    ).toEqual({ text: "x y", nested: ["z", 1, null, true] });
  });

  it("leaves non-string scalars and array order untouched", () => {
    expect(normalizeForDedupe([3, 1, 2])).toEqual([3, 1, 2]);
    expect(normalizeForDedupe(42)).toBe(42);
    expect(normalizeForDedupe(null)).toBeNull();
  });
});

describe("requestDedupeKey", () => {
  const base = {
    kind: "retain_request",
    writerId: "ghost",
    payload: { action: "retain", body: { items: [{ content: "hello" }] } },
  } as const;

  it("is stable across whitespace, key order, and formatting variants", () => {
    const variant = requestDedupeKey({
      kind: "retain_request",
      writerId: "ghost",
      payload: { body: { items: [{ content: " hello  " }] }, action: "retain" },
    });
    expect(variant).toBe(requestDedupeKey(base));
  });

  it("differs when content, kind, writer, or target genuinely differ", () => {
    const original = requestDedupeKey(base);
    expect(original).toMatch(/^[0-9a-f]{64}$/);
    expect(
      requestDedupeKey({
        ...base,
        payload: { action: "retain", body: { items: [{ content: "hello!" }] } },
      }),
    ).not.toBe(original);
    expect(requestDedupeKey({ ...base, kind: "recall_request" })).not.toBe(
      original,
    );
    expect(requestDedupeKey({ ...base, writerId: "other" })).not.toBe(original);
    expect(requestDedupeKey({ ...base, target: "ops" })).not.toBe(original);
    expect(requestDedupeKey({ ...base, writerId: undefined })).not.toBe(
      original,
    );
  });
});

describe("normalizeSecurityEventPath", () => {
  it("strips query strings and fragments", () => {
    expect(normalizeSecurityEventPath("/a/b?x=1&y=2")).toBe("/a/b");
    expect(normalizeSecurityEventPath("/a/b#frag")).toBe("/a/b");
  });

  it("lowercases and collapses trailing slashes", () => {
    expect(normalizeSecurityEventPath("/Admin/")).toBe("/admin");
    expect(normalizeSecurityEventPath("/ADMIN///")).toBe("/admin");
    expect(normalizeSecurityEventPath("/")).toBe("/");
    expect(normalizeSecurityEventPath("")).toBe("/");
  });

  it("builds method-scoped dedupe keys", () => {
    expect(securityEventDedupeKey("get", "/A/?q=1")).toBe("GET:/a");
    expect(securityEventDedupeKey("POST", "/a")).toBe("POST:/a");
  });
});

describe("SecurityEventIdentityCap", () => {
  it("keeps distinct keys until the cap, then buckets into an aggregate", () => {
    const cap = new SecurityEventIdentityCap();
    for (
      let index = 0;
      index < MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER;
      index += 1
    ) {
      expect(cap.resolve("w", `GET:/p-${index}`)).toBe(`GET:/p-${index}`);
    }
    expect(cap.resolve("w", "GET:/p-0")).toBe("GET:/p-0");
    expect(cap.resolve("w", "GET:/overflow")).toBe("aggregate:w");
    expect(cap.resolve("w", "POST:/overflow")).toBe("aggregate:w");
    // Unscoped (anonymous) and other writers track their own budgets.
    expect(cap.resolve(undefined, "GET:/overflow")).toBe("GET:/overflow");
    expect(cap.resolve("other", "GET:/overflow")).toBe("GET:/overflow");
    for (
      let index = 0;
      index < MAX_SECURITY_EVENT_IDENTITIES_PER_WRITER;
      index += 1
    ) {
      cap.resolve(undefined, `GET:/anon-${index}`);
    }
    expect(cap.resolve(undefined, "GET:/anon-overflow")).toBe(
      "aggregate:anonymous",
    );
  });
});
