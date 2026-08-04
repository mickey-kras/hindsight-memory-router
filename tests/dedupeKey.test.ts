import { describe, expect, it } from "vitest";
import {
  MAX_SECURITY_EVENT_IDENTITIES,
  normalizeSecurityEventPath,
  requestDedupeKey,
  SecurityEventIdentityCap,
  securityEventDedupeKey,
} from "../src/quarantine/dedupeKey.js";

describe("requestDedupeKey", () => {
  const base = {
    kind: "retain_request",
    writerId: "ghost",
    payload: { action: "retain", body: { items: [{ content: "hello" }] } },
  } as const;

  it("is stable across object key order and JSON formatting", () => {
    const variant = requestDedupeKey({
      kind: "retain_request",
      writerId: "ghost",
      payload: { body: { items: [{ content: "hello" }] }, action: "retain" },
    });
    expect(variant).toBe(requestDedupeKey(base));
  });

  it("does not merge semantically different string content", () => {
    const original = requestDedupeKey(base);
    expect(
      requestDedupeKey({
        ...base,
        payload: { action: "retain", body: { items: [{ content: "hello  " }] } },
      }),
    ).not.toBe(original);
    expect(
      requestDedupeKey({
        ...base,
        payload: { action: "retain", body: { items: [{ content: "hello!" }] } },
      }),
    ).not.toBe(original);
  });

  it("scopes identity by kind, writer, and policy target", () => {
    const original = requestDedupeKey(base);
    expect(original).toMatch(/^[0-9a-f]{64}$/);
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
  it("normalizes query strings, fragments, casing, and trailing slashes", () => {
    expect(normalizeSecurityEventPath("/a/b?x=1&y=2")).toBe("/a/b");
    expect(normalizeSecurityEventPath("/a/b#frag")).toBe("/a/b");
    expect(normalizeSecurityEventPath("/ADMIN///")).toBe("/admin");
    expect(normalizeSecurityEventPath("/")).toBe("/");
    expect(normalizeSecurityEventPath("")).toBe("/");
  });

  it("builds method-scoped keys", () => {
    expect(securityEventDedupeKey("get", "/A/?q=1")).toBe("GET:/a");
    expect(securityEventDedupeKey("POST", "/a")).toBe("POST:/a");
  });
});

describe("SecurityEventIdentityCap", () => {
  it("scopes identities by writer and bounds total process memory", () => {
    const cap = new SecurityEventIdentityCap();
    expect(cap.resolve("writer-a", "GET:/same")).toBe("writer-a:GET:/same");
    expect(cap.resolve("writer-b", "GET:/same")).toBe("writer-b:GET:/same");
    expect(cap.resolve(undefined, "GET:/same")).toBe("anonymous:GET:/same");

    for (let index = 3; index < MAX_SECURITY_EVENT_IDENTITIES; index += 1) {
      expect(cap.resolve(`writer-${index}`, `GET:/p-${index}`)).toBe(
        `writer-${index}:GET:/p-${index}`,
      );
    }

    expect(cap.resolve("writer-a", "GET:/same")).toBe("writer-a:GET:/same");
    expect(cap.resolve("new-writer", "GET:/overflow")).toBe("aggregate");
    expect(cap.resolve("another-writer", "POST:/overflow")).toBe("aggregate");
  });
});
