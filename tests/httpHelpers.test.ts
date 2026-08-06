import { describe, expect, it } from "vitest";
import { HttpError } from "../src/httpError.js";
import { integerQuery, parseRequestUrl } from "../src/httpHelpers.js";

describe("parseRequestUrl", () => {
  it("parses origin-form request targets", () => {
    const url = parseRequestUrl("/admin/quarantine/queue?limit=5");
    expect(url.pathname).toBe("/admin/quarantine/queue");
    expect(url.searchParams.get("limit")).toBe("5");
  });

  it("resolves dot segments before route matching", () => {
    expect(
      parseRequestUrl("/admin/../v1/default/banks/ops/memories").pathname,
    ).toBe("/v1/default/banks/ops/memories");
  });

  it("keeps encoded segments encoded for downstream decoding", () => {
    expect(parseRequestUrl("/v1/default/banks/a%2Fb/memories").pathname).toBe(
      "/v1/default/banks/a%2Fb/memories",
    );
  });

  it("accepts absolute-form request targets from proxies", () => {
    const url = parseRequestUrl("http://router.example:8890/health");
    expect(url.pathname).toBe("/health");
  });

  it("keeps protocol-relative targets in the path instead of the authority", () => {
    // Pins the string-concatenation form: with new URL(raw, base) a
    // "//host" target would displace the authority and collapse the
    // pathname to "/", losing the probe's real target from denied-endpoint
    // security events.
    const url = parseRequestUrl("//attacker.example/path");
    expect(url.hostname).toBe("memory-router.internal");
    expect(url.pathname).toBe("//attacker.example/path");
  });

  it("rejects unsupported relative and asterisk request-target forms", () => {
    for (const raw of ["health", "*"]) {
      let caught: unknown;
      try {
        parseRequestUrl(raw);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(HttpError);
      expect((caught as HttpError).status).toBe(400);
      expect((caught as HttpError).code).toBe("invalid_url");
    }
  });

  it("rejects malformed request targets with 400 invalid_url", () => {
    for (const raw of ["http://", "http://exa mple/", "https://["]) {
      let caught: unknown;
      try {
        parseRequestUrl(raw);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(HttpError);
      expect((caught as HttpError).status).toBe(400);
      expect((caught as HttpError).code).toBe("invalid_url");
    }
  });
});

describe("integerQuery over URLSearchParams", () => {
  const params = (search: string) => new URL(`http://x/${search}`).searchParams;

  it("returns the fallback when the parameter is absent", () => {
    expect(integerQuery(params("?other=1"), "limit", 100, 1, 500)).toBe(100);
  });

  it("parses a single in-range value", () => {
    expect(integerQuery(params("?limit=42"), "limit", 100, 1, 500)).toBe(42);
  });

  it("rejects repeated parameters", () => {
    expect(() =>
      integerQuery(params("?limit=1&limit=2"), "limit", 100, 1, 500),
    ).toThrow("limit is invalid");
  });

  it("rejects non-integer, out-of-range, and empty values", () => {
    for (const search of [
      "?limit=abc",
      "?limit=0",
      "?limit=501",
      "?limit=2.5",
      "?limit=",
    ]) {
      expect(() => integerQuery(params(search), "limit", 100, 1, 500)).toThrow(
        "limit is invalid",
      );
    }
  });
});
