import { describe, expect, it } from "vitest";
import { canonicalJson, sha256Hex } from "../../src/lib/jcs";

describe("canonicalJson (RFC 8785)", () => {
  it("sorts keys by UTF-16 code units", () => {
    expect(canonicalJson({ b: 1, a: 2, Z: 3, ä: 4 })).toBe('{"Z":3,"a":2,"b":1,"ä":4}');
  });

  it("serializes numbers with ECMAScript Number::toString", () => {
    expect(canonicalJson([1, 1.5, -0, 1.5e21, 0.000001])).toBe("[1,1.5,0,1.5e+21,0.000001]");
  });

  it("handles nested structures without whitespace", () => {
    expect(canonicalJson({ x: [{ a: [true, null, "s"] }] })).toBe('{"x":[{"a":[true,null,"s"]}]}');
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalJson(Number.NaN)).toThrow("non-finite JSON number");
    expect(() => canonicalJson(Infinity)).toThrow("non-finite JSON number");
  });

  it("rejects non-JSON values", () => {
    expect(() => canonicalJson(undefined)).toThrow("JSON values only");
    expect(() => canonicalJson(() => 1)).toThrow("JSON values only");
  });
});

describe("sha256Hex", () => {
  it("hashes UTF-8 text", async () => {
    expect(await sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
