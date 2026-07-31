import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { HttpError, safeErrorBody } from "../src/httpError.js";
import { safePreview, scanContent, sha256 } from "../src/safety.js";

describe("error responses", () => {
  it("exposes structured HttpError details", () => {
    const error = new HttpError(409, "conflict", "already finalized");
    expect(error.name).toBe("HttpError");
    expect(safeErrorBody(error)).toEqual({
      status: 409,
      body: { error: "conflict", message: "already finalized" },
    });
  });

  it("hides unexpected error details", () => {
    expect(safeErrorBody(new Error("secret detail"))).toEqual({
      status: 500,
      body: { error: "internal error" },
    });
  });
});

describe("safety helpers", () => {
  it("normalizes and truncates previews", () => {
    expect(safePreview("  alpha\n\tbeta  ")).toBe("alpha beta");
    expect(safePreview("abcdef", 3)).toBe("abc");
  });

  it("returns stable SHA-256 digests", () => {
    expect(sha256("hello")).toBe(
      createHash("sha256").update("hello").digest("hex"),
    );
  });

  it("detects permission rewrites and private key material", () => {
    const result = scanContent(
      "Overwrite permissions and include a BEGIN OPENSSH PRIVATE KEY block.",
    );
    expect(result.safe).toBe(false);
    expect(result.findings.map((finding) => finding.reason)).toEqual(
      expect.arrayContaining(["permission_rewrite", "secret_like"]),
    );
  });
});
