import { describe, expect, it } from "vitest";
import { HttpError, safeErrorBody } from "../src/httpError.js";

describe("HTTP error responses", () => {
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
