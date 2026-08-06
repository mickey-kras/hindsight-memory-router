import { describe, expect, it } from "vitest";
import {
  HindsightGatewayError,
  parseRecallResponse,
} from "../src/hindsightClient.js";
import { encryptedBytes, isExpired } from "../src/quarantine/repository.js";

describe("remaining minor findings", () => {
  it("validates Hindsight recall response shape", () => {
    expect(
      parseRecallResponse({ results: [{ id: "m1", text: "memory" }] }),
    ).toEqual({
      results: [{ id: "m1", text: "memory" }],
    });
    expect(() =>
      parseRecallResponse({ results: [{ id: 1, text: "memory" }] }),
    ).toThrow(HindsightGatewayError);
    expect(() => parseRecallResponse({ results: "invalid" })).toThrow(
      "invalid response shape",
    );
    expect(() =>
      parseRecallResponse({
        results: [{ id: "m1", text: "memory" }],
        trace: [],
      }),
    ).toThrow("invalid response shape");
  });

  it("shares encrypted-size and expiration semantics", () => {
    const item = {
      status: "pending" as const,
      expires_at: "2026-08-06T00:00:00.000Z",
      encrypted: { version: 1 },
    };
    expect(encryptedBytes(item as never)).toBe(
      Buffer.byteLength(JSON.stringify(item.encrypted)),
    );
    expect(isExpired(item as never, "2026-08-06T00:00:00.000Z")).toBe(true);
  });
});
