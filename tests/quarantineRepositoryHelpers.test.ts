import { describe, expect, it } from "vitest";
import { encryptedBytes, isExpired } from "../src/quarantine/repository.js";

describe("quarantine repository helpers", () => {
  it("measures encrypted envelopes", () => {
    const item = { encrypted: { version: 1 } };

    expect(encryptedBytes(item as never)).toBe(
      Buffer.byteLength(JSON.stringify(item.encrypted)),
    );
    expect(encryptedBytes(null)).toBe(0);
  });

  it("expires only reviewable items at or after their deadline", () => {
    const item = {
      status: "pending" as const,
      expires_at: "2026-08-06T00:00:00.000Z",
    };

    expect(isExpired(item as never, "2026-08-06T00:00:00.000Z")).toBe(true);
    expect(isExpired(item as never, "2026-08-05T23:59:59.999Z")).toBe(false);
    expect(
      isExpired({ ...item, status: "reviewed_allowed" } as never, "2026-08-07"),
    ).toBe(false);
  });
});
