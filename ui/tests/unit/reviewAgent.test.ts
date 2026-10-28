import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DecryptError } from "../../src/lib/quarantineCrypto";
import { decryptWithReviewAgent, REVIEW_AGENT_URL } from "../../src/lib/reviewAgent";
import type { DecryptedQuarantineObject, EncryptedQuarantineEnvelope } from "../../src/lib/types";

const fixtures = new URL("../fixtures/", import.meta.url);
const envelope = JSON.parse(
  readFileSync(new URL("q_provider_0123456789abcdef.envelope.json", fixtures), "utf8"),
) as EncryptedQuarantineEnvelope;
const decrypted: DecryptedQuarantineObject = {
  quarantine_id: "q_provider_0123456789abcdef",
  created_at: "2026-09-16T18:25:46.000000+00:00",
  reason: "suspicious_content",
  payload: { action: "security_event" },
};

afterEach(() => vi.unstubAllGlobals());

describe("local review agent", () => {
  it("verifies an agent-reviewed provider envelope without sending router tokens", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ decrypted }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await decryptWithReviewAgent(envelope, "s".repeat(32))).toEqual(decrypted);
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(REVIEW_AGENT_URL);
    expect(new Headers(options.headers).get("Authorization")).toBe(`Bearer ${"s".repeat(32)}`);
    expect(JSON.parse(options.body as string)).toEqual({ envelope });
    expect(options.credentials).toBe("omit");
  });

  it("rejects missing credentials without contacting the agent", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(decryptWithReviewAgent(envelope, "")).rejects.toThrow(DecryptError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an unavailable or unauthorized agent", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 403 })));
    await expect(decryptWithReviewAgent(envelope, "s".repeat(32))).rejects.toThrow("rejected");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    await expect(decryptWithReviewAgent(envelope, "s".repeat(32))).rejects.toThrow("unavailable");
  });

  it("rejects incorrect digest, metadata or response shape", async () => {
    for (const value of [
      { ...decrypted, payload: { altered: true } },
      { ...decrypted, reason: "auth_failed" },
      { junk: true },
    ]) {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
        JSON.stringify({ decrypted: value }), { status: 200 },
      )));
      await expect(decryptWithReviewAgent(envelope, "s".repeat(32))).rejects.toThrow(DecryptError);
    }
  });
});
