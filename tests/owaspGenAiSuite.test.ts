import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { createMemoryRouterServer } from "../src/server.js";
import type { WriterRegistry } from "../src/types.js";

const registry: WriterRegistry = {
  writers: {
    main: {
      role: "orchestrator",
      source: "test",
      write_bank: "main",
      read_banks: ["main", "core", "ops", "dev", "creative", "personal"],
    },
  },
  defaults: {
    unknown_writer_action: "review_queue",
    suspicious_content_action: "review_queue",
    review_queue_path: "/tmp/review.jsonl",
  },
};

const owaspMatrix = [
  ["LLM01", "Prompt Injection", "mapped"],
  ["LLM02", "Sensitive Information Disclosure", "mapped"],
  ["LLM03", "Supply Chain", "documented"],
  ["LLM04", "Data and Model Poisoning", "mapped"],
  ["LLM05", "Improper Output Handling", "mapped"],
  ["LLM06", "Excessive Agency", "mapped"],
  ["LLM07", "System Prompt Leakage", "mapped"],
  ["LLM08", "Vector and Embedding Weaknesses", "mapped"],
  ["LLM09", "Misinformation", "mapped"],
  ["LLM10", "Unbounded Consumption", "mapped"],
] as const;

async function withServer<T>(
  options: { maxBodyBytes?: number },
  fn: (baseUrl: string) => Promise<T>,
): Promise<T> {
  const server = createMemoryRouterServer({
    registry,
    routerToken: "router-token",
    adminToken: "admin-token",
    maxBodyBytes: options.maxBodyBytes,
    hindsight: new FakeHindsightGateway(),
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("bad address");
  try {
    return await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

describe("OWASP GenAI quarantine regression scaffold", () => {
  it("tracks every OWASP GenAI Top 10 2025 category", () => {
    expect(owaspMatrix.map(([id]) => id)).toEqual([
      "LLM01",
      "LLM02",
      "LLM03",
      "LLM04",
      "LLM05",
      "LLM06",
      "LLM07",
      "LLM08",
      "LLM09",
      "LLM10",
    ]);
    expect(owaspMatrix.every(([, , status]) => status.length > 0)).toBe(true);
  });

  it("rejects malformed JSON with a safe structured response", async () => {
    await withServer({}, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/v1/default/banks/main/memories`, {
        method: "POST",
        headers: {
          authorization: "Bearer router-token",
          "content-type": "application/json",
        },
        body: "{not-json",
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({
        error: "invalid_json",
        message: "invalid JSON body",
      });
    });
  });

  it("rejects oversized JSON with a safe structured response", async () => {
    await withServer({ maxBodyBytes: 32 }, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/v1/default/banks/main/memories`, {
        method: "POST",
        headers: {
          authorization: "Bearer router-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({ items: [{ content: "x".repeat(100) }] }),
      });
      expect(response.status).toBe(413);
      expect(await response.json()).toMatchObject({
        error: "payload_too_large",
        message: "payload too large",
      });
    });
  });
});
