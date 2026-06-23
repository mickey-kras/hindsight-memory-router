import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { MemoryReviewQueue } from "../src/reviewQueue.js";
import { createMemoryRouterServer } from "../src/server.js";

async function withServer<T>(
  fn: (
    baseUrl: string,
    hindsight: FakeHindsightGateway,
    reviewQueue: MemoryReviewQueue,
  ) => Promise<T>,
): Promise<T> {
  const hindsight = new FakeHindsightGateway();
  const reviewQueue = new MemoryReviewQueue();
  const server = createMemoryRouterServer({
    registry: DEFAULT_REGISTRY,
    hindsight,
    reviewQueue,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("unexpected server address");
  try {
    return await fn(`http://127.0.0.1:${address.port}`, hindsight, reviewQueue);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

describe("OpenClaw Hindsight plugin contract", () => {
  it("accepts retain payload shape produced by HindsightClient.retain", async () => {
    await withServer(async (baseUrl, hindsight) => {
      const res = await fetch(`${baseUrl}/v1/default/banks/main/memories`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          items: [
            {
              content: "Verified router contract retain payload.",
              context: "OpenClaw transcript",
              document_id: "openclaw:agent:main",
              metadata: { source: "openclaw" },
              tags: ["source_system:openclaw"],
              update_mode: "append",
            },
          ],
          async: true,
        }),
      });
      expect(res.status).toBe(200);
      expect(hindsight.retained).toHaveLength(1);
      expect(hindsight.retained[0].bankId).toBe("main");
    });
  });

  it("accepts recall payload shape produced by HindsightClient.recall", async () => {
    await withServer(async (baseUrl, hindsight) => {
      const res = await fetch(
        `${baseUrl}/v1/default/banks/dev/memories/recall`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            query: "What changed in the memory router?",
            max_tokens: 1024,
            budget: "mid",
            types: ["world", "experience"],
            trace: false,
          }),
        },
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.results.length).toBeGreaterThan(0);
      expect(hindsight.recalled.map((item) => item.bankId)).toEqual([
        "dev",
        "core",
      ]);
    });
  });

  it("logs unknown Hindsight endpoints instead of proxying them", async () => {
    await withServer(async (baseUrl, hindsight, reviewQueue) => {
      const res = await fetch(`${baseUrl}/v1/default/banks/main/config`);
      expect(res.status).toBe(404);
      expect(hindsight.retained).toHaveLength(0);
      expect(hindsight.recalled).toHaveLength(0);
      expect(reviewQueue.records[0]).toMatchObject({
        reason: "denied_endpoint",
        path: "/v1/default/banks/main/config",
      });
    });
  });
});
