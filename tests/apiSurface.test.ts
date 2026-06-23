import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { MemoryReviewQueue } from "../src/reviewQueue.js";
import { createMemoryRouterServer } from "../src/server.js";

async function withServer<T>(fn: (baseUrl: string, reviewQueue: MemoryReviewQueue) => Promise<T>): Promise<T> {
  const reviewQueue = new MemoryReviewQueue();
  const server = createMemoryRouterServer({ registry: DEFAULT_REGISTRY, hindsight: new FakeHindsightGateway(), reviewQueue });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("unexpected server address");
  try {
    return await fn(`http://127.0.0.1:${address.port}`, reviewQueue);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
}

describe("memory-router API surface", () => {
  it("serves health", async () => {
    await withServer(async (baseUrl) => {
      const res = await fetch(`${baseUrl}/health`);
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({ status: "healthy", service: "memory-router" });
    });
  });

  it("serves version", async () => {
    await withServer(async (baseUrl) => {
      const res = await fetch(`${baseUrl}/version`);
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({ api_version: "0.8.3" });
    });
  });

  it("denies unknown endpoints", async () => {
    await withServer(async (baseUrl, reviewQueue) => {
      const res = await fetch(`${baseUrl}/v1/default/banks`);
      expect(res.status).toBe(404);
      expect(await res.json()).toMatchObject({ error: "endpoint denied by memory-router policy" });
      expect(reviewQueue.records[0].reason).toBe("denied_endpoint");
    });
  });
});
