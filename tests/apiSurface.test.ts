import { describe, expect, it, vi } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { createMemoryRouterServer } from "../src/server.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

async function withServer<T>(
  fn: (context: {
    baseUrl: string;
    repository: ReturnType<typeof memoryQuarantine>["repository"];
  }) => Promise<T>,
): Promise<T> {
  const quarantine = memoryQuarantine();
  const server = createMemoryRouterServer({
    registry: DEFAULT_REGISTRY,
    routerToken: "router-token",
    hindsight: new FakeHindsightGateway(),
    quarantineRepository: quarantine.repository,
    quarantineStore: quarantine.store,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("unexpected server address");
  }
  try {
    return await fn({
      baseUrl: `http://127.0.0.1:${address.port}`,
      repository: quarantine.repository,
    });
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

describe("memory-router API surface", () => {
  it("serves process health without database access", async () => {
    await withServer(async ({ baseUrl, repository }) => {
      vi.spyOn(repository, "ping").mockRejectedValue(
        new Error("database unavailable"),
      );
      const response = await fetch(`${baseUrl}/health`);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        status: "healthy",
        service: "memory-router",
      });
    });
  });

  it("serves readiness when quarantine storage is available", async () => {
    await withServer(async ({ baseUrl }) => {
      const response = await fetch(`${baseUrl}/ready`);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        status: "ready",
        service: "memory-router",
      });
    });
  });

  it("returns 503 readiness when quarantine storage is unavailable", async () => {
    await withServer(async ({ baseUrl, repository }) => {
      vi.spyOn(repository, "ping").mockRejectedValue(
        new Error("database unavailable"),
      );
      const response = await fetch(`${baseUrl}/ready`);
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({
        status: "not_ready",
        service: "memory-router",
      });
    });
  });

  it("serves version", async () => {
    await withServer(async ({ baseUrl }) => {
      const response = await fetch(`${baseUrl}/version`, {
        headers: { authorization: "Bearer router-token" },
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ api_version: "0.9.0" });
    });
  });

  it("denies and records unknown endpoints as encrypted events", async () => {
    await withServer(async ({ baseUrl, repository }) => {
      const response = await fetch(`${baseUrl}/v1/default/banks`, {
        headers: { authorization: "Bearer router-token" },
      });
      expect(response.status).toBe(404);
      expect(await response.json()).toMatchObject({
        error: "endpoint denied by memory-router policy",
      });
      expect(await repository.listReviewable()).toEqual([
        expect.objectContaining({
          kind: "security_event",
          reason: "denied_endpoint",
        }),
      ]);
    });
  });
});
