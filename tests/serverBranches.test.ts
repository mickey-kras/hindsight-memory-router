import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { MemoryQuarantineStore } from "../src/quarantineStore.js";
import { MemoryReviewQueue } from "../src/reviewQueue.js";
import {
  createMemoryRouterServer,
  type CreateMemoryRouterServerOptions,
} from "../src/server.js";

async function withServer<T>(
  options: CreateMemoryRouterServerOptions,
  run: (baseUrl: string) => Promise<T>,
): Promise<T> {
  const server = createMemoryRouterServer({
    registry: DEFAULT_REGISTRY,
    hindsight: new FakeHindsightGateway(),
    reviewQueue: new MemoryReviewQueue(),
    quarantineStore: new MemoryQuarantineStore(),
    ...options,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("unexpected server address");
  }
  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

describe("server request branches", () => {
  it("requires the configured router token", async () => {
    await withServer({ routerToken: "router-token" }, async (baseUrl) => {
      const unauthorized = await fetch(`${baseUrl}/version`);
      expect(unauthorized.status).toBe(401);

      const authorized = await fetch(`${baseUrl}/version`, {
        headers: { authorization: "Bearer router-token" },
      });
      expect(authorized.status).toBe(200);
    });
  });

  it("denies admin routes when no admin token is configured", async () => {
    await withServer({}, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/admin/quarantine/queue`);
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "unauthorized" });
    });
  });

  it("returns a structured error for unknown admin routes", async () => {
    await withServer({ adminToken: "admin-token" }, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/admin/unknown`, {
        headers: { authorization: "Bearer admin-token" },
      });
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({
        error: "admin_endpoint_not_found",
      });
    });
  });

  it("rejects malformed JSON request bodies", async () => {
    await withServer({}, async (baseUrl) => {
      const response = await fetch(
        `${baseUrl}/v1/default/banks/main/memories`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{not-json",
        },
      );
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_json" });
    });
  });

  it("rejects request bodies above the configured limit", async () => {
    await withServer({ maxBodyBytes: 8 }, async (baseUrl) => {
      const response = await fetch(
        `${baseUrl}/v1/default/banks/main/memories`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ items: [] }),
        },
      );
      expect(response.status).toBe(413);
      expect(await response.json()).toMatchObject({
        error: "payload_too_large",
      });
    });
  });
});
