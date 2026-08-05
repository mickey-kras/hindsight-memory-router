import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import {
  createMemoryRouterServer,
  type CreateMemoryRouterServerOptions,
} from "../src/server.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

async function withServer<T>(
  options: CreateMemoryRouterServerOptions,
  run: (baseUrl: string) => Promise<T>,
): Promise<T> {
  const quarantine = memoryQuarantine();
  const server = createMemoryRouterServer({
    registry: DEFAULT_REGISTRY,
    hindsight: new FakeHindsightGateway(),
    quarantineRepository: quarantine.repository,
    quarantineStore: quarantine.store,
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
      expect(await authorized.json()).toMatchObject({
        api_version: "0.9.0",
        features: { quarantine_database: true },
      });
    });
  });

  it("denies admin routes when no admin token is configured", async () => {
    await withServer({}, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/admin/quarantine/queue`);
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "unauthorized" });
    });
  });

  it("returns structured errors for unknown admin routes and invalid queries", async () => {
    await withServer({ adminToken: "admin-token" }, async (baseUrl) => {
      const headers = { authorization: "Bearer admin-token" };
      const unknown = await fetch(`${baseUrl}/admin/unknown`, { headers });
      expect(unknown.status).toBe(404);
      expect(await unknown.json()).toEqual({
        error: "admin_endpoint_not_found",
      });

      const invalidQuery = await fetch(
        `${baseUrl}/admin/quarantine/queue?limit=0`,
        { headers },
      );
      expect(invalidQuery.status).toBe(400);
      expect(await invalidQuery.json()).toMatchObject({
        error: "invalid_query",
      });
    });
  });

  it("returns 400 for malformed percent-encoding in memory paths", async () => {
    await withServer({ routerToken: "router-token" }, async (baseUrl) => {
      const headers = {
        authorization: "Bearer router-token",
        "content-type": "application/json",
      };
      const retain = await fetch(
        `${baseUrl}/v1/default/banks/%E0%A4%A/memories`,
        { method: "POST", headers, body: "{}" },
      );
      expect(retain.status).toBe(400);
      expect(await retain.json()).toMatchObject({
        error: "invalid_path_encoding",
      });

      const recall = await fetch(
        `${baseUrl}/v1/default/banks/%E0%A4%A/memories/recall`,
        { method: "POST", headers, body: "{}" },
      );
      expect(recall.status).toBe(400);
      expect(await recall.json()).toMatchObject({
        error: "invalid_path_encoding",
      });
    });
  });

  it("returns 400 for malformed percent-encoding in admin item paths", async () => {
    await withServer({ adminToken: "admin-token" }, async (baseUrl) => {
      const headers = { authorization: "Bearer admin-token" };
      const response = await fetch(`${baseUrl}/admin/quarantine/items/%ZZ`, {
        headers,
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({
        error: "invalid_path_encoding",
      });
    });
  });

  it("rejects malformed JSON request bodies", async () => {
    await withServer({ routerToken: "router-token" }, async (baseUrl) => {
      const response = await fetch(
        `${baseUrl}/v1/default/banks/main/memories`,
        {
          method: "POST",
          headers: {
            authorization: "Bearer router-token",
            "content-type": "application/json",
          },
          body: "{not-json",
        },
      );
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_json" });
    });
  });

  it("rejects request bodies above the configured limit", async () => {
    await withServer(
      { routerToken: "router-token", maxBodyBytes: 8 },
      async (baseUrl) => {
        const response = await fetch(
          `${baseUrl}/v1/default/banks/main/memories`,
          {
            method: "POST",
            headers: {
              authorization: "Bearer router-token",
              "content-type": "application/json",
            },
            body: JSON.stringify({ items: [] }),
          },
        );
        expect(response.status).toBe(413);
        expect(await response.json()).toMatchObject({
          error: "payload_too_large",
        });
      },
    );
  });

  it("encrypts denied endpoint security events", async () => {
    await withServer({ routerToken: "router-token" }, async (baseUrl) => {
      const response = await fetch(`${baseUrl}/unknown`, {
        headers: { authorization: "Bearer router-token" },
      });
      expect(response.status).toBe(404);
      expect(await response.json()).toMatchObject({
        error: "endpoint denied by memory-router policy",
      });
    });
  });
});
