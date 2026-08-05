import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import {
  createMemoryRouterServer,
  type CreateMemoryRouterServerOptions,
} from "../src/server.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

async function withServer(
  options: CreateMemoryRouterServerOptions,
  run: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const quarantine = memoryQuarantine();
  const server = createMemoryRouterServer({
    registry: DEFAULT_REGISTRY,
    hindsight: new FakeHindsightGateway(),
    quarantineRepository: quarantine.repository,
    quarantineStore: quarantine.store,
    sweepIntervalSeconds: 0,
    ...options,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("unexpected server address");
  }
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

const auth = (token: string): Record<string, string> => ({
  authorization: `Bearer ${token}`,
});

async function cleanup(baseUrl: string, token: string): Promise<Response> {
  return fetch(`${baseUrl}/admin/quarantine/cleanup`, {
    method: "POST",
    headers: {
      ...auth(token),
      "content-type": "application/json",
    },
    body: JSON.stringify({ scope: "pending", dry_run: true }),
  });
}

async function reject(baseUrl: string, token: string): Promise<Response> {
  return fetch(`${baseUrl}/admin/quarantine/items/missing/reject`, {
    method: "POST",
    headers: auth(token),
  });
}

describe("scoped admin tokens", () => {
  it("limits the read token to read-only endpoints", async () => {
    await withServer({ adminReadToken: "read-token" }, async (baseUrl) => {
      expect(
        await fetch(`${baseUrl}/admin/quarantine/stats`, {
          headers: auth("read-token"),
        }),
      ).toMatchObject({ status: 200 });
      expect(await reject(baseUrl, "read-token")).toMatchObject({
        status: 401,
      });
      expect(await cleanup(baseUrl, "read-token")).toMatchObject({
        status: 401,
      });
    });
  });

  it("lets the review token read and review but not clean up", async () => {
    await withServer({ adminReviewToken: "review-token" }, async (baseUrl) => {
      expect(
        await fetch(`${baseUrl}/admin/quarantine/stats`, {
          headers: auth("review-token"),
        }),
      ).toMatchObject({ status: 200 });
      expect(await reject(baseUrl, "review-token")).toMatchObject({
        status: 404,
      });
      expect(await cleanup(baseUrl, "review-token")).toMatchObject({
        status: 401,
      });
    });
  });

  it("limits the cleanup token to cleanup", async () => {
    await withServer(
      { adminCleanupToken: "cleanup-token" },
      async (baseUrl) => {
        expect(await cleanup(baseUrl, "cleanup-token")).toMatchObject({
          status: 200,
        });
        expect(
          await fetch(`${baseUrl}/admin/quarantine/stats`, {
            headers: auth("cleanup-token"),
          }),
        ).toMatchObject({ status: 401 });
        expect(await reject(baseUrl, "cleanup-token")).toMatchObject({
          status: 401,
        });
      },
    );
  });

  it("keeps the legacy admin token as a migration superuser", async () => {
    await withServer({ adminToken: "legacy-token" }, async (baseUrl) => {
      expect(
        await fetch(`${baseUrl}/admin/quarantine/stats`, {
          headers: auth("legacy-token"),
        }),
      ).toMatchObject({ status: 200 });
      expect(await reject(baseUrl, "legacy-token")).toMatchObject({
        status: 404,
      });
      expect(await cleanup(baseUrl, "legacy-token")).toMatchObject({
        status: 200,
      });
    });
  });

  it("does not let one scoped token impersonate another scope", async () => {
    await withServer(
      {
        adminReadToken: "read-token",
        adminReviewToken: "review-token",
        adminCleanupToken: "cleanup-token",
      },
      async (baseUrl) => {
        expect(await cleanup(baseUrl, "read-token")).toMatchObject({
          status: 401,
        });
        expect(await cleanup(baseUrl, "review-token")).toMatchObject({
          status: 401,
        });
        expect(await reject(baseUrl, "read-token")).toMatchObject({
          status: 401,
        });
        expect(await reject(baseUrl, "cleanup-token")).toMatchObject({
          status: 401,
        });
      },
    );
  });
});
