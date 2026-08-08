import { describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { createMemoryRouterServer } from "../src/server.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

async function withServer<T>(
  run: (context: {
    baseUrl: string;
    hindsight: FakeHindsightGateway;
    repository: ReturnType<typeof memoryQuarantine>["repository"];
  }) => Promise<T>,
): Promise<T> {
  const hindsight = new FakeHindsightGateway();
  const quarantine = memoryQuarantine();
  const server = createMemoryRouterServer({
    registry: DEFAULT_REGISTRY,
    routerToken: "router-token",
    hindsight,
    quarantineRepository: quarantine.repository,
    quarantineStore: quarantine.store,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("unexpected server address");
  }
  try {
    return await run({
      baseUrl: `http://127.0.0.1:${address.port}`,
      hindsight,
      repository: quarantine.repository,
    });
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

describe("OpenClaw Hindsight plugin contract", () => {
  it("accepts the retain payload produced by HindsightClient.retain", async () => {
    await withServer(async ({ baseUrl, hindsight }) => {
      const response = await fetch(
        `${baseUrl}/v1/default/banks/main/memories`,
        {
          method: "POST",
          headers: {
            authorization: "Bearer router-token",
            "content-type": "application/json",
          },
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
        },
      );
      expect(response.status).toBe(200);
      expect(hindsight.retained).toHaveLength(1);
      expect(hindsight.retained[0].bankId).toBe("main");
    });
  });

  it("accepts the recall payload produced by HindsightClient.recall", async () => {
    await withServer(async ({ baseUrl, hindsight }) => {
      const response = await fetch(
        `${baseUrl}/v1/default/banks/main/memories/recall`,
        {
          method: "POST",
          headers: {
            authorization: "Bearer router-token",
            "content-type": "application/json",
          },
          body: JSON.stringify({
            query: "What changed in the memory router?",
            max_tokens: 1024,
            budget: "mid",
            types: ["world", "experience"],
            trace: false,
          }),
        },
      );
      expect(response.status).toBe(200);
      const body = (await response.json()) as { results: unknown[] };
      expect(body.results.length).toBeGreaterThan(0);
      expect(hindsight.recalled.map((item) => item.bankId)).toEqual(["main"]);
    });
  });

  it("records unknown Hindsight endpoints instead of proxying them", async () => {
    await withServer(async ({ baseUrl, hindsight, repository }) => {
      const response = await fetch(`${baseUrl}/v1/default/banks/main/config`, {
        headers: { authorization: "Bearer router-token" },
      });
      expect(response.status).toBe(404);
      expect(hindsight.retained).toHaveLength(0);
      expect(hindsight.recalled).toHaveLength(0);
      expect(await repository.listReviewable()).toEqual([
        expect.objectContaining({
          kind: "security_event",
          reason: "denied_endpoint",
        }),
      ]);
    });
  });
});
