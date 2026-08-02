import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import { parseRecallBody, parseRetainBody } from "../src/requestValidation.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { createMemoryRouterServer } from "../src/server.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve())),
          ),
      ),
  );
});

describe("router request validation", () => {
  it("validates retain and recall structures", () => {
    expect(() => parseRetainBody({})).toThrow("at least one memory item");
    expect(() => parseRetainBody({ items: [{ content: "   " }] })).toThrow(
      "non-empty string",
    );
    expect(() =>
      parseRetainBody({ items: [{ content: "ok", tags: [1] }] }),
    ).toThrow("tags must contain strings");
    expect(
      parseRetainBody({ items: [{ content: "ok" }], async: true }),
    ).toEqual({ items: [{ content: "ok" }], async: true });

    expect(() => parseRecallBody({})).toThrow("non-empty string");
    expect(() => parseRecallBody({ query: "ok", max_tokens: 0 })).toThrow(
      "positive integer",
    );
    expect(() => parseRecallBody({ query: "ok", budget: "huge" })).toThrow(
      "low, mid, or high",
    );
    expect(parseRecallBody({ query: "what happened?", trace: true })).toEqual({
      query: "what happened?",
      trace: true,
    });
  });

  it("returns 400 for malformed retain and recall HTTP bodies", async () => {
    const hindsight = new FakeHindsightGateway();
    const quarantine = memoryQuarantine();
    const server = createMemoryRouterServer({
      registry: DEFAULT_REGISTRY,
      routerToken: "router-token",
      hindsight,
      quarantineRepository: quarantine.repository,
      quarantineStore: quarantine.store,
    });
    servers.push(server);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("unexpected server address");
    }
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const headers = {
      authorization: "Bearer router-token",
      "content-type": "application/json",
    };

    const retain = await fetch(`${baseUrl}/v1/default/banks/ops/memories`, {
      method: "POST",
      headers,
      body: "{}",
    });
    expect(retain.status).toBe(400);
    await expect(retain.json()).resolves.toMatchObject({
      error: "invalid_retain_body",
    });

    const recall = await fetch(
      `${baseUrl}/v1/default/banks/ops/memories/recall`,
      { method: "POST", headers, body: "{}" },
    );
    expect(recall.status).toBe(400);
    await expect(recall.json()).resolves.toMatchObject({
      error: "invalid_recall_body",
    });

    expect(hindsight.retained).toHaveLength(0);
    expect(hindsight.recalled).toHaveLength(0);
  });
});
