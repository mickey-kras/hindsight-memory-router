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
  it("preserves valid retain bodies, nullable fields, and extensions", () => {
    const body = {
      items: [
        {
          content: "  keep original whitespace  ",
          context: null,
          document_id: null,
          metadata: null,
          tags: null,
          timestamp: null,
          update_mode: null,
          extension: { nested: [1, { enabled: true }] },
        },
      ],
      async: true,
      document_tags: ["doc"],
      extension: { nested: { value: 1 } },
    };

    expect(parseRetainBody(body)).toEqual(body);
  });

  it("preserves valid recall bodies, nullable fields, and extensions", () => {
    const body = {
      query: "  keep original whitespace  ",
      max_tokens: 1,
      budget: "mid" as const,
      types: null,
      tags: null,
      tags_match: "all",
      trace: true,
      extension: { nested: [1, { enabled: true }] },
    };

    expect(parseRecallBody(body)).toEqual(body);
  });

  it.each([
    [null, "retain body must be an object"],
    [[], "retain body must be an object"],
    [{}, "retain body requires at least one memory item"],
    [{ items: [] }, "retain body requires at least one memory item"],
    [{ items: null }, "retain body requires at least one memory item"],
    [{ items: [null] }, "memory item 0 must be an object"],
    [{ items: [{}] }, "memory item 0 content must be a non-empty string"],
    [
      { items: [{ content: "   " }] },
      "memory item 0 content must be a non-empty string",
    ],
    [
      { items: [{ content: "ok", context: 1 }] },
      "context must be a string or null",
    ],
    [
      { items: [{ content: "ok", document_id: 1 }] },
      "document_id must be a string or null",
    ],
    [
      { items: [{ content: "ok", timestamp: 1 }] },
      "timestamp must be a string or null",
    ],
    [{ items: [{ content: "ok", tags: [1] }] }, "tags must contain strings"],
    [
      { items: [{ content: "ok", metadata: { key: 1 } }] },
      "metadata must map strings to strings",
    ],
    [
      { items: [{ content: "ok", update_mode: "merge" }] },
      "update_mode must be replace or append",
    ],
    [{ items: [{ content: "ok" }], async: "true" }, "async must be a boolean"],
    [
      { items: [{ content: "ok" }], document_tags: [1] },
      "document_tags must contain strings",
    ],
  ])("rejects invalid retain shape %#", (value, message) => {
    expect(() => parseRetainBody(value)).toThrow(message);
  });

  it.each([
    [null, "recall body must be an object"],
    [[], "recall body must be an object"],
    [{}, "recall query must be a non-empty string"],
    [{ query: 1 }, "recall query must be a non-empty string"],
    [{ query: "   " }, "recall query must be a non-empty string"],
    [{ query: "ok", max_tokens: 0 }, "max_tokens must be a positive integer"],
    [{ query: "ok", max_tokens: -1 }, "max_tokens must be a positive integer"],
    [{ query: "ok", max_tokens: 1.5 }, "max_tokens must be a positive integer"],
    [{ query: "ok", max_tokens: "1" }, "max_tokens must be a positive integer"],
    [
      { query: "ok", max_tokens: Number.MAX_SAFE_INTEGER + 1 },
      "max_tokens must be a positive integer",
    ],
    [{ query: "ok", budget: "huge" }, "budget must be low, mid, or high"],
    [{ query: "ok", types: [1] }, "types must contain strings"],
    [{ query: "ok", tags: [1] }, "tags must contain strings"],
    [{ query: "ok", tags_match: 1 }, "tags_match must be a string"],
    [{ query: "ok", trace: "true" }, "trace must be a boolean"],
  ])("rejects invalid recall shape %#", (value, message) => {
    expect(() => parseRecallBody(value)).toThrow(message);
  });

  it("does not coerce request values", () => {
    expect(() =>
      parseRetainBody({ items: [{ content: 123 }], async: 1 }),
    ).toThrow("non-empty string");
    expect(() => parseRecallBody({ query: 123, trace: 1 })).toThrow(
      "non-empty string",
    );
  });

  it("returns stable HTTP errors for malformed retain and recall bodies", async () => {
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
    await expect(retain.json()).resolves.toEqual({
      error: "invalid_retain_body",
      message: "retain body requires at least one memory item",
    });

    const recall = await fetch(
      `${baseUrl}/v1/default/banks/ops/memories/recall`,
      { method: "POST", headers, body: "{}" },
    );
    expect(recall.status).toBe(400);
    await expect(recall.json()).resolves.toEqual({
      error: "invalid_recall_body",
      message: "recall query must be a non-empty string",
    });

    expect(hindsight.retained).toHaveLength(0);
    expect(hindsight.recalled).toHaveLength(0);
  });
});
