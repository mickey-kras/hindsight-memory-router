import { afterEach, describe, expect, it, vi } from "vitest";
import { FakeHindsightGateway } from "../src/hindsightClient.js";
import {
  DEFAULT_HINDSIGHT_LIMITS,
  HindsightLimits,
  hindsightLimitConfigFromEnv,
  type HindsightLimitConfig,
} from "../src/hindsightLimits.js";
import { InMemorySlidingWindowRateLimiter } from "../src/quarantine/rateLimiter.js";
import { DEFAULT_REGISTRY } from "../src/registry.js";
import { createMemoryRouterServer } from "../src/server.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

afterEach(() => vi.unstubAllEnvs());

function limits(
  overrides: Partial<HindsightLimitConfig> = {},
): HindsightLimitConfig {
  return { ...DEFAULT_HINDSIGHT_LIMITS, ...overrides };
}

describe("Hindsight request limits", () => {
  it("isolates per-writer quota while enforcing a global ceiling", async () => {
    const limiter = new InMemorySlidingWindowRateLimiter();
    const control = new HindsightLimits(
      limits({ retainWriterMax: 1, retainGlobalMax: 2 }),
      limiter,
      () => 1_000,
    );
    const body = { items: [{ content: "ordinary" }] };

    await control.consumeRetain("writer-a", body);
    await control.consumeRetain("writer-b", body);
    await expect(control.consumeRetain("writer-a", body)).rejects.toMatchObject({
      status: 429,
      code: "hindsight_rate_limited",
    });
    await expect(control.consumeRetain("writer-c", body)).rejects.toMatchObject({
      status: 429,
      code: "hindsight_rate_limited",
    });
  });

  it("uses separate retain and recall budgets", async () => {
    const control = new HindsightLimits(
      limits({
        retainWriterMax: 1,
        retainGlobalMax: 10,
        recallWriterMax: 1,
        recallGlobalMax: 10,
      }),
      new InMemorySlidingWindowRateLimiter(),
      () => 1_000,
    );

    await control.consumeRetain("writer-a", {
      items: [{ content: "ordinary" }],
    });
    await control.consumeRecall("writer-a", { query: "ordinary" });

    await expect(
      control.consumeRetain("writer-a", {
        items: [{ content: "ordinary again" }],
      }),
    ).rejects.toMatchObject({ status: 429 });
    await expect(
      control.consumeRecall("writer-a", { query: "ordinary again" }),
    ).rejects.toMatchObject({ status: 429 });
  });

  it("accepts exact request-boundary values", async () => {
    const control = new HindsightLimits(
      limits({
        maxRetainItems: 2,
        maxRetainContentBytes: 4,
        maxRecallQueryBytes: 4,
        maxRecallMaxTokens: 10,
      }),
      new InMemorySlidingWindowRateLimiter(),
      () => 1_000,
    );

    await expect(
      control.consumeRetain("writer-a", {
        items: [{ content: "é" }, { content: "é" }],
      }),
    ).resolves.toBeUndefined();
    await expect(
      control.consumeRecall("writer-a", { query: "éé", max_tokens: 10 }),
    ).resolves.toBeUndefined();
  });

  it("rejects oversized retain and recall fields with stable 413 errors", async () => {
    const config = limits({
      maxRetainItems: 1,
      maxRetainContentBytes: 4,
      maxRecallQueryBytes: 4,
      maxRecallMaxTokens: 10,
    });

    await expect(
      new HindsightLimits(config).consumeRetain("writer-a", {
        items: [{ content: "a" }, { content: "b" }],
      }),
    ).rejects.toMatchObject({ status: 413, code: "retain_item_limit_exceeded" });
    await expect(
      new HindsightLimits(config).consumeRetain("writer-a", {
        items: [{ content: "hello" }],
      }),
    ).rejects.toMatchObject({ status: 413, code: "retain_content_too_large" });
    await expect(
      new HindsightLimits(config).consumeRecall("writer-a", {
        query: "hello",
      }),
    ).rejects.toMatchObject({ status: 413, code: "recall_query_too_large" });
    await expect(
      new HindsightLimits(config).consumeRecall("writer-a", {
        query: "ok",
        max_tokens: 11,
      }),
    ).rejects.toMatchObject({ status: 413, code: "recall_max_tokens_exceeded" });
  });

  it("returns Retry-After for rate-limit responses", async () => {
    const control = new HindsightLimits(
      limits({ retainWriterMax: 1, rateLimitWindowMs: 1_001 }),
      new InMemorySlidingWindowRateLimiter(),
      () => 1_000,
    );
    const body = { items: [{ content: "ordinary" }] };
    await control.consumeRetain("writer-a", body);

    await expect(control.consumeRetain("writer-a", body)).rejects.toMatchObject({
      status: 429,
      code: "hindsight_rate_limited",
      headers: { "retry-after": "2" },
    });
  });

  it.each([
    "HINDSIGHT_RETAIN_RATE_LIMIT_WRITER_MAX",
    "HINDSIGHT_RETAIN_RATE_LIMIT_GLOBAL_MAX",
    "HINDSIGHT_RECALL_RATE_LIMIT_WRITER_MAX",
    "HINDSIGHT_RECALL_RATE_LIMIT_GLOBAL_MAX",
    "HINDSIGHT_RATE_LIMIT_WINDOW_MS",
    "HINDSIGHT_RETAIN_MAX_ITEMS",
    "HINDSIGHT_RETAIN_MAX_CONTENT_BYTES",
    "HINDSIGHT_RECALL_MAX_QUERY_BYTES",
    "HINDSIGHT_RECALL_MAX_TOKENS",
  ])("rejects invalid %s configuration", (name) => {
    expect(() => hindsightLimitConfigFromEnv({ [name]: "0" })).toThrow(name);
  });

  it("rejects invalid Hindsight configuration when the server starts", () => {
    vi.stubEnv("HINDSIGHT_RECALL_MAX_TOKENS", "0");
    const quarantine = memoryQuarantine();

    expect(() =>
      createMemoryRouterServer({
        registry: DEFAULT_REGISTRY,
        hindsight: new FakeHindsightGateway(),
        quarantineRepository: quarantine.repository,
        quarantineStore: quarantine.store,
      }),
    ).toThrow("HINDSIGHT_RECALL_MAX_TOKENS");
  });
});

describe("Hindsight request-limit server integration", () => {
  it("rejects oversized requests before Hindsight", async () => {
    await withServer(
      limits({
        maxRetainItems: 1,
        maxRetainContentBytes: 4,
        maxRecallQueryBytes: 4,
        maxRecallMaxTokens: 10,
      }),
      async (baseUrl, hindsight) => {
        const cases = [
          [
            "/v1/default/banks/main/memories",
            { items: [{ content: "a" }, { content: "b" }] },
            "retain_item_limit_exceeded",
          ],
          [
            "/v1/default/banks/main/memories",
            { items: [{ content: "hello" }] },
            "retain_content_too_large",
          ],
          [
            "/v1/default/banks/main/memories/recall",
            { query: "hello" },
            "recall_query_too_large",
          ],
          [
            "/v1/default/banks/main/memories/recall",
            { query: "ok", max_tokens: 11 },
            "recall_max_tokens_exceeded",
          ],
        ] as const;

        for (const [path, body, code] of cases) {
          const response = await post(baseUrl, path, body);
          expect(response.status).toBe(413);
          expect(await response.json()).toMatchObject({ error: code });
        }
        expect(hindsight.retained).toHaveLength(0);
        expect(hindsight.recalled).toHaveLength(0);
      },
    );
  });

  it("rate-limits before the second Hindsight call", async () => {
    await withServer(
      limits({ retainWriterMax: 1, retainGlobalMax: 10 }),
      async (baseUrl, hindsight) => {
        const body = { items: [{ content: "ordinary memory" }] };
        expect(
          (await post(baseUrl, "/v1/default/banks/main/memories", body)).status,
        ).toBe(200);
        const rejected = await post(
          baseUrl,
          "/v1/default/banks/main/memories",
          body,
        );

        expect(rejected.status).toBe(429);
        expect(rejected.headers.get("retry-after")).toBe("60");
        expect(await rejected.json()).toMatchObject({
          error: "hindsight_rate_limited",
        });
        expect(hindsight.retained).toHaveLength(1);
      },
    );
  });

  it("preserves normal behavior below the configured limits", async () => {
    await withServer(DEFAULT_HINDSIGHT_LIMITS, async (baseUrl, hindsight) => {
      expect(
        (
          await post(baseUrl, "/v1/default/banks/main/memories", {
            items: [{ content: "ordinary memory" }],
          })
        ).status,
      ).toBe(200);
      expect(
        (
          await post(baseUrl, "/v1/default/banks/main/memories/recall", {
            query: "ordinary query",
          })
        ).status,
      ).toBe(200);

      expect(hindsight.retained).toHaveLength(1);
      expect(hindsight.recalled.length).toBeGreaterThan(0);
    });
  });
});

async function withServer(
  config: HindsightLimitConfig,
  run: (baseUrl: string, hindsight: FakeHindsightGateway) => Promise<void>,
): Promise<void> {
  const quarantine = memoryQuarantine();
  const hindsight = new FakeHindsightGateway();
  const server = createMemoryRouterServer({
    routerToken: "router-token",
    registry: DEFAULT_REGISTRY,
    hindsight,
    hindsightLimits: config,
    quarantineRepository: quarantine.repository,
    quarantineStore: quarantine.store,
    sweepIntervalSeconds: 0,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("unexpected server address");
  }
  try {
    await run(`http://127.0.0.1:${address.port}`, hindsight);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

function post(baseUrl: string, path: string, body: unknown): Promise<Response> {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      authorization: "Bearer router-token",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}
