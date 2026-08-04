import { afterEach, describe, expect, it, vi } from "vitest";
import {
  FakeHindsightGateway,
  FetchHindsightGateway,
  HindsightGatewayError,
} from "../src/hindsightClient.js";

function mockFetch(...responses: Response[]) {
  const fetchMock = vi.fn();
  for (const response of responses) {
    fetchMock.mockResolvedValueOnce(response);
  }
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("FetchHindsightGateway", () => {
  it("sends authenticated health requests without a duplicate slash", async () => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify({ status: "healthy" }), { status: 200 }),
    );
    const gateway = new FetchHindsightGateway("https://hindsight.test/", "key");

    await expect(gateway.health()).resolves.toEqual({ status: "healthy" });
    expect(fetchMock).toHaveBeenCalledWith("https://hindsight.test/health", {
      method: "GET",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer key",
      },
      body: undefined,
      signal: expect.any(AbortSignal),
    });
  });

  it("returns null for an empty response without adding authorization", async () => {
    const fetchMock = mockFetch(new Response(null, { status: 204 }));
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    await expect(gateway.version()).resolves.toBeNull();
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      headers: { "content-type": "application/json" },
    });
  });

  it("encodes bank and memory ids for retain, recall, and invalidation", async () => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
      new Response(JSON.stringify({ results: [] }), { status: 200 }),
      new Response(JSON.stringify({ success: true }), { status: 200 }),
    );
    const gateway = new FetchHindsightGateway("https://hindsight.test");
    const retainBody = { items: [{ content: "hello" }] };
    const recallBody = { query: "hello" };

    await gateway.retain("ops/team", retainBody);
    await gateway.recall("ops/team", recallBody);
    await gateway.invalidateMemory("ops/team", "memory/id", "manual reject");

    expect(fetchMock.mock.calls[0]).toEqual([
      "https://hindsight.test/v1/default/banks/ops%2Fteam/memories",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(retainBody),
        signal: expect.any(AbortSignal),
      },
    ]);
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      "https://hindsight.test/v1/default/banks/ops%2Fteam/memories/recall",
    );
    expect(fetchMock.mock.calls[2]).toEqual([
      "https://hindsight.test/v1/default/banks/ops%2Fteam/memories/memory%2Fid",
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          state: "invalidated",
          reason: "manual reject",
        }),
        signal: expect.any(AbortSignal),
      },
    ]);
  });

  it("throws an actionable error for failed upstream requests", async () => {
    mockFetch(new Response('{"error":"down"}', { status: 503 }));
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    await expect(gateway.health()).rejects.toThrow(
      'Hindsight GET /health failed: HTTP 503 {"error":"down"}',
    );
  });

  it("rejects with a typed timeout error when the upstream hangs", async () => {
    const fetchMock = vi.fn((...args: unknown[]) => {
      const init = args[1] as { signal: AbortSignal };
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason));
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const gateway = new FetchHindsightGateway(
      "https://hindsight.test",
      undefined,
      10,
    );

    const failure = await gateway.health().catch((error: unknown) => error);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure).toMatchObject({
      kind: "timeout",
      status: 504,
      code: "hindsight_timeout",
    });
    expect((failure as Error).message).toContain("timed out after 10ms");
  });

  it("rejects with a typed invalid-response error for non-JSON upstream bodies", async () => {
    mockFetch(new Response("<html>proxy error</html>", { status: 200 }));
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = await gateway.health().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure).toMatchObject({
      kind: "invalid-response",
      status: 502,
      code: "hindsight_invalid_response",
      upstreamStatus: 200,
    });
  });

  it("truncates unbounded upstream error bodies", async () => {
    mockFetch(new Response("x".repeat(4096), { status: 500 }));
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = (await gateway
      .health()
      .catch((error: unknown) => error)) as HindsightGatewayError;
    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure.kind).toBe("http");
    expect(failure.upstreamStatus).toBe(500);
    expect(failure.message).toContain(`${"x".repeat(512)}...(truncated)`);
    expect(failure.message.length).toBeLessThan(600);
  });

  it("rejects with a typed network error when the connection fails", async () => {
    const fetchMock = vi.fn(async () => {
      throw new TypeError("fetch failed");
    });
    vi.stubGlobal("fetch", fetchMock);
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = await gateway.health().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure).toMatchObject({
      kind: "network",
      status: 502,
      code: "hindsight_unavailable",
    });
  });

  it("rejects non-positive timeouts", () => {
    expect(
      () => new FetchHindsightGateway("https://hindsight.test", "k", 0),
    ).toThrow("Hindsight timeout must be a positive integer");
  });
});

describe("FakeHindsightGateway", () => {
  it("records calls and returns deterministic responses", async () => {
    const gateway = new FakeHindsightGateway();
    const retainBody = { items: [{ content: "hello" }] };
    const recallBody = { query: "hello" };

    await expect(gateway.health()).resolves.toEqual({ status: "healthy" });
    await expect(gateway.version()).resolves.toMatchObject({
      api_version: "0.8.3",
    });
    await expect(gateway.retain("ops", retainBody)).resolves.toEqual({
      ok: true,
    });
    await expect(gateway.recall("ops", recallBody)).resolves.toMatchObject({
      results: [{ id: "ops-result", text: "memory from ops" }],
    });
    await gateway.invalidateMemory("ops", "memory-1", "rejected");
    expect(gateway.retained).toEqual([{ bankId: "ops", body: retainBody }]);
    expect(gateway.recalled).toEqual([{ bankId: "ops", body: recallBody }]);
    expect(gateway.invalidated).toEqual([
      { bankId: "ops", memoryId: "memory-1", reason: "rejected" },
    ]);
  });
});
