import { afterEach, describe, expect, it, vi } from "vitest";
import {
  FakeHindsightGateway,
  FetchHindsightGateway,
  hindsightGatewayErrorDetails,
  HindsightGatewayError,
  parseRecallResponse,
} from "../src/hindsightClient.js";
import { safeErrorBody } from "../src/httpError.js";

function mockFetch(...responses: Response[]) {
  const fetchMock = vi.fn();
  for (const response of responses) {
    fetchMock.mockResolvedValueOnce(response);
  }
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function responseWithBodyFailure(error: Error): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"partial":'));
      controller.error(error);
    },
  });
  return new Response(stream, { status: 200 });
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

  it("hides upstream HTTP error bodies from public errors", async () => {
    const upstreamBody = '{"error":"internal secret detail"}';
    mockFetch(new Response(upstreamBody, { status: 503 }));
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = (await gateway
      .health()
      .catch((error: unknown) => error)) as HindsightGatewayError;

    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure).toMatchObject({
      kind: "http",
      status: 502,
      code: "hindsight_http_error",
      message: "Upstream memory service request failed",
      upstreamStatus: 503,
    });
    expect(JSON.stringify(safeErrorBody(failure))).not.toContain(upstreamBody);
    expect(hindsightGatewayErrorDetails(failure)).toEqual({
      error_kind: "http",
      status: 502,
      upstream_status: 503,
      operation: "health",
      method: "GET",
    });
  });

  it("does not retain malicious upstream error text in diagnostics", async () => {
    const upstreamBody =
      "first line\r\nsecond line\u0000 Authorization: Bearer secret https://user:pass@example.test/path";
    mockFetch(new Response(upstreamBody, { status: 500 }));
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = (await gateway
      .health()
      .catch((error: unknown) => error)) as HindsightGatewayError;
    const publicError = JSON.stringify(safeErrorBody(failure));
    const diagnostics = JSON.stringify(hindsightGatewayErrorDetails(failure));

    expect(publicError).not.toContain("first line");
    expect(publicError).not.toContain("Bearer secret");
    expect(publicError).not.toContain("user:pass");
    expect(diagnostics).not.toContain("first line");
    expect(diagnostics).not.toContain("Bearer secret");
    expect(diagnostics).not.toContain("user:pass");
    expect(diagnostics).not.toContain("\u0000");
    expect(diagnostics).not.toContain("\r");
    expect(diagnostics).not.toContain("\n");
  });

  it("does not consume excessively large upstream error bodies", async () => {
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({ cancel });
    mockFetch(
      new Response(stream, {
        status: 500,
        headers: { "content-length": String(Number.MAX_SAFE_INTEGER) },
      }),
    );
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = (await gateway
      .health()
      .catch((error: unknown) => error)) as HindsightGatewayError;

    expect(cancel).toHaveBeenCalledOnce();
    expect(hindsightGatewayErrorDetails(failure)).toEqual({
      error_kind: "http",
      status: 502,
      upstream_status: 500,
      operation: "health",
      method: "GET",
    });
  });

  it("maps a successful response body stream failure to hindsight_unavailable", async () => {
    mockFetch(
      responseWithBodyFailure(
        new TypeError(
          "terminated https://user:pass@example.test/private\nstack detail",
        ),
      ),
    );
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = await gateway.health().catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure).toMatchObject({
      kind: "network",
      status: 502,
      code: "hindsight_unavailable",
      message: "Upstream memory service is unavailable",
    });
    expect(
      hindsightGatewayErrorDetails(failure as HindsightGatewayError),
    ).toEqual({
      error_kind: "network",
      status: 502,
      operation: "health",
      method: "GET",
    });
    expect(JSON.stringify(safeErrorBody(failure))).not.toContain("user:pass");
  });

  it("maps a successful response body timeout to hindsight_timeout", async () => {
    mockFetch(
      responseWithBodyFailure(
        new DOMException("body timed out", "TimeoutError"),
      ),
    );
    const gateway = new FetchHindsightGateway(
      "https://hindsight.test",
      undefined,
      10,
    );

    const failure = await gateway.health().catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure).toMatchObject({
      kind: "timeout",
      status: 504,
      code: "hindsight_timeout",
      message: "Upstream memory service timed out",
    });
    expect(safeErrorBody(failure)).toEqual({
      status: 504,
      body: {
        error: "hindsight_timeout",
        message: "Upstream memory service timed out",
      },
    });
    expect(
      hindsightGatewayErrorDetails(failure as HindsightGatewayError),
    ).toEqual({
      error_kind: "timeout",
      status: 504,
      operation: "health",
      method: "GET",
      timeout_ms: 10,
    });
  });

  it("rejects with a stable typed timeout error when the upstream hangs", async () => {
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
      message: "Upstream memory service timed out",
    });
    expect(
      hindsightGatewayErrorDetails(failure as HindsightGatewayError),
    ).toMatchObject({
      error_kind: "timeout",
      status: 504,
      operation: "health",
      method: "GET",
      timeout_ms: 10,
    });
  });

  it("rejects with a stable typed invalid-response error for non-JSON upstream bodies", async () => {
    mockFetch(new Response("<html>proxy error</html>", { status: 200 }));
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = await gateway.health().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure).toMatchObject({
      kind: "invalid-response",
      status: 502,
      code: "hindsight_invalid_response",
      message: "Upstream memory service returned an invalid response",
      upstreamStatus: 200,
    });
  });

  it("rejects with a stable typed network error when the connection fails", async () => {
    const fetchMock = vi.fn(async () => {
      throw new TypeError(
        "fetch failed https://user:pass@example.test/private\nstack detail",
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    const failure = await gateway.health().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(HindsightGatewayError);
    expect(failure).toMatchObject({
      kind: "network",
      status: 502,
      code: "hindsight_unavailable",
      message: "Upstream memory service is unavailable",
    });
    expect(
      JSON.stringify(
        hindsightGatewayErrorDetails(failure as HindsightGatewayError),
      ),
    ).not.toContain("user:pass");
  });

  it("rejects non-positive timeouts", () => {
    expect(
      () => new FetchHindsightGateway("https://hindsight.test", "k", 0),
    ).toThrow("Hindsight timeout must be a positive integer");
  });
});

describe("parseRecallResponse", () => {
  it("accepts valid recall responses", () => {
    expect(
      parseRecallResponse({ results: [{ id: "m1", text: "memory" }] }),
    ).toEqual({
      results: [{ id: "m1", text: "memory" }],
    });
  });

  it("preserves valid extension fields", () => {
    const response = {
      results: [
        {
          id: "m1",
          text: "memory",
          extension: { nested: [1, { enabled: true }] },
        },
      ],
      trace: { nested: { value: 1 } },
      extension: { future: true },
    };

    expect(parseRecallResponse(response)).toEqual(response);
  });

  it.each([
    [null],
    [[]],
    [{}],
    [{ results: "invalid" }],
    [{ results: [null] }],
    [{ results: [{ id: 1, text: "memory" }] }],
    [{ results: [{ id: "m1", text: 1 }] }],
    [{ results: [{ id: "m1", text: "memory" }], chunks: [] }],
    [{ results: [{ id: "m1", text: "memory" }], entities: "bad" }],
    [{ results: [{ id: "m1", text: "memory" }], source_facts: [] }],
    [{ results: [{ id: "m1", text: "memory" }], trace: [] }],
  ])("rejects malformed recall responses %#", (response) => {
    const error = (() => {
      try {
        parseRecallResponse(response);
        return undefined;
      } catch (caught) {
        return caught;
      }
    })();

    expect(error).toBeInstanceOf(HindsightGatewayError);
    expect(error).toMatchObject({
      status: 502,
      code: "hindsight_invalid_response",
      message: "Upstream memory service returned an invalid response",
      kind: "invalid-response",
      context: { operation: "recall", method: "POST" },
    });
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
