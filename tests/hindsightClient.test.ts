import { afterEach, describe, expect, it, vi } from "vitest";
import {
  FakeHindsightGateway,
  FetchHindsightGateway,
} from "../src/hindsightClient.js";

function mockFetch(response: Response) {
  const fetchMock = vi.fn().mockResolvedValue(response);
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

  it("encodes bank ids and serializes retain and recall bodies", async () => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify({ results: [] }), { status: 200 }),
    );
    const gateway = new FetchHindsightGateway("https://hindsight.test");
    const retainBody = { items: [{ content: "hello" }] };
    const recallBody = { query: "hello" };

    await gateway.retain("ops/team", retainBody);
    await gateway.recall("ops/team", recallBody);

    expect(fetchMock.mock.calls[0]).toEqual([
      "https://hindsight.test/v1/default/banks/ops%2Fteam/memories",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(retainBody),
      },
    ]);
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      "https://hindsight.test/v1/default/banks/ops%2Fteam/memories/recall",
    );
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({
      method: "POST",
      body: JSON.stringify(recallBody),
    });
  });

  it("throws an actionable error for failed upstream requests", async () => {
    mockFetch(new Response('{"error":"down"}', { status: 503 }));
    const gateway = new FetchHindsightGateway("https://hindsight.test");

    await expect(gateway.health()).rejects.toThrow(
      'Hindsight GET /health failed: HTTP 503 {"error":"down"}',
    );
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
    expect(gateway.retained).toEqual([{ bankId: "ops", body: retainBody }]);
    expect(gateway.recalled).toEqual([{ bankId: "ops", body: recallBody }]);
  });
});
