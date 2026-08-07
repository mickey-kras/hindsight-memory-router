import { once } from "node:events";
import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  FetchHindsightGateway,
  HindsightGatewayError,
  type HindsightGateway,
} from "../src/hindsightClient.js";
import { RouterPolicy } from "../src/policy.js";
import { createMemoryRouterServer } from "../src/server.js";
import type { RecallBody, RecallResponse, RetainBody, WriterRegistry } from "../src/types.js";
import { memoryQuarantine } from "./quarantineTestUtils.js";

const registry: WriterRegistry = {
  writers: {
    ops: {
      role: "ops",
      source: "test",
      write_bank: "ops",
      read_banks: ["ops"],
    },
  },
  defaults: {
    unknown_writer_action: "review_queue",
    suspicious_content_action: "review_queue",
  },
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Hindsight diagnostics", () => {
  it("logs one-line bounded metadata without upstream error text", async () => {
    const upstreamBody =
      "first line\r\nsecond line\u0000 Bearer secret https://user:pass@example.test/private";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(upstreamBody, { status: 503 })),
    );
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const quarantine = memoryQuarantine();
    const policy = new RouterPolicy({
      registry,
      hindsight: new FetchHindsightGateway("https://hindsight.test"),
      quarantineStore: quarantine.store,
      quarantineRepository: quarantine.repository,
    });

    await expect(policy.recall("ops", { query: "normal" })).resolves.toEqual({
      results: [],
    });

    expect(stderr).toHaveBeenCalledOnce();
    const log = String(stderr.mock.calls[0]?.[0]);
    expect(log).toContain('"event":"bank_unavailable"');
    expect(log).toContain('"error_kind":"http"');
    expect(log).toContain('"upstream_status":503');
    expect(log).toContain('"error_body_truncated":false');
    expect(log).not.toContain("first line");
    expect(log).not.toContain("Bearer secret");
    expect(log).not.toContain("user:pass");
    expect(log).not.toContain("\r");
    expect(log.match(/\n/g)).toHaveLength(1);
  });

  it("returns a stable public error and logs only metadata for propagated failures", async () => {
    const maliciousUpstreamText =
      "first line\r\nsecond line\u0000 Bearer secret https://user:pass@example.test/private";
    const hindsight: HindsightGateway = {
      async health() {
        return { status: "healthy" };
      },
      async version() {
        return { api_version: "test" };
      },
      async retain(_bankId: string, _body: RetainBody) {
        throw new HindsightGatewayError("http", maliciousUpstreamText, 503);
      },
      async recall(
        _bankId: string,
        _body: RecallBody,
      ): Promise<RecallResponse> {
        return { results: [] };
      },
      async invalidateMemory() {},
    };
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const quarantine = memoryQuarantine();
    const server = createMemoryRouterServer({
      allowAnonymous: true,
      registry,
      hindsight,
      quarantineStore: quarantine.store,
      quarantineRepository: quarantine.repository,
      sweepIntervalSeconds: 0,
    });

    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const address = server.address() as AddressInfo;
      const response = await postJson(
        address.port,
        "/v1/default/banks/ops/memories",
        { items: [{ content: "hello" }] },
      );

      expect(response.status).toBe(502);
      expect(JSON.parse(response.body)).toEqual({
        error: "hindsight_http_error",
        message: "Upstream memory service request failed",
      });
      expect(response.body).not.toContain("first line");
      expect(response.body).not.toContain("Bearer secret");
      expect(response.body).not.toContain("user:pass");

      expect(stderr).toHaveBeenCalledOnce();
      const log = String(stderr.mock.calls[0]?.[0]);
      expect(log).toContain("memory-router upstream request failed");
      expect(log).toContain('"error_kind":"http"');
      expect(log).toContain('"upstream_status":503');
      expect(log).not.toContain("first line");
      expect(log).not.toContain("Bearer secret");
      expect(log).not.toContain("user:pass");
      expect(log).not.toContain("\r");
      expect(log.match(/\n/g)).toHaveLength(1);
    } finally {
      await closeServer(server);
    }
  });
});

function postJson(
  port: number,
  path: string,
  body: unknown,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: { "content-type": "application/json" },
      },
      (res) => {
        let responseBody = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          responseBody += chunk;
        });
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, body: responseBody });
        });
      },
    );
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

function closeServer(server: ReturnType<typeof createMemoryRouterServer>): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
