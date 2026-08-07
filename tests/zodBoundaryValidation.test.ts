import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  HindsightGatewayError,
  parseRecallResponse,
} from "../src/hindsightClient.js";
import {
  parseApproveBody,
  parseCleanupBody,
} from "../src/quarantine/adminRequestValidation.js";
import { DEFAULT_REGISTRY, validateRegistry } from "../src/registry.js";
import { createMemoryRouterServer } from "../src/server.js";
import type { WriterRegistry } from "../src/types.js";
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

describe("registry Zod boundary", () => {
  it.each([
    [
      {
        writers: {},
        defaults: {
          unknown_writer_action: "allow",
          suspicious_content_action: "review_queue",
        },
      },
      "registry.defaults.unknown_writer_action must be review_queue",
    ],
    [
      {
        writers: {},
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "allow",
        },
      },
      "registry.defaults.suspicious_content_action must be review_queue",
    ],
    [
      {
        writers: {
          ops: {
            role: "ops",
            source: "test",
            write_bank: "ops",
            read_banks: [1],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      },
      "writer ops has invalid read_bank",
    ],
  ])("preserves registry rejection contracts", (value, message) => {
    expect(() => validateRegistry(value as unknown as WriterRegistry)).toThrow(
      message,
    );
  });

  it("does not coerce writer policy values", () => {
    const value = structuredClone(DEFAULT_REGISTRY) as unknown as {
      writers: Record<string, Record<string, unknown>>;
    };
    value.writers.ops!.write_bank = 1;

    expect(() => validateRegistry(value as unknown as WriterRegistry)).toThrow(
      "writer ops missing write_bank",
    );
  });
});

describe("Hindsight recall Zod boundary", () => {
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
  ])("returns the typed invalid-response contract %#", (value) => {
    const error = (() => {
      try {
        parseRecallResponse(value);
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

describe("admin HTTP Zod boundary", () => {
  it("preserves valid admin bodies and expected_count semantics", () => {
    expect(
      parseApproveBody({ decrypted: null, extension: { future: true } }),
    ).toEqual({ decrypted: null, extension: { future: true } });
    expect(
      parseCleanupBody({
        scope: "all",
        reasons: ["unknown_writer"],
        older_than: "2026-01-01T00:00:00Z",
        dry_run: false,
        expected_count: "not-coerced",
        extension: { future: true },
      }),
    ).toEqual({
      scope: "all",
      reasons: ["unknown_writer"],
      older_than: "2026-01-01T00:00:00Z",
      dry_run: false,
      expected_count: "not-coerced",
      extension: { future: true },
    });
  });

  it.each([
    [null, "cleanup body must be an object"],
    [{ scope: "other" }, "scope must be pending or all"],
    [{ reasons: ["other"] }, "reasons must contain valid review reasons"],
    [{ older_than: 1 }, "older_than must be a string"],
    [{ dry_run: "false" }, "dry_run must be a boolean"],
  ])("rejects malformed cleanup body %#", (value, message) => {
    expect(() => parseCleanupBody(value)).toThrow(message);
  });

  it("rejects malformed approve bodies", () => {
    expect(() => parseApproveBody(null)).toThrow(
      "approve body must be an object",
    );
    expect(() => parseApproveBody([])).toThrow(
      "approve body must be an object",
    );
  });

  it("returns 400 invalid_request for malformed admin HTTP bodies", async () => {
    const quarantine = memoryQuarantine();
    const server = createMemoryRouterServer({
      registry: DEFAULT_REGISTRY,
      adminToken: "admin-token",
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
      authorization: "Bearer admin-token",
      "content-type": "application/json",
    };

    const cleanup = await fetch(`${baseUrl}/admin/quarantine/cleanup`, {
      method: "POST",
      headers,
      body: "null",
    });
    expect(cleanup.status).toBe(400);
    await expect(cleanup.json()).resolves.toEqual({
      error: "invalid_request",
      message: "cleanup body must be an object",
    });

    const approve = await fetch(
      `${baseUrl}/admin/quarantine/items/q_test_0123456789abcdef/approve`,
      { method: "POST", headers, body: "null" },
    );
    expect(approve.status).toBe(400);
    await expect(approve.json()).resolves.toEqual({
      error: "invalid_request",
      message: "approve body must be an object",
    });
  });
});
