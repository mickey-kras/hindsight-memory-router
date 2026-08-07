import { describe, expect, it } from "vitest";
import {
  HindsightGatewayError,
  parseRecallResponse,
} from "../src/hindsightClient.js";
import { DEFAULT_REGISTRY, validateRegistry } from "../src/registry.js";
import type { WriterRegistry } from "../src/types.js";

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
