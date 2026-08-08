import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_REGISTRY,
  getWriter,
  loadRegistry,
  validateRegistry,
} from "../src/registry.js";
import type { WriterRegistry } from "../src/types.js";

function registryWith(writers: WriterRegistry["writers"]): WriterRegistry {
  return {
    writers,
    defaults: {
      unknown_writer_action: "review_queue",
      suspicious_content_action: "review_queue",
    },
  };
}

function registry(value: unknown): WriterRegistry {
  return value as WriterRegistry;
}

describe("registry", () => {
  it("uses the minimal default registry and resolves known writers", () => {
    expect(loadRegistry()).toBe(DEFAULT_REGISTRY);
    expect(getWriter(DEFAULT_REGISTRY, "main")).toEqual({
      role: "default",
      source: "application",
      write_bank: "main",
      read_banks: ["main"],
    });
    expect(getWriter(DEFAULT_REGISTRY, "ops")).toBeUndefined();
    expect(getWriter(DEFAULT_REGISTRY, "missing")).toBeUndefined();
  });

  it("loads and validates a registry file", () => {
    const directory = mkdtempSync(join(tmpdir(), "registry-test-"));
    const path = join(directory, "registry.json");
    const registry = registryWith({
      ops: {
        role: "ops",
        source: "test",
        write_bank: "ops",
        read_banks: ["ops", "core"],
      },
    });
    try {
      writeFileSync(path, JSON.stringify(registry));
      expect(loadRegistry(path)).toEqual(registry);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([
    [null, "registry must be an object"],
    [{}, "registry.writers must be an object"],
    [
      registryWith({
        "": { role: "x", source: "x", write_bank: "ops", read_banks: [] },
      }),
      "writer id cannot be empty",
    ],
    [
      registryWith({
        ops: {
          role: "x",
          source: "x",
          write_bank: "" as "ops",
          read_banks: [],
        },
      }),
      "writer ops missing write_bank",
    ],
    [
      registryWith({
        ops: {
          role: "x",
          source: "x",
          write_bank: "quarantine" as "ops",
          read_banks: [],
        },
      }),
      "writer ops cannot write quarantine",
    ],
    [
      registryWith({
        ops: {
          role: "x",
          source: "x",
          write_bank: "ops",
          read_banks: null as unknown as [],
        },
      }),
      "writer ops missing read_banks",
    ],
    [
      registryWith({
        ops: {
          role: "x",
          source: "x",
          write_bank: "ops",
          read_banks: ["quarantine" as "ops"],
        },
      }),
      "writer ops cannot read quarantine",
    ],
    [
      registryWith({
        main: {
          role: "x",
          source: "x",
          write_bank: "main",
          read_banks: ["research"],
        },
      }),
      "main writer cannot read research",
    ],
    [
      registry({
        writers: { ops: null },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops must be an object",
    ],
    [
      registry({
        writers: {
          ops: {
            role: "",
            source: "test",
            write_bank: "ops",
            read_banks: ["ops"],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops missing role",
    ],
    [
      registry({
        writers: {
          ops: {
            role: "ops",
            source: "",
            write_bank: "ops",
            read_banks: ["ops"],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops missing source",
    ],
    [
      registry({
        writers: {
          ops: {
            role: "ops",
            source: "test",
            write_bank: "bogus",
            read_banks: ["ops"],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops has invalid write_bank",
    ],
    [
      registry({
        writers: {
          ops: {
            role: "ops",
            source: "test",
            write_bank: "ops",
            read_banks: ["bogus"],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops has invalid read_bank",
    ],
    [
      registry({ writers: {}, defaults: null }),
      "registry.defaults must be an object",
    ],
  ])("rejects invalid registry input", (value, message) => {
    expect(() => validateRegistry(value as WriterRegistry)).toThrow(message);
  });

  it("accepts valid writer policies", () => {
    expect(() =>
      validateRegistry(
        registryWith({
          main: {
            role: "main",
            source: "test",
            write_bank: "main",
            read_banks: ["main", "core"],
          },
        }),
      ),
    ).not.toThrow();
  });

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
    value.writers.main!.write_bank = 1;

    expect(() => validateRegistry(value as unknown as WriterRegistry)).toThrow(
      "writer main missing write_bank",
    );
  });
});
