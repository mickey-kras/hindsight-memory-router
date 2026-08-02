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

describe("registry", () => {
  it("uses the default registry and resolves known writers", () => {
    expect(loadRegistry()).toBe(DEFAULT_REGISTRY);
    expect(getWriter(DEFAULT_REGISTRY, "ops")?.write_bank).toBe("ops");
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
});
