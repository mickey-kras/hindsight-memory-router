import { readFileSync } from "node:fs";
import type { WriterRegistry, WriterRule } from "./types.js";

export const DEFAULT_REGISTRY: WriterRegistry = {
  writers: {
    main: {
      role: "orchestrator",
      source: "openclaw",
      write_bank: "main",
      read_banks: ["main", "core", "ops", "dev", "creative", "personal"],
    },
    ops: {
      role: "ops",
      source: "openclaw",
      write_bank: "ops",
      read_banks: ["ops", "core"],
    },
    dev: {
      role: "dev",
      source: "openclaw",
      write_bank: "dev",
      read_banks: ["dev", "core"],
    },
    creative: {
      role: "creative",
      source: "openclaw",
      write_bank: "creative",
      read_banks: ["creative", "core"],
    },
    personal: {
      role: "personal",
      source: "openclaw",
      write_bank: "personal",
      read_banks: ["personal", "core"],
    },
    research: {
      role: "research",
      source: "openclaw",
      write_bank: "research",
      read_banks: ["research", "core"],
    },
  },
  defaults: {
    unknown_writer_action: "review_queue",
    suspicious_content_action: "review_queue",
    review_queue_path: "/volume1/reports/hindsight-review/review.jsonl",
  },
};

export function loadRegistry(path?: string): WriterRegistry {
  if (!path) return DEFAULT_REGISTRY;
  const parsed = JSON.parse(readFileSync(path, "utf8")) as WriterRegistry;
  validateRegistry(parsed);
  return parsed;
}

export function getWriter(
  registry: WriterRegistry,
  writerId: string,
): WriterRule | undefined {
  return registry.writers[writerId];
}

export function validateRegistry(registry: WriterRegistry): void {
  if (!registry || typeof registry !== "object")
    throw new Error("registry must be an object");
  if (!registry.writers || typeof registry.writers !== "object") {
    throw new Error("registry.writers must be an object");
  }
  for (const [writerId, rule] of Object.entries(registry.writers)) {
    if (!writerId.trim()) throw new Error("writer id cannot be empty");
    if (!rule.write_bank)
      throw new Error(`writer ${writerId} missing write_bank`);
    if (!Array.isArray(rule.read_banks))
      throw new Error(`writer ${writerId} missing read_banks`);
    if (rule.read_banks.includes("quarantine")) {
      throw new Error(`writer ${writerId} cannot read quarantine`);
    }
    if (writerId === "main" && rule.read_banks.includes("research")) {
      throw new Error("main writer cannot read research");
    }
  }
}
