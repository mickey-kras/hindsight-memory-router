import { readFileSync } from "node:fs";
import { BANK_IDS, type WriterRegistry, type WriterRule } from "./types.js";

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
  },
};

const BANK_ID_SET = new Set<string>(BANK_IDS);

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
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    throw new Error("registry must be an object");
  }
  if (
    !registry.writers ||
    typeof registry.writers !== "object" ||
    Array.isArray(registry.writers)
  ) {
    throw new Error("registry.writers must be an object");
  }
  if (
    !registry.defaults ||
    typeof registry.defaults !== "object" ||
    Array.isArray(registry.defaults)
  ) {
    throw new Error("registry.defaults must be an object");
  }
  if (registry.defaults.unknown_writer_action !== "review_queue") {
    throw new Error("registry.defaults.unknown_writer_action must be review_queue");
  }
  if (registry.defaults.suspicious_content_action !== "review_queue") {
    throw new Error(
      "registry.defaults.suspicious_content_action must be review_queue",
    );
  }

  for (const [writerId, value] of Object.entries(registry.writers)) {
    if (!writerId.trim()) throw new Error("writer id cannot be empty");
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`writer ${writerId} must be an object`);
    }
    const rule = value as WriterRule;
    if (typeof rule.role !== "string" || !rule.role.trim()) {
      throw new Error(`writer ${writerId} missing role`);
    }
    if (typeof rule.source !== "string" || !rule.source.trim()) {
      throw new Error(`writer ${writerId} missing source`);
    }
    if (typeof rule.write_bank !== "string" || !rule.write_bank) {
      throw new Error(`writer ${writerId} missing write_bank`);
    }
    if (!BANK_ID_SET.has(rule.write_bank)) {
      throw new Error(`writer ${writerId} has invalid write_bank`);
    }
    if (!Array.isArray(rule.read_banks)) {
      throw new Error(`writer ${writerId} missing read_banks`);
    }
    for (const bank of rule.read_banks as unknown[]) {
      if (typeof bank !== "string" || !BANK_ID_SET.has(bank)) {
        throw new Error(`writer ${writerId} has invalid read_bank`);
      }
    }
    if (writerId === "main" && rule.read_banks.includes("research")) {
      throw new Error("main writer cannot read research");
    }
  }
}
