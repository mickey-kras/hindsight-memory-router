import { readFileSync } from "node:fs";
import { z } from "zod";
import { BANK_IDS, type WriterRegistry, type WriterRule } from "./types.js";

export const DEFAULT_REGISTRY: WriterRegistry = {
  writers: {
    main: {
      role: "orchestrator",
      source: "application",
      write_bank: "main",
      read_banks: ["main", "core", "ops", "dev", "creative", "personal"],
    },
    ops: {
      role: "ops",
      source: "application",
      write_bank: "ops",
      read_banks: ["ops", "core"],
    },
    dev: {
      role: "dev",
      source: "application",
      write_bank: "dev",
      read_banks: ["dev", "core"],
    },
    creative: {
      role: "creative",
      source: "application",
      write_bank: "creative",
      read_banks: ["creative", "core"],
    },
    personal: {
      role: "personal",
      source: "application",
      write_bank: "personal",
      read_banks: ["personal", "core"],
    },
    research: {
      role: "research",
      source: "application",
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

const registrySchema = z
  .object({
    writers: z.record(z.string(), z.unknown()),
    defaults: z
      .object({
        unknown_writer_action: z.literal("review_queue"),
        suspicious_content_action: z.literal("review_queue"),
      })
      .passthrough(),
  })
  .passthrough();

const writerRuleSchema = z
  .object({
    role: z.string().refine((value) => value.trim().length > 0),
    source: z.string().refine((value) => value.trim().length > 0),
    write_bank: z.string().min(1),
    read_banks: z.array(z.string()),
  })
  .passthrough();

export function loadRegistry(path?: string): WriterRegistry {
  if (!path) return DEFAULT_REGISTRY;
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  validateRegistry(parsed as WriterRegistry);
  return parsed as WriterRegistry;
}

export function getWriter(
  registry: WriterRegistry,
  writerId: string,
): WriterRule | undefined {
  return registry.writers[writerId];
}

export function validateRegistry(registry: WriterRegistry): void {
  const parsed = registrySchema.safeParse(registry);
  if (!parsed.success) {
    throw new Error(
      registryValidationMessage(registry, parsed.error.issues[0]),
    );
  }

  for (const [writerId, value] of Object.entries(parsed.data.writers)) {
    if (!writerId.trim()) throw new Error("writer id cannot be empty");

    const writer = writerRuleSchema.safeParse(value);
    if (!writer.success) {
      throw new Error(
        writerValidationMessage(writerId, value, writer.error.issues[0]),
      );
    }

    const rule = writer.data;
    if (rule.write_bank === "quarantine") {
      throw new Error(`writer ${writerId} cannot write quarantine`);
    }
    if (!BANK_ID_SET.has(rule.write_bank)) {
      throw new Error(`writer ${writerId} has invalid write_bank`);
    }
    if (rule.read_banks.includes("quarantine")) {
      throw new Error(`writer ${writerId} cannot read quarantine`);
    }
    for (const bank of rule.read_banks) {
      if (!BANK_ID_SET.has(bank)) {
        throw new Error(`writer ${writerId} has invalid read_bank`);
      }
    }
    if (writerId === "main" && rule.read_banks.includes("research")) {
      throw new Error("main writer cannot read research");
    }
  }
}

function registryValidationMessage(
  value: unknown,
  issue: z.core.$ZodIssue | undefined,
): string {
  if (!isObject(value)) return "registry must be an object";
  if (issue?.path[0] === "writers") return "registry.writers must be an object";
  if (issue?.path[0] === "defaults") {
    if (issue.path[1] === "unknown_writer_action") {
      return "registry.defaults.unknown_writer_action must be review_queue";
    }
    if (issue.path[1] === "suspicious_content_action") {
      return "registry.defaults.suspicious_content_action must be review_queue";
    }
    return "registry.defaults must be an object";
  }
  return "registry must be an object";
}

function writerValidationMessage(
  writerId: string,
  value: unknown,
  issue: z.core.$ZodIssue | undefined,
): string {
  if (!isObject(value)) return `writer ${writerId} must be an object`;
  switch (issue?.path[0]) {
    case "role":
      return `writer ${writerId} missing role`;
    case "source":
      return `writer ${writerId} missing source`;
    case "write_bank":
      return `writer ${writerId} missing write_bank`;
    case "read_banks":
      return issue.path.length > 1
        ? `writer ${writerId} has invalid read_bank`
        : `writer ${writerId} missing read_banks`;
    default:
      return `writer ${writerId} must be an object`;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
