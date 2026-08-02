import { createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import type { QuarantineKind, ReviewReason } from "../types.js";
import {
  createEncryptedQuarantineEnvelope,
  decodePrivateKey,
  decryptQuarantineEnvelope,
} from "./envelopeCrypto.js";
import type { NewQuarantineItem, QuarantineRepository } from "./repository.js";
import { createQuarantineRepository } from "./repositoryFactory.js";

interface LegacyReviewRecord {
  timestamp: string;
  writer_id?: string;
  source?: string;
  reason: ReviewReason;
  quarantine_id?: string;
  decision: "pending" | "rejected" | "postponed" | "promoted";
  postpone_count?: number;
  decided_at?: string;
}

export interface LegacyMigrationOptions {
  queuePath: string;
  objectDirectory: string;
  databaseUrl: string;
  privateKey: string;
}

export interface LegacyMigrationSummary {
  imported: number;
  skipped_existing: number;
  skipped_finalized: number;
  skipped_without_payload: number;
}

export async function migrateLegacyQuarantine(
  options: LegacyMigrationOptions,
): Promise<LegacyMigrationSummary> {
  const repository = await createQuarantineRepository(options.databaseUrl);
  try {
    return await importLegacyQuarantine(repository, options);
  } finally {
    await repository.close();
  }
}

export async function importLegacyQuarantine(
  repository: QuarantineRepository,
  options: Omit<LegacyMigrationOptions, "databaseUrl">,
): Promise<LegacyMigrationSummary> {
  const privateKey = decodePrivateKey(options.privateKey);
  const publicKey = createPublicKey(privateKey)
    .export({ type: "spki", format: "pem" })
    .toString();
  const records = parseLegacyQueue(await readFile(options.queuePath, "utf8"));
  const summary: LegacyMigrationSummary = {
    imported: 0,
    skipped_existing: 0,
    skipped_finalized: 0,
    skipped_without_payload: 0,
  };

  for (const record of records) {
    if (record.decision !== "pending" && record.decision !== "postponed") {
      summary.skipped_finalized += 1;
      continue;
    }
    if (!record.quarantine_id) {
      summary.skipped_without_payload += 1;
      continue;
    }
    if (await repository.get(record.quarantine_id)) {
      summary.skipped_existing += 1;
      continue;
    }

    const envelope = JSON.parse(
      await readFile(
        legacyObjectPath(options.objectDirectory, record.quarantine_id),
        "utf8",
      ),
    ) as unknown;
    const decrypted = decryptQuarantineEnvelope(envelope, privateKey);
    if (decrypted.quarantine_id !== record.quarantine_id) {
      throw new Error(
        `legacy queue/envelope mismatch for ${record.quarantine_id}`,
      );
    }
    const encrypted = createEncryptedQuarantineEnvelope(decrypted, publicKey);
    const item: NewQuarantineItem = {
      quarantine_id: decrypted.quarantine_id,
      created_at: decrypted.created_at,
      updated_at: decrypted.created_at,
      kind: legacyKind(decrypted.payload),
      reason: decrypted.reason,
      ...(decrypted.writer_id === undefined
        ? {}
        : { writer_id: decrypted.writer_id }),
      ...(decrypted.source === undefined ? {} : { source: decrypted.source }),
      sha256: encrypted.sha256,
      encrypted,
      status: "pending",
      postpone_count: 0,
    };
    await repository.insert(item);

    const postponeCount =
      record.decision === "postponed"
        ? Math.max(1, record.postpone_count ?? 1)
        : Math.max(0, record.postpone_count ?? 0);
    const postponedAt = record.decided_at ?? record.timestamp;
    for (let index = 0; index < postponeCount; index += 1) {
      await repository.postpone(record.quarantine_id, postponedAt);
    }
    summary.imported += 1;
  }

  return summary;
}

function parseLegacyQueue(raw: string): LegacyReviewRecord[] {
  return raw
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line, index) => parseLegacyRecord(JSON.parse(line), index + 1));
}

function parseLegacyRecord(value: unknown, line: number): LegacyReviewRecord {
  const record = requireObject(value, `legacy queue line ${line}`);
  if (
    record.decision !== "pending" &&
    record.decision !== "postponed" &&
    record.decision !== "rejected" &&
    record.decision !== "promoted"
  ) {
    throw new Error(`legacy queue line ${line} has an invalid decision`);
  }
  if (typeof record.timestamp !== "string" || !record.timestamp) {
    throw new Error(`legacy queue line ${line} has no timestamp`);
  }
  if (typeof record.reason !== "string" || !record.reason) {
    throw new Error(`legacy queue line ${line} has no reason`);
  }
  return {
    timestamp: record.timestamp,
    reason: record.reason as ReviewReason,
    decision: record.decision,
    ...(typeof record.writer_id === "string"
      ? { writer_id: record.writer_id }
      : {}),
    ...(typeof record.source === "string" ? { source: record.source } : {}),
    ...(typeof record.quarantine_id === "string"
      ? { quarantine_id: record.quarantine_id }
      : {}),
    ...(typeof record.postpone_count === "number"
      ? { postpone_count: record.postpone_count }
      : {}),
    ...(typeof record.decided_at === "string"
      ? { decided_at: record.decided_at }
      : {}),
  };
}

function legacyKind(payload: unknown): QuarantineKind {
  const object = requireObject(payload, "legacy quarantine payload");
  if (object.action === "retain") return "retain_request";
  if (object.action === "recall") return "recall_request";
  throw new Error("legacy quarantine payload action is unsupported");
}

function legacyObjectPath(directory: string, quarantineId: string): string {
  if (!/^q_[0-9A-Za-z]+_[0-9a-f]{16}$/.test(quarantineId)) {
    throw new Error("invalid legacy quarantine_id");
  }
  const base = resolve(directory);
  const path = resolve(base, `${quarantineId}.enc.json`);
  if (!path.startsWith(`${base}${sep}`)) {
    throw new Error("invalid legacy quarantine object path");
  }
  return path;
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}
