import {
  constants,
  createCipheriv,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { resolve, sep } from "node:path";
import {
  parseEncryptedQuarantineEnvelope,
  WRAPPED_KEY_FIELD,
  type EncryptedQuarantineEnvelope,
} from "./quarantine/envelopeCrypto.js";
import { sha256 } from "./safety.js";
import type { ReviewReason } from "./types.js";

const GCM_AUTH_TAG_LENGTH_BYTES = 16;

export interface QuarantineInput {
  timestamp: string;
  reason: ReviewReason;
  writerId?: string;
  source?: string;
  payload: unknown;
}

export interface QuarantineResult {
  quarantine_id: string;
  sha256: string;
}

export interface QuarantineStore {
  put(input: QuarantineInput): QuarantineResult;
}

function publicKeyPemFromEnv(value?: string): string {
  if (!value?.trim()) throw new Error("QUARANTINE_PUBLIC_KEY is required");

  const trimmed = value.trim();
  if (trimmed.includes("BEGIN PUBLIC KEY")) {
    return trimmed.replace(/\\n/g, "\n");
  }

  const decoded = Buffer.from(trimmed, "base64").toString("utf8");
  if (!decoded.includes("BEGIN PUBLIC KEY")) {
    throw new Error("QUARANTINE_PUBLIC_KEY must be PEM or base64-encoded PEM");
  }
  return decoded;
}

export function assertSafeQuarantineId(quarantineId: string): void {
  if (!/^q_[0-9A-Za-z]+_[0-9a-f]{16}$/.test(quarantineId)) {
    throw new Error("invalid quarantine_id");
  }
}

export function encryptedQuarantineObjectPath(
  objectDir: string,
  quarantineId: string,
): string {
  assertSafeQuarantineId(quarantineId);
  const baseDir = resolve(objectDir);
  const objectPath = resolve(baseDir, `${quarantineId}.enc.json`);
  if (!objectPath.startsWith(`${baseDir}${sep}`)) {
    throw new Error("invalid quarantine object path");
  }
  return objectPath;
}

export function readEncryptedQuarantineEnvelope(
  objectDir: string,
  quarantineId: string,
): EncryptedQuarantineEnvelope {
  const raw = readFileSync(
    encryptedQuarantineObjectPath(objectDir, quarantineId),
    { encoding: "utf8" },
  );
  return parseEncryptedQuarantineEnvelope(JSON.parse(raw));
}

export function deleteEncryptedQuarantineObject(
  objectDir: string,
  quarantineId: string,
): void {
  unlinkSync(encryptedQuarantineObjectPath(objectDir, quarantineId));
}

export class EncryptedFileQuarantineStore implements QuarantineStore {
  constructor(
    private readonly publicKeyEnv: string | undefined,
    private readonly objectDir: string,
  ) {}

  put(input: QuarantineInput): QuarantineResult {
    const publicKey = publicKeyPemFromEnv(this.publicKeyEnv);
    const quarantineId = `q_${input.timestamp.replace(/[^0-9A-Za-z]/g, "")}_${randomBytes(8).toString("hex")}`;
    const plaintext = JSON.stringify({
      quarantine_id: quarantineId,
      created_at: input.timestamp,
      reason: input.reason,
      writer_id: input.writerId,
      source: input.source,
      payload: input.payload,
    });
    const digest = sha256(plaintext);

    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv, {
      authTagLength: GCM_AUTH_TAG_LENGTH_BYTES,
    });
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const wrappedKey = publicEncrypt(
      {
        key: publicKey,
        oaepHash: "sha256",
        padding: constants.RSA_PKCS1_OAEP_PADDING,
      },
      key,
    );

    const envelope: EncryptedQuarantineEnvelope = {
      version: 1,
      quarantine_id: quarantineId,
      created_at: input.timestamp,
      reason: input.reason,
      writer_id: input.writerId,
      source: input.source,
      sha256: digest,
      encryption: {
        algorithm: "AES-256-GCM",
        key_wrap: "RSA-OAEP-SHA256",
        [WRAPPED_KEY_FIELD]: wrappedKey.toString("base64"),
        iv_b64: iv.toString("base64"),
        tag_b64: tag.toString("base64"),
      },
      ciphertext_b64: ciphertext.toString("base64"),
    };

    mkdirSync(this.objectDir, { recursive: true, mode: 0o700 });
    writeFileSync(
      encryptedQuarantineObjectPath(this.objectDir, quarantineId),
      JSON.stringify(envelope) + "\n",
      { encoding: "utf8", mode: 0o600 },
    );

    return { quarantine_id: quarantineId, sha256: digest };
  }
}

export class MemoryQuarantineStore implements QuarantineStore {
  readonly records: Array<QuarantineInput & QuarantineResult> = [];

  put(input: QuarantineInput): QuarantineResult {
    const quarantineId = `q_test_${this.records.length + 1}`;
    const digest = sha256(JSON.stringify(input));
    const result = { quarantine_id: quarantineId, sha256: digest };
    this.records.push({ ...input, ...result });
    return result;
  }
}
