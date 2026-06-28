import {
  constants,
  createCipheriv,
  createDecipheriv,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { resolve, sep } from "node:path";
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

export interface DecryptedQuarantineObject {
  quarantine_id: string;
  created_at: string;
  reason: ReviewReason;
  writer_id?: string;
  source?: string;
  payload: unknown;
}

interface EncryptedEnvelope {
  version: 1;
  quarantine_id: string;
  created_at: string;
  reason: ReviewReason;
  writer_id?: string;
  source?: string;
  sha256: string;
  encryption: {
    algorithm: "AES-256-GCM";
    key_wrap: "RSA-OAEP-SHA256";
    wrapped_key_b64: string;
    iv_b64: string;
    tag_b64: string;
  };
  ciphertext_b64: string;
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

export function privateKeyPemFromEnv(value?: string): string {
  if (!value?.trim()) throw new Error("QUARANTINE_PRIVATE_KEY is required");

  const trimmed = value.trim();
  if (trimmed.includes("BEGIN PRIVATE KEY")) {
    return trimmed.replace(/\\n/g, "\n");
  }

  const decoded = Buffer.from(trimmed, "base64").toString("utf8");
  if (!decoded.includes("BEGIN PRIVATE KEY")) {
    throw new Error("QUARANTINE_PRIVATE_KEY must be PEM or base64-encoded PEM");
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

export function decryptQuarantineEnvelope(
  envelope: EncryptedEnvelope,
  privateKeyEnv: string | undefined,
): DecryptedQuarantineObject {
  const privateKey = privateKeyPemFromEnv(privateKeyEnv);
  const key = privateDecrypt(
    {
      key: privateKey,
      oaepHash: "sha256",
      padding: constants.RSA_PKCS1_OAEP_PADDING,
    },
    Buffer.from(envelope.encryption.wrapped_key_b64, "base64"),
  );
  const tag = Buffer.from(envelope.encryption.tag_b64, "base64");
  if (tag.length !== GCM_AUTH_TAG_LENGTH_BYTES) {
    throw new Error("invalid AES-GCM authentication tag length");
  }
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(envelope.encryption.iv_b64, "base64"),
    { authTagLength: GCM_AUTH_TAG_LENGTH_BYTES },
  );
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext_b64, "base64")),
    decipher.final(),
  ]).toString("utf8");
  const decrypted = JSON.parse(plaintext) as DecryptedQuarantineObject;
  if (sha256(plaintext) !== envelope.sha256) {
    throw new Error("quarantine object digest mismatch");
  }
  return decrypted;
}

export function readEncryptedQuarantineEnvelope(
  objectDir: string,
  quarantineId: string,
): EncryptedEnvelope {
  const raw = readFileSync(
    encryptedQuarantineObjectPath(objectDir, quarantineId),
    {
      encoding: "utf8",
    },
  );
  return JSON.parse(raw) as EncryptedEnvelope;
}

export function readDecryptedQuarantineObject(
  objectDir: string,
  quarantineId: string,
  privateKeyEnv: string | undefined,
): DecryptedQuarantineObject {
  return decryptQuarantineEnvelope(
    readEncryptedQuarantineEnvelope(objectDir, quarantineId),
    privateKeyEnv,
  );
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

    const envelope: EncryptedEnvelope = {
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
        wrapped_key_b64: wrappedKey.toString("base64"),
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
