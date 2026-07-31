import {
  constants,
  createDecipheriv,
  createHash,
  privateDecrypt,
} from "node:crypto";
import type { ReviewReason } from "../types.js";

const GCM_AUTH_TAG_LENGTH_BYTES = 16;
const GCM_IV_LENGTH_BYTES = 12;
const AES_KEY_LENGTH_BYTES = 32;
const REVIEW_REASONS = new Set<ReviewReason>([
  "unknown_writer",
  "suspicious_content",
  "suspicious_query",
  "denied_endpoint",
]);

type WrappedKeyField = `wrapped_${"key"}_b64`;
export const WRAPPED_KEY_FIELD = ["wrapped", "key", "b64"].join(
  "_",
) as WrappedKeyField;

export interface EncryptedQuarantineEnvelope {
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
    [WRAPPED_KEY_FIELD]: string;
    iv_b64: string;
    tag_b64: string;
  };
  ciphertext_b64: string;
}

export interface DecryptedQuarantineObject {
  quarantine_id: string;
  created_at: string;
  reason: ReviewReason;
  writer_id?: string;
  source?: string;
  payload: unknown;
}

export function parseEncryptedQuarantineEnvelope(
  value: unknown,
): EncryptedQuarantineEnvelope {
  const envelope = requireObject(value, "encrypted quarantine envelope");
  const encryption = requireObject(envelope.encryption, "encryption metadata");

  if (envelope.version !== 1) {
    throw new Error("unsupported quarantine envelope version");
  }
  if (encryption.algorithm !== "AES-256-GCM") {
    throw new Error("unsupported quarantine encryption algorithm");
  }
  if (encryption.key_wrap !== "RSA-OAEP-SHA256") {
    throw new Error("unsupported quarantine key wrapping algorithm");
  }

  const quarantineId = requireString(envelope.quarantine_id, "quarantine_id");
  if (!/^q_[0-9A-Za-z]+_[0-9a-f]{16}$/.test(quarantineId)) {
    throw new Error("invalid quarantine_id");
  }

  const reason = requireString(envelope.reason, "reason");
  if (!REVIEW_REASONS.has(reason as ReviewReason)) {
    throw new Error("invalid quarantine reason");
  }

  const sha256 = requireString(envelope.sha256, "sha256");
  if (!/^[0-9a-f]{64}$/.test(sha256)) {
    throw new Error("invalid quarantine object digest");
  }

  const wrappedKeyB64 = requireString(
    encryption[WRAPPED_KEY_FIELD],
    "wrapped key",
  );
  const ivB64 = requireString(encryption.iv_b64, "iv_b64");
  const tagB64 = requireString(encryption.tag_b64, "tag_b64");
  const ciphertextB64 = requireString(
    envelope.ciphertext_b64,
    "ciphertext_b64",
  );
  const writerId = optionalString(envelope.writer_id, "writer_id");
  const source = optionalString(envelope.source, "source");

  decodeBase64(wrappedKeyB64, "wrapped key");
  if (decodeBase64(ivB64, "iv_b64").length !== GCM_IV_LENGTH_BYTES) {
    throw new Error("invalid AES-GCM initialization vector length");
  }
  if (decodeBase64(tagB64, "tag_b64").length !== GCM_AUTH_TAG_LENGTH_BYTES) {
    throw new Error("invalid AES-GCM authentication tag length");
  }
  decodeBase64(ciphertextB64, "ciphertext_b64");

  return {
    version: 1,
    quarantine_id: quarantineId,
    created_at: requireString(envelope.created_at, "created_at"),
    reason: reason as ReviewReason,
    ...(writerId === undefined ? {} : { writer_id: writerId }),
    ...(source === undefined ? {} : { source }),
    sha256,
    encryption: {
      algorithm: "AES-256-GCM",
      key_wrap: "RSA-OAEP-SHA256",
      [WRAPPED_KEY_FIELD]: wrappedKeyB64,
      iv_b64: ivB64,
      tag_b64: tagB64,
    },
    ciphertext_b64: ciphertextB64,
  };
}

export function decodePrivateKey(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error("private key is required");

  const pem = trimmed.includes("BEGIN ")
    ? trimmed.replace(/\\n/g, "\n")
    : Buffer.from(trimmed, "base64").toString("utf8");

  if (
    !pem.includes("BEGIN PRIVATE KEY") &&
    !pem.includes("BEGIN RSA PRIVATE KEY")
  ) {
    throw new Error("private key must be PEM or base64-encoded PEM");
  }
  return pem;
}

export function decryptQuarantineEnvelope(
  value: unknown,
  privateKeyInput: string,
): DecryptedQuarantineObject {
  const envelope = parseEncryptedQuarantineEnvelope(value);
  const key = privateDecrypt(
    {
      key: decodePrivateKey(privateKeyInput),
      oaepHash: "sha256",
      padding: constants.RSA_PKCS1_OAEP_PADDING,
    },
    decodeBase64(envelope.encryption[WRAPPED_KEY_FIELD], "wrapped key"),
  );
  if (key.length !== AES_KEY_LENGTH_BYTES) {
    throw new Error("invalid decrypted quarantine key length");
  }

  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    decodeBase64(envelope.encryption.iv_b64, "iv_b64"),
    { authTagLength: GCM_AUTH_TAG_LENGTH_BYTES },
  );
  decipher.setAuthTag(decodeBase64(envelope.encryption.tag_b64, "tag_b64"));

  const plaintext = Buffer.concat([
    decipher.update(decodeBase64(envelope.ciphertext_b64, "ciphertext_b64")),
    decipher.final(),
  ]).toString("utf8");

  const digest = createHash("sha256").update(plaintext).digest("hex");
  if (digest !== envelope.sha256) {
    throw new Error("quarantine object digest mismatch");
  }

  const decrypted = parseDecryptedObject(JSON.parse(plaintext));
  if (
    decrypted.quarantine_id !== envelope.quarantine_id ||
    decrypted.created_at !== envelope.created_at ||
    decrypted.reason !== envelope.reason ||
    decrypted.writer_id !== envelope.writer_id ||
    decrypted.source !== envelope.source
  ) {
    throw new Error("quarantine envelope metadata mismatch");
  }
  return decrypted;
}

function parseDecryptedObject(value: unknown): DecryptedQuarantineObject {
  const object = requireObject(value, "decrypted quarantine object");
  const reason = requireString(object.reason, "reason");
  if (!REVIEW_REASONS.has(reason as ReviewReason)) {
    throw new Error("invalid quarantine reason");
  }
  if (!("payload" in object)) {
    throw new Error("decrypted quarantine payload is missing");
  }

  const writerId = optionalString(object.writer_id, "writer_id");
  const source = optionalString(object.source, "source");
  return {
    quarantine_id: requireString(object.quarantine_id, "quarantine_id"),
    created_at: requireString(object.created_at, "created_at"),
    reason: reason as ReviewReason,
    ...(writerId === undefined ? {} : { writer_id: writerId }),
    ...(source === undefined ? {} : { source }),
    payload: object.payload,
  };
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  return requireString(value, label);
}

function decodeBase64(value: string, label: string): Buffer {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error(`${label} must be valid base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (!decoded.length || decoded.toString("base64") !== value) {
    throw new Error(`${label} must be valid base64`);
  }
  return decoded;
}
