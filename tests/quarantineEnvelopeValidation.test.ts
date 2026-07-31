import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  decodePrivateKey,
  decryptQuarantineEnvelope,
  parseEncryptedQuarantineEnvelope,
  WRAPPED_KEY_FIELD,
} from "../src/quarantine/envelopeCrypto.js";
import {
  EncryptedFileQuarantineStore,
  readEncryptedQuarantineEnvelope,
} from "../src/quarantineStore.js";

function withEnvelope<T>(
  run: (context: {
    envelope: ReturnType<typeof readEncryptedQuarantineEnvelope>;
    privateKey: string;
  }) => T,
): T {
  const directory = mkdtempSync(join(tmpdir(), "quarantine-validation-"));
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  try {
    const store = new EncryptedFileQuarantineStore(
      Buffer.from(publicKey).toString("base64"),
      directory,
    );
    const result = store.put({
      timestamp: "2026-07-31T07:30:00.000Z",
      reason: "unknown_writer",
      writerId: "writer-a",
      source: "validation-test",
      payload: { content: "encrypted" },
    });
    return run({
      envelope: readEncryptedQuarantineEnvelope(
        directory,
        result.quarantine_id,
      ),
      privateKey,
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

describe("quarantine envelope validation", () => {
  it("rejects malformed envelope fields", () => {
    withEnvelope(({ envelope }) => {
      const cases: Array<[unknown, string]> = [
        [null, "encrypted quarantine envelope must be an object"],
        [[envelope], "encrypted quarantine envelope must be an object"],
        [
          { ...envelope, encryption: null },
          "encryption metadata must be an object",
        ],
        [
          { ...envelope, version: 2 },
          "unsupported quarantine envelope version",
        ],
        [
          {
            ...envelope,
            encryption: { ...envelope.encryption, algorithm: "AES-128-GCM" },
          },
          "unsupported quarantine encryption algorithm",
        ],
        [
          {
            ...envelope,
            encryption: { ...envelope.encryption, key_wrap: "RSA-OAEP" },
          },
          "unsupported quarantine key wrapping algorithm",
        ],
        [{ ...envelope, quarantine_id: "bad" }, "invalid quarantine_id"],
        [
          { ...envelope, quarantine_id: "" },
          "quarantine_id must be a non-empty string",
        ],
        [{ ...envelope, reason: "other" }, "invalid quarantine reason"],
        [{ ...envelope, sha256: "abc" }, "invalid quarantine object digest"],
        [
          { ...envelope, created_at: undefined },
          "created_at must be a non-empty string",
        ],
        [
          { ...envelope, writer_id: "" },
          "writer_id must be a non-empty string",
        ],
        [{ ...envelope, source: 42 }, "source must be a non-empty string"],
        [
          {
            ...envelope,
            encryption: {
              ...envelope.encryption,
              [WRAPPED_KEY_FIELD]: undefined,
            },
          },
          "wrapped key must be a non-empty string",
        ],
        [
          {
            ...envelope,
            encryption: {
              ...envelope.encryption,
              [WRAPPED_KEY_FIELD]: "not-base64",
            },
          },
          "wrapped key must be valid base64",
        ],
        [
          {
            ...envelope,
            encryption: { ...envelope.encryption, iv_b64: "not-base64" },
          },
          "iv_b64 must be valid base64",
        ],
        [
          {
            ...envelope,
            encryption: {
              ...envelope.encryption,
              iv_b64: Buffer.alloc(11).toString("base64"),
            },
          },
          "invalid AES-GCM initialization vector length",
        ],
        [
          {
            ...envelope,
            encryption: { ...envelope.encryption, tag_b64: "not-base64" },
          },
          "tag_b64 must be valid base64",
        ],
        [
          {
            ...envelope,
            encryption: {
              ...envelope.encryption,
              tag_b64: Buffer.alloc(15).toString("base64"),
            },
          },
          "invalid AES-GCM authentication tag length",
        ],
        [
          { ...envelope, ciphertext_b64: "not-base64" },
          "ciphertext_b64 must be valid base64",
        ],
        [
          { ...envelope, ciphertext_b64: "AAAA=" },
          "ciphertext_b64 must be valid base64",
        ],
      ];

      for (const [value, message] of cases) {
        expect(() => parseEncryptedQuarantineEnvelope(value)).toThrow(message);
      }
    });
  });

  it("accepts envelopes without optional metadata", () => {
    withEnvelope(({ envelope }) => {
      const value = clone(envelope) as Record<string, unknown>;
      delete value.writer_id;
      delete value.source;
      expect(parseEncryptedQuarantineEnvelope(value)).not.toHaveProperty(
        "writer_id",
      );
      expect(parseEncryptedQuarantineEnvelope(value)).not.toHaveProperty(
        "source",
      );
    });
  });

  it("accepts PKCS1 private keys", () => {
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    expect(decodePrivateKey(privateKey)).toContain("BEGIN RSA PRIVATE KEY");
    expect(
      decodePrivateKey(Buffer.from(privateKey).toString("base64")),
    ).toContain("BEGIN RSA PRIVATE KEY");
  });

  it("detects every authenticated metadata mismatch", () => {
    withEnvelope(({ envelope, privateKey }) => {
      const mutations: Array<Record<string, unknown>> = [
        { quarantine_id: "q_other_0123456789abcdef" },
        { created_at: "2026-08-01T00:00:00.000Z" },
        { reason: "denied_endpoint" },
        { writer_id: "writer-b" },
        { source: "other-source" },
      ];
      for (const mutation of mutations) {
        expect(() =>
          decryptQuarantineEnvelope({ ...envelope, ...mutation }, privateKey),
        ).toThrow("quarantine envelope metadata mismatch");
      }
    });
  });
});
