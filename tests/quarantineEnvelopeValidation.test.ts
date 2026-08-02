import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createEncryptedQuarantineEnvelope,
  decodePrivateKey,
  decryptQuarantineEnvelope,
  parseDecryptedQuarantineObject,
  parseEncryptedQuarantineEnvelope,
  WRAPPED_KEY_FIELD,
  type DecryptedQuarantineObject,
} from "../src/quarantine/envelopeCrypto.js";

function context() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const decrypted: DecryptedQuarantineObject = {
    quarantine_id: "q_20260731073000000Z_0123456789abcdef",
    created_at: "2026-07-31T07:30:00.000Z",
    reason: "recalled_suspicious_memory",
    writer_id: "writer-a",
    source: "validation-test",
    payload: {
      action: "recalled_memory",
      bank_id: "ops",
      result: { id: "memory-1", text: "encrypted" },
    },
  };
  return {
    decrypted,
    privateKey,
    envelope: createEncryptedQuarantineEnvelope(decrypted, publicKey),
  };
}

describe("quarantine envelope validation", () => {
  it("rejects malformed envelope fields", () => {
    const { envelope } = context();
    const cases: Array<[unknown, string]> = [
      [null, "encrypted quarantine envelope must be an object"],
      [[envelope], "encrypted quarantine envelope must be an object"],
      [
        { ...envelope, encryption: null },
        "encryption metadata must be an object",
      ],
      [{ ...envelope, version: 2 }, "unsupported quarantine envelope version"],
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
      [{ ...envelope, reason: "other" }, "invalid quarantine reason"],
      [{ ...envelope, sha256: "abc" }, "invalid quarantine object digest"],
      [
        { ...envelope, created_at: undefined },
        "created_at must be a non-empty string",
      ],
      [{ ...envelope, writer_id: "" }, "writer_id must be a non-empty string"],
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
    ];

    for (const [value, message] of cases) {
      expect(() => parseEncryptedQuarantineEnvelope(value)).toThrow(message);
    }
  });

  it("accepts envelopes and decrypted objects without optional metadata", () => {
    const { envelope, decrypted } = context();
    const envelopeWithoutOptional = structuredClone(envelope) as Record<
      string,
      unknown
    >;
    delete envelopeWithoutOptional.writer_id;
    delete envelopeWithoutOptional.source;
    expect(
      parseEncryptedQuarantineEnvelope(envelopeWithoutOptional),
    ).not.toHaveProperty("writer_id");

    const decryptedWithoutOptional = structuredClone(decrypted) as Record<
      string,
      unknown
    >;
    delete decryptedWithoutOptional.writer_id;
    delete decryptedWithoutOptional.source;
    expect(
      parseDecryptedQuarantineObject(decryptedWithoutOptional),
    ).not.toHaveProperty("source");
  });

  it("validates decrypted payload and private key forms", () => {
    expect(() => parseDecryptedQuarantineObject(null)).toThrow(
      "decrypted quarantine object must be an object",
    );
    expect(() =>
      parseDecryptedQuarantineObject({
        quarantine_id: "q_20260731073000000Z_0123456789abcdef",
        created_at: "2026-07-31T07:30:00.000Z",
        reason: "unknown_writer",
      }),
    ).toThrow("payload is missing");

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

  it("detects authenticated metadata mismatch", () => {
    const { envelope, privateKey } = context();
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
