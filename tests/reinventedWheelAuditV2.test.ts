import {
  constants,
  createCipheriv,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalizeDecryptedQuarantineObject,
  createEncryptedQuarantineEnvelope,
  decryptQuarantineEnvelope,
  sha256Hex,
  WRAPPED_KEY_FIELD,
  type DecryptedQuarantineObject,
  type EncryptedQuarantineEnvelope,
} from "../src/quarantine/envelopeCrypto.js";
import { validateRegistry } from "../src/registry.js";
import type { WriterRegistry } from "../src/types.js";

function registry(value: unknown): WriterRegistry {
  return value as WriterRegistry;
}

function keyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

function decrypted(): DecryptedQuarantineObject {
  return {
    quarantine_id: "q_20260806060000000Z_0123456789abcdef",
    created_at: "2026-08-06T06:00:00.000Z",
    reason: "unknown_writer",
    writer_id: "unknown-writer",
    source: "test",
    payload: { action: "retain", body: { items: [{ content: "raw" }] } },
  };
}

function createLegacyEnvelope(
  value: DecryptedQuarantineObject,
  publicKey: string,
): EncryptedQuarantineEnvelope {
  const plaintext = canonicalizeDecryptedQuarantineObject(value);
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: 16,
  });
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const wrappedKey = publicEncrypt(
    {
      key: publicKey,
      oaepHash: "sha256",
      padding: constants.RSA_PKCS1_OAEP_PADDING,
    },
    key,
  );
  return {
    version: 1,
    quarantine_id: value.quarantine_id,
    created_at: value.created_at,
    reason: value.reason,
    writer_id: value.writer_id,
    source: value.source,
    sha256: sha256Hex(plaintext),
    encryption: {
      algorithm: "AES-256-GCM",
      key_wrap: "RSA-OAEP-SHA256",
      [WRAPPED_KEY_FIELD]: wrappedKey.toString("base64"),
      iv_b64: iv.toString("base64"),
      tag_b64: cipher.getAuthTag().toString("base64"),
    },
    ciphertext_b64: ciphertext.toString("base64"),
  };
}

describe("reinvented-wheel audit v2 regressions", () => {
  it("rejects removal of the AAD marker from a modern envelope", () => {
    const keys = keyPair();
    const envelope = createEncryptedQuarantineEnvelope(
      decrypted(),
      keys.publicKey,
    );
    const downgraded = structuredClone(envelope);
    delete downgraded.encryption.aad;

    expect(() =>
      decryptQuarantineEnvelope(downgraded, keys.privateKey),
    ).toThrow();
  });

  it("continues to decrypt legacy envelopes without AAD", () => {
    const keys = keyPair();
    const value = decrypted();

    expect(
      decryptQuarantineEnvelope(
        createLegacyEnvelope(value, keys.publicKey),
        keys.privateKey,
      ),
    ).toEqual(value);
  });

  it.each([
    [
      registry({
        writers: { ops: null },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops must be an object",
    ],
    [
      registry({
        writers: {
          ops: {
            role: "",
            source: "test",
            write_bank: "ops",
            read_banks: ["ops"],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops missing role",
    ],
    [
      registry({
        writers: {
          ops: {
            role: "ops",
            source: "",
            write_bank: "ops",
            read_banks: ["ops"],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops missing source",
    ],
    [
      registry({
        writers: {
          ops: {
            role: "ops",
            source: "test",
            write_bank: "bogus",
            read_banks: ["ops"],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops has invalid write_bank",
    ],
    [
      registry({
        writers: {
          ops: {
            role: "ops",
            source: "test",
            write_bank: "ops",
            read_banks: ["bogus"],
          },
        },
        defaults: {
          unknown_writer_action: "review_queue",
          suspicious_content_action: "review_queue",
        },
      }),
      "writer ops has invalid read_bank",
    ],
    [registry({ writers: {}, defaults: null }), "registry.defaults must be an object"],
  ])("rejects incomplete registry runtime shapes", (value, message) => {
    expect(() => validateRegistry(value)).toThrow(message);
  });
});
