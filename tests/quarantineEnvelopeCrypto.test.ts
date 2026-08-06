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
  parseEncryptedQuarantineEnvelope,
  sha256Hex,
  WRAPPED_KEY_FIELD,
  type DecryptedQuarantineObject,
  type EncryptedQuarantineEnvelope,
} from "../src/quarantine/envelopeCrypto.js";

function keyPair(): {
  publicKeyPem: string;
  publicKeyBase64: string;
  privateKeyPem: string;
  privateKeyBase64: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    publicKeyPem: publicKey,
    publicKeyBase64: Buffer.from(publicKey).toString("base64"),
    privateKeyPem: privateKey,
    privateKeyBase64: Buffer.from(privateKey).toString("base64"),
  };
}

function decrypted(): DecryptedQuarantineObject {
  return {
    quarantine_id: "q_20260731040000000Z_0123456789abcdef",
    created_at: "2026-07-31T04:00:00.000Z",
    reason: "unknown_writer",
    writer_id: "unknown-writer",
    source: "test",
    payload: {
      action: "retain",
      body: {
        items: [{ metadata: { z: "last", a: "first" }, content: "raw" }],
      },
    },
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

describe("quarantine envelope crypto", () => {
  it("encrypts and decrypts canonical JSON with PEM and base64 keys", () => {
    const keys = keyPair();
    const value = decrypted();
    const envelope = createEncryptedQuarantineEnvelope(
      value,
      keys.publicKeyBase64,
    );

    expect(envelope.encryption.aad).toBe("metadata-v1");
    expect(envelope.sha256).toBe(
      sha256Hex(canonicalizeDecryptedQuarantineObject(value)),
    );
    expect(decryptQuarantineEnvelope(envelope, keys.privateKeyPem)).toEqual(
      value,
    );
    expect(decryptQuarantineEnvelope(envelope, keys.privateKeyBase64)).toEqual(
      value,
    );
    expect(
      createEncryptedQuarantineEnvelope(value, keys.publicKeyPem).quarantine_id,
    ).toBe(value.quarantine_id);
  });

  it("canonicalizes objects independently of property insertion order", () => {
    const left = decrypted();
    const right = structuredClone(left) as DecryptedQuarantineObject;
    right.payload = {
      body: {
        items: [{ content: "raw", metadata: { a: "first", z: "last" } }],
      },
      action: "retain",
    };
    expect(canonicalizeDecryptedQuarantineObject(left)).toBe(
      canonicalizeDecryptedQuarantineObject(right),
    );
  });

  it("rejects malformed encryption metadata and invalid keys", () => {
    const keys = keyPair();
    const envelope = createEncryptedQuarantineEnvelope(
      decrypted(),
      keys.publicKeyPem,
    );
    expect(() =>
      parseEncryptedQuarantineEnvelope({
        ...envelope,
        encryption: { ...envelope.encryption, tag_b64: "AA==" },
      }),
    ).toThrow("authentication tag length");
    expect(() =>
      parseEncryptedQuarantineEnvelope({
        ...envelope,
        encryption: { ...envelope.encryption, aad: "unknown" },
      }),
    ).toThrow("AAD format");
    expect(() =>
      createEncryptedQuarantineEnvelope(decrypted(), "bad-key"),
    ).toThrow("QUARANTINE_PUBLIC_KEY");
    expect(() => decryptQuarantineEnvelope(envelope, "bad-key")).toThrow(
      "private key",
    );
  });

  it("authenticates envelope metadata and ciphertext", () => {
    const keys = keyPair();
    const envelope = createEncryptedQuarantineEnvelope(
      decrypted(),
      keys.publicKeyPem,
    );
    expect(() =>
      decryptQuarantineEnvelope(
        { ...envelope, created_at: "2026-08-01T00:00:00.000Z" },
        keys.privateKeyPem,
      ),
    ).toThrow();
    expect(() =>
      decryptQuarantineEnvelope(
        { ...envelope, sha256: "0".repeat(64) },
        keys.privateKeyPem,
      ),
    ).toThrow();
    expect(() =>
      decryptQuarantineEnvelope(
        {
          ...envelope,
          ciphertext_b64: Buffer.from("changed").toString("base64"),
        },
        keys.privateKeyPem,
      ),
    ).toThrow();
  });

  it("rejects removal of the AAD marker from a modern envelope", () => {
    const keys = keyPair();
    const envelope = createEncryptedQuarantineEnvelope(
      decrypted(),
      keys.publicKeyPem,
    );
    const downgraded = structuredClone(envelope);
    delete downgraded.encryption.aad;

    expect(() =>
      decryptQuarantineEnvelope(downgraded, keys.privateKeyPem),
    ).toThrow();
  });

  it("continues to decrypt legacy envelopes without AAD", () => {
    const keys = keyPair();
    const value = decrypted();

    expect(
      decryptQuarantineEnvelope(
        createLegacyEnvelope(value, keys.publicKeyPem),
        keys.privateKeyPem,
      ),
    ).toEqual(value);
  });
});
