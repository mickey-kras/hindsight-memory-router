import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalizeDecryptedQuarantineObject,
  createEncryptedQuarantineEnvelope,
  decryptQuarantineEnvelope,
  parseEncryptedQuarantineEnvelope,
  sha256Hex,
  type DecryptedQuarantineObject,
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
      body: { items: [{ metadata: { z: "last", a: "first" }, content: "raw" }] },
    },
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
    expect(() => createEncryptedQuarantineEnvelope(decrypted(), "bad-key")).toThrow(
      "QUARANTINE_PUBLIC_KEY",
    );
    expect(() => decryptQuarantineEnvelope(envelope, "bad-key")).toThrow(
      "private key",
    );
  });

  it("detects digest and ciphertext tampering", () => {
    const keys = keyPair();
    const envelope = createEncryptedQuarantineEnvelope(
      decrypted(),
      keys.publicKeyPem,
    );
    expect(() =>
      decryptQuarantineEnvelope(
        { ...envelope, sha256: "0".repeat(64) },
        keys.privateKeyPem,
      ),
    ).toThrow("digest mismatch");
    expect(() =>
      decryptQuarantineEnvelope(
        { ...envelope, ciphertext_b64: Buffer.from("changed").toString("base64") },
        keys.privateKeyPem,
      ),
    ).toThrow();
  });
});
