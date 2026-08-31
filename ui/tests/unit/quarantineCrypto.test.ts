// Conformance tests against golden fixtures produced by the router's own
// memory_router/envelope.py (see tests/fixtures). If the TS port diverges from
// the Python implementation, these tests fail.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  canonicalDecrypted,
  decryptEnvelope,
  importDecryptionKeyPem,
  DecryptError,
} from "../../src/lib/quarantineCrypto";
import type {
  DecryptedQuarantineObject,
  EncryptedQuarantineEnvelope,
} from "../../src/lib/types";

const FIXTURES = new URL("../fixtures/", import.meta.url);

function fixture<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8")) as T;
}

const privatePem = readFileSync(new URL("quarantine-private.pem", FIXTURES), "utf8");

const IDS = [
  "q_retain_0123456789abcdef",
  "q_recall_aaaabbbbccccdddd",
  "q_query_f00df00df00df00d",
];

describe("decryptEnvelope conformance", () => {
  it.each(IDS)("%s: decrypts to the Python-verified object", async (id) => {
    const envelope = fixture<EncryptedQuarantineEnvelope>(`${id}.envelope.json`);
    const expected = fixture<DecryptedQuarantineObject>(`${id}.decrypted.json`);
    const key = await importDecryptionKeyPem(privatePem);
    const decrypted = await decryptEnvelope(envelope, key);
    expect(decrypted).toEqual(expected);
  });

  it.each(IDS)("%s: canonical form matches the Python hash input byte-for-byte", async (id) => {
    const expectedCanonical = readFileSync(new URL(`${id}.canonical.txt`, FIXTURES), "utf8");
    const decrypted = fixture<DecryptedQuarantineObject>(`${id}.decrypted.json`);
    expect(canonicalDecrypted(decrypted)).toBe(expectedCanonical);
  });

  it("rejects the wrong decryption key", async () => {
    const envelope = fixture<EncryptedQuarantineEnvelope>(
      "q_retain_0123456789abcdef.envelope.json",
    );
    const other = await crypto.subtle.generateKey({ name: "RSA-OAEP", hash: "SHA-256", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) }, false, ["decrypt"]);
    await expect(decryptEnvelope(envelope, other.privateKey)).rejects.toThrow(DecryptError);
  });

  it("rejects a tampered ciphertext", async () => {
    const envelope = fixture<EncryptedQuarantineEnvelope>(
      "q_retain_0123456789abcdef.envelope.json",
    );
    const tampered = {
      ...envelope,
      ciphertext_b64: envelope.ciphertext_b64.replace(/.$/, envelope.ciphertext_b64.endsWith("A") ? "B" : "A"),
    };
    const key = await importDecryptionKeyPem(privatePem);
    await expect(decryptEnvelope(tampered, key)).rejects.toThrow(DecryptError);
  });

  it("rejects envelope metadata that disagrees with the payload", async () => {
    const envelope = fixture<EncryptedQuarantineEnvelope>(
      "q_retain_0123456789abcdef.envelope.json",
    );
    const tampered = { ...envelope, reason: "auth_failed" as const };
    const key = await importDecryptionKeyPem(privatePem);
    await expect(decryptEnvelope(tampered, key)).rejects.toThrow(DecryptError);
  });
});

describe("importDecryptionKeyPem", () => {
  it("imports as non-extractable", async () => {
    const key = await importDecryptionKeyPem(privatePem);
    expect(key.extractable).toBe(false);
    expect(key.type).toBe("private");
  });

  it("rejects garbage input", async () => {
    await expect(importDecryptionKeyPem("not a key")).rejects.toThrow(DecryptError);
  });

  it("rejects encrypted PEM", async () => {
    await expect(
      importDecryptionKeyPem("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"),
    ).rejects.toThrow(DecryptError);
  });
});
