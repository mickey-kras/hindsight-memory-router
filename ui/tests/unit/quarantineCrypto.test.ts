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
  ReviewReason,
} from "../../src/lib/types";
import { REASONS } from "../../src/lib/types";

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
  it.each(REASONS)("decrypts the supported reason %s", async (reason) => {
    const envelopes = fixture<Record<ReviewReason, EncryptedQuarantineEnvelope>>("reasons.json");
    const key = await importDecryptionKeyPem(privatePem);
    const decrypted = await decryptEnvelope(envelopes[reason], key);
    expect(decrypted.reason).toBe(reason);
  });

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

describe("key wrap provider fail-closed", () => {
  function withProvider(
    encryption: Record<string, unknown>,
  ): EncryptedQuarantineEnvelope {
    const envelope = fixture<EncryptedQuarantineEnvelope>(
      "q_retain_0123456789abcdef.envelope.json",
    );
    return { ...envelope, encryption: { ...envelope.encryption, ...encryption } };
  }

  it("rejects an RSA envelope carrying an inert provider block", async () => {
    // Golden fixture from create_provider_envelope: valid RSA-OAEP wrap, but
    // the provider block means unwrap requires the matching review-tool
    // provider. Python decrypt_envelope rejects it; the UI must too.
    const envelope = fixture<EncryptedQuarantineEnvelope>(
      "q_provider_0123456789abcdef.envelope.json",
    );
    expect(envelope.encryption.key_wrap).toBe("RSA-OAEP-SHA256");
    expect(envelope.encryption.provider).toEqual({ name: "fixture-inert", version: 1 });
    const key = await importDecryptionKeyPem(privatePem);
    await expect(decryptEnvelope(envelope, key)).rejects.toThrow(
      "unsupported quarantine key wrap provider",
    );
  });

  it("rejects a provider envelope before touching the key", async () => {
    const envelope = withProvider({ provider: { name: "sidecar", version: 2 } });
    const wrongKey = crypto.subtle.generateKey(
      { name: "RSA-OAEP", hash: "SHA-256", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) },
      false,
      ["decrypt"],
    );
    await expect(decryptEnvelope(envelope, (await wrongKey).privateKey)).rejects.toThrow(
      "unsupported quarantine key wrap provider",
    );
  });

  it.each([
    ["a non-object provider", { provider: "sidecar" }],
    ["a provider missing version", { provider: { name: "sidecar" } }],
    ["a provider with extra fields", { provider: { name: "sidecar", version: 1, url: "https://x" } }],
    ["a provider with a bad name", { provider: { name: "bad name!", version: 1 } }],
    ["a provider with a zero version", { provider: { name: "sidecar", version: 0 } }],
    ["a provider with a float version", { provider: { name: "sidecar", version: 1.5 } }],
    ["a provider with a string version", { provider: { name: "sidecar", version: "1" } }],
  ])("fails closed on %s", async (_label, encryption) => {
    const key = await importDecryptionKeyPem(privatePem);
    await expect(decryptEnvelope(withProvider(encryption), key)).rejects.toThrow(
      "invalid quarantine key wrap provider",
    );
  });

  it("rejects an unknown key_wrap without a provider block", async () => {
    const key = await importDecryptionKeyPem(privatePem);
    await expect(
      decryptEnvelope(withProvider({ key_wrap: "WRAP-SIDECAR" }), key),
    ).rejects.toThrow("unsupported quarantine key wrapping algorithm");
  });

  it("rejects a malformed key_wrap token alongside a provider block", async () => {
    const key = await importDecryptionKeyPem(privatePem);
    await expect(
      decryptEnvelope(
        withProvider({ key_wrap: "not a token", provider: { name: "sidecar", version: 1 } }),
        key,
      ),
    ).rejects.toThrow("unsupported quarantine key wrapping algorithm");
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
