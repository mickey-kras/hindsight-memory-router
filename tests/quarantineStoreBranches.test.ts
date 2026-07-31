import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertSafeQuarantineId,
  decryptQuarantineEnvelope,
  deleteEncryptedQuarantineObject,
  encryptedQuarantineObjectPath,
  EncryptedFileQuarantineStore,
  MemoryQuarantineStore,
  privateKeyPemFromEnv,
  readDecryptedQuarantineObject,
  readEncryptedQuarantineEnvelope,
} from "../src/quarantineStore.js";

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    publicKeyBase64: Buffer.from(publicKey).toString("base64"),
    privateKeyBase64: Buffer.from(privateKey).toString("base64"),
  };
}

function createEnvelope() {
  const directory = mkdtempSync(join(tmpdir(), "quarantine-branches-"));
  const keys = keyPair();
  const store = new EncryptedFileQuarantineStore(
    keys.publicKeyBase64,
    directory,
  );
  const result = store.put({
    timestamp: "2026-07-31T00:00:00.000Z",
    reason: "unknown_writer",
    payload: { content: "review locally" },
  });
  return {
    directory,
    keys,
    result,
    envelope: readEncryptedQuarantineEnvelope(directory, result.quarantine_id),
  };
}

describe("quarantine store branches", () => {
  it("validates public and private key configuration", () => {
    const directory = mkdtempSync(join(tmpdir(), "quarantine-keys-"));
    const keys = keyPair();
    const input = {
      timestamp: "2026-07-31T00:00:00.000Z",
      reason: "unknown_writer" as const,
      payload: { content: "payload" },
    };
    try {
      expect(() =>
        new EncryptedFileQuarantineStore(undefined, directory).put(input),
      ).toThrow("QUARANTINE_PUBLIC_KEY is required");
      expect(() =>
        new EncryptedFileQuarantineStore("not-a-key", directory).put(input),
      ).toThrow("QUARANTINE_PUBLIC_KEY must be PEM or base64-encoded PEM");
      expect(() =>
        new EncryptedFileQuarantineStore(
          keys.publicKeyPem.replaceAll("\n", "\\n"),
          directory,
        ).put(input),
      ).not.toThrow();

      expect(() => privateKeyPemFromEnv()).toThrow(
        "QUARANTINE_PRIVATE_KEY is required",
      );
      expect(() => privateKeyPemFromEnv("not-a-key")).toThrow(
        "QUARANTINE_PRIVATE_KEY must be PEM or base64-encoded PEM",
      );
      expect(
        privateKeyPemFromEnv(keys.privateKeyPem.replaceAll("\n", "\\n")),
      ).toContain("BEGIN PRIVATE KEY");
      expect(privateKeyPemFromEnv(keys.privateKeyBase64)).toContain(
        "BEGIN PRIVATE KEY",
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("validates quarantine ids and derives safe object paths", () => {
    const id = "q_20260731_0123456789abcdef";
    expect(() => assertSafeQuarantineId(id)).not.toThrow();
    expect(encryptedQuarantineObjectPath("/tmp/quarantine", id)).toBe(
      `/tmp/quarantine/${id}.enc.json`,
    );
    expect(() => assertSafeQuarantineId("../escape")).toThrow(
      "invalid quarantine_id",
    );
  });

  it("rejects malformed authentication tags and digest mismatches", () => {
    const context = createEnvelope();
    try {
      expect(() =>
        decryptQuarantineEnvelope(
          {
            ...context.envelope,
            encryption: { ...context.envelope.encryption, tag_b64: "AA==" },
          },
          context.keys.privateKeyPem,
        ),
      ).toThrow("invalid AES-GCM authentication tag length");

      expect(() =>
        decryptQuarantineEnvelope(
          { ...context.envelope, sha256: "0".repeat(64) },
          context.keys.privateKeyPem,
        ),
      ).toThrow("quarantine object digest mismatch");
    } finally {
      rmSync(context.directory, { recursive: true, force: true });
    }
  });

  it("reads, decrypts, and deletes encrypted objects", () => {
    const context = createEnvelope();
    const path = encryptedQuarantineObjectPath(
      context.directory,
      context.result.quarantine_id,
    );
    try {
      expect(
        readDecryptedQuarantineObject(
          context.directory,
          context.result.quarantine_id,
          context.keys.privateKeyBase64,
        ),
      ).toMatchObject({ payload: { content: "review locally" } });
      expect(existsSync(path)).toBe(true);
      deleteEncryptedQuarantineObject(
        context.directory,
        context.result.quarantine_id,
      );
      expect(existsSync(path)).toBe(false);
    } finally {
      rmSync(context.directory, { recursive: true, force: true });
    }
  });

  it("records deterministic in-memory quarantine ids", () => {
    const store = new MemoryQuarantineStore();
    const input = {
      timestamp: "2026-07-31T00:00:00.000Z",
      reason: "unknown_writer" as const,
      payload: { content: "payload" },
    };
    expect(store.put(input).quarantine_id).toBe("q_test_1");
    expect(store.put(input).quarantine_id).toBe("q_test_2");
    expect(store.records).toHaveLength(2);
  });
});
