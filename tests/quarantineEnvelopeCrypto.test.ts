import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  decryptQuarantineEnvelope,
  parseEncryptedQuarantineEnvelope,
} from "../src/quarantine/envelopeCrypto.js";
import {
  EncryptedFileQuarantineStore,
  readEncryptedQuarantineEnvelope,
} from "../src/quarantine/quarantineStore.js";

function keyPair(): {
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
    publicKeyBase64: Buffer.from(publicKey).toString("base64"),
    privateKeyPem: privateKey,
    privateKeyBase64: Buffer.from(privateKey).toString("base64"),
  };
}

function withEnvelope<T>(
  run: (context: {
    envelope: ReturnType<typeof readEncryptedQuarantineEnvelope>;
    privateKeyPem: string;
    privateKeyBase64: string;
  }) => T,
): T {
  const directory = mkdtempSync(join(tmpdir(), "quarantine-crypto-"));
  const keys = keyPair();
  try {
    const store = new EncryptedFileQuarantineStore(
      keys.publicKeyBase64,
      directory,
    );
    const result = store.put({
      timestamp: "2026-07-31T04:00:00.000Z",
      reason: "unknown_writer",
      writerId: "unknown-writer",
      source: "test",
      payload: { secret: "RAW_LOCAL_REVIEW_ONLY" },
    });
    return run({
      envelope: readEncryptedQuarantineEnvelope(
        directory,
        result.quarantine_id,
      ),
      privateKeyPem: keys.privateKeyPem,
      privateKeyBase64: keys.privateKeyBase64,
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("quarantine envelope crypto", () => {
  it("decrypts envelopes with PEM and base64-encoded private keys", () => {
    withEnvelope(({ envelope, privateKeyPem, privateKeyBase64 }) => {
      expect(decryptQuarantineEnvelope(envelope, privateKeyPem)).toMatchObject({
        quarantine_id: envelope.quarantine_id,
        payload: { secret: "RAW_LOCAL_REVIEW_ONLY" },
      });
      expect(
        decryptQuarantineEnvelope(envelope, privateKeyBase64),
      ).toMatchObject({ payload: { secret: "RAW_LOCAL_REVIEW_ONLY" } });
    });
  });

  it("rejects malformed encryption metadata", () => {
    withEnvelope(({ envelope }) => {
      expect(() =>
        parseEncryptedQuarantineEnvelope({
          ...envelope,
          encryption: { ...envelope.encryption, tag_b64: "AA==" },
        }),
      ).toThrow("authentication tag length");
    });
  });

  it("detects digest tampering after authenticated decryption", () => {
    withEnvelope(({ envelope, privateKeyPem }) => {
      expect(() =>
        decryptQuarantineEnvelope(
          { ...envelope, sha256: "0".repeat(64) },
          privateKeyPem,
        ),
      ).toThrow("digest mismatch");
    });
  });

  it("rejects a private key that cannot unwrap the envelope key", () => {
    withEnvelope(({ envelope }) => {
      const otherKeys = keyPair();
      expect(() =>
        decryptQuarantineEnvelope(envelope, otherKeys.privateKeyPem),
      ).toThrow();
    });
  });
});
