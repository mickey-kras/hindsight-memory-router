import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { decryptQuarantineEnvelope } from "../src/quarantine/envelopeCrypto.js";
import {
  EncryptedFileQuarantineStore,
  readEncryptedQuarantineEnvelope,
} from "../src/quarantine/quarantineStore.js";

function keyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    publicKey: Buffer.from(publicKey).toString("base64"),
    privateKey: Buffer.from(privateKey).toString("base64"),
  };
}

describe("EncryptedFileQuarantineStore", () => {
  it("stores encrypted payload without raw text", () => {
    const dir = mkdtempSync(join(tmpdir(), "memory-router-quarantine-"));
    try {
      const keys = keyPair();
      const store = new EncryptedFileQuarantineStore(keys.publicKey, dir);
      const result = store.put({
        timestamp: "2026-06-24T00:00:00.000Z",
        reason: "suspicious_content",
        writerId: "ops",
        source: "test",
        payload: { content: "VERY_SECRET_UNTRUSTED_PAYLOAD" },
      });

      const path = join(dir, `${result.quarantine_id}.enc.json`);
      expect(existsSync(path)).toBe(true);
      const stored = readFileSync(path, "utf8");
      expect(stored).toContain(result.quarantine_id);
      expect(stored).not.toContain("VERY_SECRET_UNTRUSTED_PAYLOAD");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("decrypts only with the matching private key", () => {
    const dir = mkdtempSync(join(tmpdir(), "memory-router-quarantine-"));
    try {
      const keys = keyPair();
      const wrongKeys = keyPair();
      const store = new EncryptedFileQuarantineStore(keys.publicKey, dir);
      const result = store.put({
        timestamp: "2026-06-24T00:00:00.000Z",
        reason: "unknown_writer",
        writerId: "unknown",
        source: "test",
        payload: { content: "MATCHING_KEY_ONLY" },
      });
      const envelope = readEncryptedQuarantineEnvelope(
        dir,
        result.quarantine_id,
      );

      const decrypted = decryptQuarantineEnvelope(envelope, keys.privateKey);
      expect(JSON.stringify(decrypted.payload)).toContain("MATCHING_KEY_ONLY");

      expect(() =>
        decryptQuarantineEnvelope(envelope, wrongKeys.privateKey),
      ).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
