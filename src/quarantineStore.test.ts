import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import {
  EncryptedFileQuarantineStore,
  readDecryptedQuarantineObject,
} from "./quarantineStore.js";

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
        payload: { content: "DECRYPT_ME_ONLY_WITH_PRIVATE_KEY" },
      });

      const decrypted = readDecryptedQuarantineObject(
        dir,
        result.quarantine_id,
        keys.privateKey,
      );
      expect(JSON.stringify(decrypted.payload)).toContain(
        "DECRYPT_ME_ONLY_WITH_PRIVATE_KEY",
      );

      expect(() =>
        readDecryptedQuarantineObject(
          dir,
          result.quarantine_id,
          wrongKeys.privateKey,
        ),
      ).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
