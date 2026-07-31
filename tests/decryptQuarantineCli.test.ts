import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  decryptQuarantineResponseFile,
  extractEnvelope,
  readPrivateKey,
  runDecryptQuarantineCli,
} from "../src/cli/decryptQuarantine.js";
import {
  EncryptedFileQuarantineStore,
  readEncryptedQuarantineEnvelope,
} from "../src/quarantine/quarantineStore.js";

function createContext() {
  const directory = mkdtempSync(join(tmpdir(), "decrypt-quarantine-cli-"));
  const responsePath = join(directory, "response.json");
  const barePath = join(directory, "envelope.json");
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const store = new EncryptedFileQuarantineStore(
    Buffer.from(publicKey).toString("base64"),
    directory,
  );
  const result = store.put({
    timestamp: "2026-07-31T07:00:00.000Z",
    reason: "suspicious_content",
    writerId: "unknown",
    source: "cli-test",
    payload: { content: "decrypt locally" },
  });
  const envelope = readEncryptedQuarantineEnvelope(
    directory,
    result.quarantine_id,
  );
  writeFileSync(responsePath, JSON.stringify({ encrypted: envelope }), "utf8");
  writeFileSync(barePath, JSON.stringify(envelope), "utf8");
  return { directory, responsePath, barePath, privateKey, envelope };
}

function capture() {
  let value = "";
  return {
    stream: { write: (chunk: string) => (value += chunk) },
    value: () => value,
  };
}

describe("decrypt quarantine CLI", () => {
  it("extracts wrapped and bare encrypted envelopes", () => {
    const context = createContext();
    try {
      expect(extractEnvelope({ encrypted: context.envelope })).toEqual(
        context.envelope,
      );
      expect(extractEnvelope(context.envelope)).toEqual(context.envelope);
    } finally {
      rmSync(context.directory, { recursive: true, force: true });
    }
  });

  it("reads a private key from streamed string and buffer chunks", async () => {
    await expect(
      readPrivateKey(Readable.from(["  key", Buffer.from(" material  ")])),
    ).resolves.toBe("key material");
    await expect(readPrivateKey(Readable.from([]))).rejects.toThrow(
      "private key is required on stdin",
    );
  });

  it("decrypts wrapped and bare response files", async () => {
    const context = createContext();
    try {
      await expect(
        decryptQuarantineResponseFile(context.responsePath, context.privateKey),
      ).resolves.toMatchObject({ payload: { content: "decrypt locally" } });
      await expect(
        decryptQuarantineResponseFile(context.barePath, context.privateKey),
      ).resolves.toMatchObject({ source: "cli-test" });
    } finally {
      rmSync(context.directory, { recursive: true, force: true });
    }
  });

  it("writes decrypted JSON and returns success", async () => {
    const context = createContext();
    const stdout = capture();
    const stderr = capture();
    try {
      await expect(
        runDecryptQuarantineCli([context.responsePath], {
          stdin: Readable.from([context.privateKey]),
          stdout: stdout.stream,
          stderr: stderr.stream,
        }),
      ).resolves.toBe(0);
      expect(JSON.parse(stdout.value())).toMatchObject({
        payload: { content: "decrypt locally" },
      });
      expect(stderr.value()).toBe("");
    } finally {
      rmSync(context.directory, { recursive: true, force: true });
    }
  });

  it("reports usage and input errors without throwing", async () => {
    const stdout = capture();
    const stderr = capture();
    await expect(
      runDecryptQuarantineCli([], {
        stdin: Readable.from([]),
        stdout: stdout.stream,
        stderr: stderr.stream,
      }),
    ).resolves.toBe(1);
    expect(stderr.value()).toContain("usage:");

    const context = createContext();
    const emptyKeyError = capture();
    try {
      await expect(
        runDecryptQuarantineCli([context.responsePath], {
          stdin: Readable.from([]),
          stdout: stdout.stream,
          stderr: emptyKeyError.stream,
        }),
      ).resolves.toBe(1);
      expect(emptyKeyError.value()).toContain(
        "private key is required on stdin",
      );
    } finally {
      rmSync(context.directory, { recursive: true, force: true });
    }
  });
});
