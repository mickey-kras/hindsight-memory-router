import { readFile } from "node:fs/promises";
import process from "node:process";
import {
  decryptQuarantineEnvelope,
  parseEncryptedQuarantineEnvelope,
} from "../quarantine/envelopeCrypto.js";

async function main(): Promise<void> {
  const [responsePath] = process.argv.slice(2);
  if (!responsePath) {
    throw new Error(
      "usage: <private-key-command> | node dist/src/cli/decryptQuarantine.js <encrypted-response.json>",
    );
  }

  const privateKey = await readStdin();
  const response = JSON.parse(await readFile(responsePath, "utf8")) as unknown;
  const envelope = extractEnvelope(response);
  const decrypted = decryptQuarantineEnvelope(envelope, privateKey);
  process.stdout.write(`${JSON.stringify(decrypted, null, 2)}\n`);
}

function extractEnvelope(value: unknown): unknown {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const object = value as Record<string, unknown>;
    if ("encrypted" in object) {
      return parseEncryptedQuarantineEnvelope(object.encrypted);
    }
  }
  return parseEncryptedQuarantineEnvelope(value);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const value = Buffer.concat(chunks).toString("utf8").trim();
  if (!value) throw new Error("private key is required on stdin");
  return value;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "decryption failed";
  process.stderr.write(`decrypt-quarantine failed: ${message}\n`);
  process.exitCode = 1;
});
