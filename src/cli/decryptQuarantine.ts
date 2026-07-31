import { readFile } from "node:fs/promises";
import process from "node:process";
import {
  decryptQuarantineEnvelope,
  parseEncryptedQuarantineEnvelope,
  type DecryptedQuarantineObject,
  type EncryptedQuarantineEnvelope,
} from "../quarantine/envelopeCrypto.js";

type InputStream = AsyncIterable<string | Uint8Array>;
type OutputStream = { write(value: string): unknown };

export interface DecryptQuarantineCliIo {
  stdin: InputStream;
  stdout: OutputStream;
  stderr: OutputStream;
}

export function extractEnvelope(
  value: unknown,
): EncryptedQuarantineEnvelope {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const object = value as Record<string, unknown>;
    if ("encrypted" in object) {
      return parseEncryptedQuarantineEnvelope(object.encrypted);
    }
  }
  return parseEncryptedQuarantineEnvelope(value);
}

export async function readPrivateKey(stdin: InputStream): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const value = Buffer.concat(chunks).toString("utf8").trim();
  if (!value) throw new Error("private key is required on stdin");
  return value;
}

export async function decryptQuarantineResponseFile(
  responsePath: string,
  privateKey: string,
): Promise<DecryptedQuarantineObject> {
  const response = JSON.parse(await readFile(responsePath, "utf8")) as unknown;
  return decryptQuarantineEnvelope(extractEnvelope(response), privateKey);
}

export async function runDecryptQuarantineCli(
  args: string[],
  io: DecryptQuarantineCliIo,
): Promise<number> {
  try {
    const [responsePath] = args;
    if (!responsePath) {
      throw new Error(
        "usage: <private-key-command> | node dist/src/cli/decryptQuarantine.js <encrypted-response.json>",
      );
    }

    const privateKey = await readPrivateKey(io.stdin);
    const decrypted = await decryptQuarantineResponseFile(
      responsePath,
      privateKey,
    );
    io.stdout.write(`${JSON.stringify(decrypted, null, 2)}\n`);
    return 0;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "decryption failed";
    io.stderr.write(`decrypt-quarantine failed: ${message}\n`);
    return 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runDecryptQuarantineCli(process.argv.slice(2), {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  }).then((exitCode) => {
    process.exitCode = exitCode;
  });
}
