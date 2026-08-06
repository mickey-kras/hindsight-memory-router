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
  readonly stdin: InputStream;
  readonly stdout: OutputStream;
  readonly stderr: OutputStream;
}

export function extractEnvelope(value: unknown): EncryptedQuarantineEnvelope {
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
  args: readonly string[],
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
    const visible = escapedReviewValue(decrypted);
    if (visible.changed) {
      io.stderr.write(
        "warning: decrypted evidence contains invisible or control characters; stdout preserves the original evidence unchanged.\n",
      );
      io.stderr.write(
        `escaped visible representation:\n${JSON.stringify(visible.value, null, 2)}\n`,
      );
    }
    io.stdout.write(`${JSON.stringify(decrypted, null, 2)}\n`);
    return 0;
  } catch (error: unknown) {
    const message =
      error instanceof Error ? error.message : "decryption failed";
    io.stderr.write(`decrypt-quarantine failed: ${message}\n`);
    return 1;
  }
}

function escapedReviewValue(value: unknown): {
  changed: boolean;
  value: unknown;
} {
  let changed = false;
  const visit = (candidate: unknown): unknown => {
    if (typeof candidate === "string") {
      const escaped = escapeControls(candidate);
      if (escaped !== candidate) changed = true;
      return escaped;
    }
    if (Array.isArray(candidate)) return candidate.map(visit);
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(
        Object.entries(candidate).map(([key, child]) => {
          const escapedKey = escapeControls(key);
          if (escapedKey !== key) changed = true;
          return [escapedKey, visit(child)];
        }),
      );
    }
    return candidate;
  };
  const visible = visit(value);
  return { changed, value: visible };
}

function escapeControls(content: string): string {
  let escaped = "";
  for (const character of content) {
    const codePoint = character.codePointAt(0);
    if (!isInvisibleOrControl(codePoint)) {
      escaped += character;
    } else if (character === "\n") escaped += "\\n";
    else if (character === "\r") escaped += "\\r";
    else if (character === "\t") escaped += "\\t";
    else if (codePoint !== undefined) {
      escaped +=
        codePoint <= 0xffff
          ? `\\u${codePoint.toString(16).toUpperCase().padStart(4, "0")}`
          : `\\u{${codePoint.toString(16).toUpperCase()}}`;
    }
  }
  return escaped;
}

function isInvisibleOrControl(codePoint: number | undefined): boolean {
  return (
    codePoint !== undefined &&
    (codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      codePoint === 0x200b ||
      codePoint === 0x200c ||
      codePoint === 0x200d ||
      codePoint === 0x2060 ||
      (codePoint >= 0xfe00 && codePoint <= 0xfe0f) ||
      (codePoint >= 0xe0000 && codePoint <= 0xe007f))
  );
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
