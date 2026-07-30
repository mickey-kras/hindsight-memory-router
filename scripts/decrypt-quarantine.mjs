#!/usr/bin/env node

import {
  constants,
  createDecipheriv,
  createHash,
  privateDecrypt,
} from "node:crypto";
import { readFile } from "node:fs/promises";

const [responsePath] = process.argv.slice(2);
if (!responsePath) {
  process.stderr.write(
    "usage: op read <private-key-reference> | node scripts/decrypt-quarantine.mjs <encrypted-response.json>\n",
  );
  process.exit(2);
}

const privateKeyInput = await readStdin();
const privateKey = decodePrivateKey(privateKeyInput);
const response = JSON.parse(await readFile(responsePath, "utf8"));
const envelope = response.encrypted ?? response;

validateEnvelope(envelope);

const key = privateDecrypt(
  {
    key: privateKey,
    oaepHash: "sha256",
    padding: constants.RSA_PKCS1_OAEP_PADDING,
  },
  Buffer.from(envelope.encryption.wrapped_key_b64, "base64"),
);
const tag = Buffer.from(envelope.encryption.tag_b64, "base64");
if (tag.length !== 16) throw new Error("invalid AES-GCM authentication tag");

const decipher = createDecipheriv(
  "aes-256-gcm",
  key,
  Buffer.from(envelope.encryption.iv_b64, "base64"),
  { authTagLength: 16 },
);
decipher.setAuthTag(tag);
const plaintext = Buffer.concat([
  decipher.update(Buffer.from(envelope.ciphertext_b64, "base64")),
  decipher.final(),
]).toString("utf8");

const digest = createHash("sha256").update(plaintext).digest("hex");
if (digest !== envelope.sha256) {
  throw new Error("quarantine object digest mismatch");
}

process.stdout.write(`${JSON.stringify(JSON.parse(plaintext), null, 2)}\n`);

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  const value = Buffer.concat(chunks).toString("utf8").trim();
  if (!value) throw new Error("private key is required on stdin");
  return value;
}

function decodePrivateKey(value) {
  if (value.includes("BEGIN PRIVATE KEY")) return value.replace(/\\n/g, "\n");
  const decoded = Buffer.from(value, "base64").toString("utf8");
  if (!decoded.includes("BEGIN PRIVATE KEY")) {
    throw new Error("private key must be PEM or base64-encoded PEM");
  }
  return decoded;
}

function validateEnvelope(envelope) {
  if (
    envelope?.version !== 1 ||
    envelope?.encryption?.algorithm !== "AES-256-GCM" ||
    envelope?.encryption?.key_wrap !== "RSA-OAEP-SHA256" ||
    typeof envelope?.sha256 !== "string" ||
    typeof envelope?.encryption?.wrapped_key_b64 !== "string" ||
    typeof envelope?.encryption?.iv_b64 !== "string" ||
    typeof envelope?.encryption?.tag_b64 !== "string" ||
    typeof envelope?.ciphertext_b64 !== "string"
  ) {
    throw new Error("invalid encrypted quarantine envelope");
  }
}
