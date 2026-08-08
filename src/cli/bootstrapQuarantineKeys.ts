import {
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import process from "node:process";
import { parseArgs } from "node:util";

export interface BootstrapQuarantineKeysOptions {
  publicKeyPath: string;
  privateKeyPath: string;
  modulusLength?: number;
}

export async function bootstrapQuarantineKeys(
  options: BootstrapQuarantineKeysOptions,
): Promise<"created" | "existing" | "repaired-public-key"> {
  const modulusLength = options.modulusLength ?? 4096;
  await mkdir(dirname(options.publicKeyPath), { recursive: true, mode: 0o755 });
  await mkdir(dirname(options.privateKeyPath), {
    recursive: true,
    mode: 0o700,
  });
  await chmod(dirname(options.privateKeyPath), 0o700);

  const [publicKey, privateKey] = await Promise.all([
    readOptional(options.publicKeyPath),
    readOptional(options.privateKeyPath),
  ]);

  if (privateKey !== undefined) {
    await chmod(options.privateKeyPath, 0o600);
    const derivedPublicKey = exportPublicKey(createPublicKey(privateKey));
    if (publicKey === undefined) {
      await writeFile(options.publicKeyPath, derivedPublicKey, {
        encoding: "utf8",
        mode: 0o644,
        flag: "wx",
      });
      return "repaired-public-key";
    }
    if (normalizePem(publicKey) !== normalizePem(derivedPublicKey)) {
      throw new Error("existing quarantine public/private keys do not match");
    }
    return "existing";
  }

  if (publicKey !== undefined) {
    throw new Error(
      "quarantine public key exists without its private key; refusing to replace review key material",
    );
  }

  const generated = generateKeyPairSync("rsa", {
    modulusLength,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  // Write the private key first. If initialization is interrupted before the
  // public key is written, the next run can safely derive and repair it.
  await writeFile(options.privateKeyPath, generated.privateKey, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  await chmod(options.privateKeyPath, 0o600);
  await writeFile(options.publicKeyPath, generated.publicKey, {
    encoding: "utf8",
    mode: 0o644,
    flag: "wx",
  });
  return "created";
}

async function readOptional(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw error;
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function exportPublicKey(key: KeyObject): string {
  return key.export({ type: "spki", format: "pem" }).toString();
}

function normalizePem(value: string): string {
  return value.trim().replaceAll("\r\n", "\n");
}

async function main(args: readonly string[]): Promise<number> {
  try {
    const parsed = parseArgs({
      args: [...args],
      options: {
        "public-key": { type: "string" },
        "private-key": { type: "string" },
      },
      strict: true,
      allowPositionals: false,
    });
    const publicKeyPath = parsed.values["public-key"];
    const privateKeyPath = parsed.values["private-key"];
    if (!publicKeyPath || !privateKeyPath) {
      throw new Error(
        "usage: bootstrapQuarantineKeys --public-key <path> --private-key <path>",
      );
    }
    const status = await bootstrapQuarantineKeys({
      publicKeyPath,
      privateKeyPath,
    });
    process.stdout.write(`quarantine key bootstrap: ${status}\n`);
    return 0;
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "key bootstrap failed";
    process.stderr.write(`quarantine key bootstrap failed: ${message}\n`);
    return 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((exitCode) => {
    process.exitCode = exitCode;
  });
}
