import {
  migrateLegacyQuarantine,
  type LegacyMigrationOptions,
  type LegacyMigrationSummary,
} from "../quarantine/legacyMigration.js";
import { DEFAULT_QUARANTINE_DATABASE_URL } from "../quarantine/repositoryFactory.js";

interface Arguments {
  queuePath: string;
  objectDirectory: string;
  databaseUrl: string;
}

interface CliContext {
  environment: NodeJS.ProcessEnv;
  readPrivateKey: () => Promise<string>;
  migrate: (options: LegacyMigrationOptions) => Promise<LegacyMigrationSummary>;
  stdout: Pick<NodeJS.WriteStream, "write">;
  stderr: Pick<NodeJS.WriteStream, "write">;
}

const DEFAULT_CONTEXT: CliContext = {
  environment: process.env,
  readPrivateKey: () => readStream(process.stdin),
  migrate: migrateLegacyQuarantine,
  stdout: process.stdout,
  stderr: process.stderr,
};

export async function runMigrateLegacyQuarantineCli(
  argv = process.argv.slice(2),
  context: Partial<CliContext> = {},
): Promise<number> {
  const runtime = { ...DEFAULT_CONTEXT, ...context };
  try {
    const args = parseArguments(argv, runtime.environment);
    const privateKey = (await runtime.readPrivateKey()).trim();
    if (!privateKey) throw new Error("private key is required on stdin");
    const summary = await runtime.migrate({
      queuePath: args.queuePath,
      objectDirectory: args.objectDirectory,
      databaseUrl: args.databaseUrl,
      privateKey,
    });
    runtime.stdout.write(`${JSON.stringify(summary)}\n`);
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : "migration failed";
    runtime.stderr.write(`legacy quarantine migration failed: ${message}\n`);
    return 1;
  }
}

export async function readStream(
  stream: NodeJS.ReadableStream,
): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  }
  return Buffer.concat(chunks).toString("utf8");
}

export function parseArguments(
  argv: string[],
  environment: NodeJS.ProcessEnv = process.env,
): Arguments {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || !value) usage();
    if (name !== "--queue" && name !== "--objects" && name !== "--database") {
      usage();
    }
    values.set(name, value);
  }

  const queuePath = values.get("--queue");
  const objectDirectory = values.get("--objects");
  if (!queuePath || !objectDirectory) usage();
  return {
    queuePath,
    objectDirectory,
    databaseUrl:
      values.get("--database") ??
      environment.QUARANTINE_DATABASE_URL ??
      DEFAULT_QUARANTINE_DATABASE_URL,
  };
}

function usage(): never {
  throw new Error(
    "usage: migrateLegacyQuarantine --queue <review.jsonl> --objects <directory> [--database <connection-string>]",
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runMigrateLegacyQuarantineCli().then((code) => {
    process.exitCode = code;
  });
}
