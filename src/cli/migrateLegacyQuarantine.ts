import { readFile } from "node:fs/promises";
import { migrateLegacyQuarantine } from "../quarantine/legacyMigration.js";
import { DEFAULT_QUARANTINE_DATABASE_URL } from "../quarantine/repositoryFactory.js";

interface Arguments {
  queuePath: string;
  objectDirectory: string;
  databaseUrl: string;
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const args = parseArguments(argv);
  const privateKey = await readFile(0, "utf8");
  const summary = await migrateLegacyQuarantine({
    queuePath: args.queuePath,
    objectDirectory: args.objectDirectory,
    databaseUrl: args.databaseUrl,
    privateKey,
  });
  process.stdout.write(`${JSON.stringify(summary)}\n`);
}

function parseArguments(argv: string[]): Arguments {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || !value) usage();
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
      process.env.QUARANTINE_DATABASE_URL ??
      DEFAULT_QUARANTINE_DATABASE_URL,
  };
}

function usage(): never {
  throw new Error(
    "usage: migrateLegacyQuarantine --queue <review.jsonl> --objects <directory> [--database <connection-string>]",
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "migration failed";
    process.stderr.write(`legacy quarantine migration failed: ${message}\n`);
    process.exit(1);
  });
}
