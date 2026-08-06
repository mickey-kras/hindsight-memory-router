import {
  accessSync,
  closeSync,
  constants,
  existsSync,
  openSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import type { QuarantineRepository } from "./repository.js";
import { PostgresQuarantineRepository } from "./postgresRepository.js";
import { SqliteQuarantineRepository } from "./sqliteRepository.js";

export const DEFAULT_QUARANTINE_DATABASE_URL = "sqlite:./data/quarantine.db";

export function isPostgresConnectionString(connectionString: string): boolean {
  return (
    connectionString.startsWith("postgres://") ||
    connectionString.startsWith("postgresql://")
  );
}

export async function createQuarantineRepository(
  connectionString = DEFAULT_QUARANTINE_DATABASE_URL,
): Promise<QuarantineRepository> {
  const repository = repositoryFromConnectionString(connectionString);
  await repository.initialize();
  return repository;
}

// Startup storage validation fails fast with a clear error instead of
// surfacing the first write failure mid-request. For SQLite the database
// file and its directory (WAL sidecar files) must be writable; PostgreSQL
// writability is enforced by schema initialization when the repository
// connects, so a ping is enough there.
export async function validateQuarantineStorage(
  repository: QuarantineRepository,
  connectionString: string,
): Promise<void> {
  try {
    await repository.ping();
  } catch (error) {
    throw new Error(
      `quarantine storage is unreachable: ${errorReason(error)}`,
      {
        cause: error,
      },
    );
  }
  assertSqliteStorageWritable(connectionString);
}

export function assertSqliteStorageWritable(connectionString: string): void {
  if (!connectionString.startsWith("sqlite:")) return;
  const path = sqlitePath(connectionString);
  if (path === ":memory:") return;
  try {
    // The directory must be writable so SQLite can create the database and
    // its WAL sidecar files.
    accessSync(dirname(path), constants.W_OK);
    if (existsSync(path)) {
      // Open read-write without truncating to prove the file itself is
      // writable; a read-only file or mount fails here.
      closeSync(openSync(path, "r+"));
    }
  } catch (error) {
    throw new Error(
      `quarantine storage at ${path} is not writable: ${errorReason(error)}`,
      { cause: error },
    );
  }
}

function errorReason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function repositoryFromConnectionString(
  connectionString: string,
): QuarantineRepository {
  if (isPostgresConnectionString(connectionString)) {
    return new PostgresQuarantineRepository(connectionString);
  }
  if (connectionString.startsWith("sqlite:")) {
    return new SqliteQuarantineRepository(sqlitePath(connectionString));
  }
  throw new Error(
    "QUARANTINE_DATABASE_URL must use sqlite:, postgres://, or postgresql://",
  );
}

export function sqlitePath(connectionString: string): string {
  const value = connectionString.slice("sqlite:".length);
  if (!value) throw new Error("SQLite database path is required");
  if (value === ":memory:") return value;
  if (value.startsWith("///")) return `/${value.slice(3)}`;
  if (value.startsWith("/")) return value;
  return resolve(value);
}
