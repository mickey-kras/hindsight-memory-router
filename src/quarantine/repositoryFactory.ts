import { resolve } from "node:path";
import type { QuarantineRepository } from "./repository.js";
import { PostgresQuarantineRepository } from "./postgresRepository.js";
import { SqliteQuarantineRepository } from "./sqliteRepository.js";

export const DEFAULT_QUARANTINE_DATABASE_URL =
  "sqlite:/volume1/reports/hindsight-quarantine/quarantine.db";

export async function createQuarantineRepository(
  connectionString = DEFAULT_QUARANTINE_DATABASE_URL,
): Promise<QuarantineRepository> {
  const repository = repositoryFromConnectionString(connectionString);
  await repository.initialize();
  return repository;
}

export function repositoryFromConnectionString(
  connectionString: string,
): QuarantineRepository {
  if (
    connectionString.startsWith("postgres://") ||
    connectionString.startsWith("postgresql://")
  ) {
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
