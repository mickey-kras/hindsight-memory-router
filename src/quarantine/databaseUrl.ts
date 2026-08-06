export const DEFAULT_QUARANTINE_DATABASE_URL = "sqlite:./data/quarantine.db";

export function isPostgresConnectionString(connectionString: string): boolean {
  return (
    connectionString.startsWith("postgres://") ||
    connectionString.startsWith("postgresql://")
  );
}
