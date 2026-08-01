import postgres, { type Sql } from "postgres";
import {
  SqlQuarantineRepository,
  type SqlDatabase,
} from "./sqlRepository.js";

export class PostgresQuarantineRepository extends SqlQuarantineRepository {
  constructor(connectionString: string) {
    const sql = postgres(connectionString, { max: 5 });
    super(new PostgresDatabase(sql, true));
  }
}

class PostgresDatabase implements SqlDatabase {
  readonly rowLockClause = " FOR UPDATE";

  constructor(
    private readonly sql: Sql,
    private readonly ownsConnection: boolean,
  ) {}

  async executeScript(script: string): Promise<void> {
    await this.sql.unsafe(script);
  }

  async run(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<void> {
    await this.sql.unsafe(toPostgresPlaceholders(statement), [...params]);
  }

  async get<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T | undefined> {
    const rows = await this.sql.unsafe<T[]>(
      toPostgresPlaceholders(statement),
      [...params],
    );
    return rows[0];
  }

  async all<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T[]> {
    return this.sql.unsafe<T[]>(toPostgresPlaceholders(statement), [...params]);
  }

  async transaction<T>(
    operation: (database: SqlDatabase) => Promise<T>,
  ): Promise<T> {
    return this.sql.begin(async (transaction) =>
      operation(new PostgresDatabase(transaction, false)),
    ) as Promise<T>;
  }

  async close(): Promise<void> {
    if (this.ownsConnection) await this.sql.end();
  }
}

export function toPostgresPlaceholders(statement: string): string {
  let index = 0;
  return statement.replace(/\?/g, () => `$${++index}`);
}
