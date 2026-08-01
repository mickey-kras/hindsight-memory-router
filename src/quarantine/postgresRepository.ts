import postgres, {
  type ParameterOrJSON,
  type Sql,
  type TransactionSql,
} from "postgres";
import { SqlQuarantineRepository, type SqlDatabase } from "./sqlRepository.js";

export class PostgresQuarantineRepository extends SqlQuarantineRepository {
  constructor(connectionString: string) {
    const sql = postgres(connectionString, { max: 5 });
    super(new PostgresDatabase(sql, sql));
  }
}

class PostgresDatabase implements SqlDatabase {
  readonly rowLockClause = " FOR UPDATE";

  constructor(
    private readonly sql: Sql | TransactionSql,
    private readonly root?: Sql,
  ) {}

  async executeScript(script: string): Promise<void> {
    await this.sql.unsafe(script);
  }

  async run(statement: string, params: readonly unknown[] = []): Promise<void> {
    await this.sql.unsafe(
      toPostgresPlaceholders(statement),
      postgresParameters(params),
    );
  }

  async get<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T | undefined> {
    const rows = await this.sql.unsafe<T[]>(
      toPostgresPlaceholders(statement),
      postgresParameters(params),
    );
    return rows[0];
  }

  async all<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T[]> {
    const rows = await this.sql.unsafe<T[]>(
      toPostgresPlaceholders(statement),
      postgresParameters(params),
    );
    return [...rows];
  }

  async transaction<T>(
    operation: (database: SqlDatabase) => Promise<T>,
  ): Promise<T> {
    if (!this.root) {
      throw new Error("nested PostgreSQL transactions are not supported");
    }
    return this.root.begin((transaction) =>
      operation(new PostgresDatabase(transaction)),
    );
  }

  async close(): Promise<void> {
    if (this.root) await this.root.end();
  }
}

export function toPostgresPlaceholders(statement: string): string {
  let index = 0;
  return statement.replace(/\?/g, () => `$${++index}`);
}

function postgresParameters(
  params: readonly unknown[],
): ParameterOrJSON<never>[] {
  return params.map((value) => {
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean" ||
      value instanceof Date ||
      value instanceof Uint8Array
    ) {
      return value;
    }
    throw new Error("unsupported PostgreSQL parameter type");
  });
}
