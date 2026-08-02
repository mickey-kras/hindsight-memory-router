import postgres, {
  type ParameterOrJSON,
  type Sql,
  type TransactionSql,
} from "postgres";
import { SqlQuarantineRepository, type SqlDatabase } from "./sqlRepository.js";

const CAPACITY_LOCK_ID = 72_499_123;

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

  placeholder(index: number): string {
    return `$${index}`;
  }

  async acquireCapacityLock(): Promise<void> {
    if (this.root) {
      throw new Error("PostgreSQL capacity lock requires a transaction");
    }
    await this.sql.unsafe(
      `SELECT pg_advisory_xact_lock(${CAPACITY_LOCK_ID})`,
    );
  }

  async executeScript(script: string): Promise<void> {
    await this.sql.unsafe(script);
  }

  async run(statement: string, params: readonly unknown[] = []): Promise<void> {
    await this.sql.unsafe(statement, postgresParameters(params));
  }

  async get<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T | undefined> {
    const rows = await this.sql.unsafe<T[]>(
      statement,
      postgresParameters(params),
    );
    return rows[0];
  }

  async all<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T[]> {
    const rows = await this.sql.unsafe<T[]>(
      statement,
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
    const result = new TransactionResult<T>();
    await this.root.begin(async (transaction) => {
      result.set(await operation(new PostgresDatabase(transaction)));
    });
    return result.get();
  }

  async close(): Promise<void> {
    if (this.root) await this.root.end();
  }
}

class TransactionResult<T> {
  private completed = false;
  private value!: T;

  set(value: T): void {
    this.value = value;
    this.completed = true;
  }

  get(): T {
    if (!this.completed) {
      throw new Error("PostgreSQL transaction did not complete");
    }
    return this.value;
  }
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
