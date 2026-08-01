import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { SqlQuarantineRepository, type SqlDatabase } from "./sqlRepository.js";

export class SqliteQuarantineRepository extends SqlQuarantineRepository {
  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    super(new SqliteDatabase(new DatabaseSync(path)));
  }
}

class SqliteDatabase implements SqlDatabase {
  readonly rowLockClause = "";
  private accessTail: Promise<void> = Promise.resolve();

  constructor(private readonly database: DatabaseSync) {}

  executeScript(script: string): Promise<void> {
    return this.enqueue(() => {
      this.database.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
      this.database.exec(script);
    });
  }

  run(statement: string, params: readonly unknown[] = []): Promise<void> {
    return this.enqueue(() => run(this.database, statement, params));
  }

  get<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T | undefined> {
    return this.enqueue(() => get<T>(this.database, statement, params));
  }

  all<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T[]> {
    return this.enqueue(() => all<T>(this.database, statement, params));
  }

  transaction<T>(
    operation: (database: SqlDatabase) => Promise<T>,
  ): Promise<T> {
    return this.enqueue(async () => {
      this.database.exec("BEGIN IMMEDIATE");
      const transaction = new SqliteTransactionDatabase(this.database);
      try {
        const result = await operation(transaction);
        this.database.exec("COMMIT");
        return result;
      } catch (error) {
        this.database.exec("ROLLBACK");
        throw error;
      }
    });
  }

  close(): Promise<void> {
    return this.enqueue(() => this.database.close());
  }

  private enqueue<T>(operation: () => T | Promise<T>): Promise<T> {
    const current = this.accessTail.then(operation);
    this.accessTail = current.then(
      () => undefined,
      () => undefined,
    );
    return current;
  }
}

class SqliteTransactionDatabase implements SqlDatabase {
  readonly rowLockClause = "";

  constructor(private readonly database: DatabaseSync) {}

  async executeScript(script: string): Promise<void> {
    this.database.exec(script);
  }

  async run(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<void> {
    run(this.database, statement, params);
  }

  async get<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T | undefined> {
    return get<T>(this.database, statement, params);
  }

  async all<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T[]> {
    return all<T>(this.database, statement, params);
  }

  async transaction<T>(
    _operation: (database: SqlDatabase) => Promise<T>,
  ): Promise<T> {
    throw new Error("nested SQLite transactions are not supported");
  }

  async close(): Promise<void> {
    throw new Error("transaction-scoped SQLite connection cannot be closed");
  }
}

function run(
  database: DatabaseSync,
  statement: string,
  params: readonly unknown[],
): void {
  database.prepare(statement).run(...(params as readonly SQLInputValue[]));
}

function get<T extends Record<string, unknown>>(
  database: DatabaseSync,
  statement: string,
  params: readonly unknown[],
): T | undefined {
  return database
    .prepare(statement)
    .get(...(params as readonly SQLInputValue[])) as T | undefined;
}

function all<T extends Record<string, unknown>>(
  database: DatabaseSync,
  statement: string,
  params: readonly unknown[],
): T[] {
  return database
    .prepare(statement)
    .all(...(params as readonly SQLInputValue[])) as T[];
}
