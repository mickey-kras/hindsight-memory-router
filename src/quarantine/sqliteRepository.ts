import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import {
  SqlQuarantineRepository,
  type SqlDatabase,
} from "./sqlRepository.js";

export class SqliteQuarantineRepository extends SqlQuarantineRepository {
  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    super(new SqliteDatabase(new DatabaseSync(path)));
  }
}

class SqliteDatabase implements SqlDatabase {
  readonly rowLockClause = "";

  constructor(private readonly database: DatabaseSync) {}

  async executeScript(script: string): Promise<void> {
    this.database.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    this.database.exec(script);
  }

  async run(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<void> {
    this.database
      .prepare(statement)
      .run(...(params as readonly SQLInputValue[]));
  }

  async get<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T | undefined> {
    return this.database
      .prepare(statement)
      .get(...(params as readonly SQLInputValue[])) as T | undefined;
  }

  async all<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T[]> {
    return this.database
      .prepare(statement)
      .all(...(params as readonly SQLInputValue[])) as T[];
  }

  async transaction<T>(
    operation: (database: SqlDatabase) => Promise<T>,
  ): Promise<T> {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const result = await operation(this);
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  async close(): Promise<void> {
    this.database.close();
  }
}
