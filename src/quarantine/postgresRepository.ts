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
      toPostgresPlaceholders(statement, params.length),
      postgresParameters(params),
    );
  }

  async get<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T | undefined> {
    const rows = await this.sql.unsafe<T[]>(
      toPostgresPlaceholders(statement, params.length),
      postgresParameters(params),
    );
    return rows[0];
  }

  async all<T extends Record<string, unknown>>(
    statement: string,
    params: readonly unknown[] = [],
  ): Promise<T[]> {
    const rows = await this.sql.unsafe<T[]>(
      toPostgresPlaceholders(statement, params.length),
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

export function toPostgresPlaceholders(
  statement: string,
  parameterCount: number,
): string {
  let output = "";
  let placeholderIndex = 0;
  let index = 0;

  while (index < statement.length) {
    const character = statement[index];
    const next = statement[index + 1];

    if (character === "'") {
      const end = quotedEnd(statement, index, "'");
      output += statement.slice(index, end);
      index = end;
      continue;
    }
    if (character === '"') {
      const end = quotedEnd(statement, index, '"');
      output += statement.slice(index, end);
      index = end;
      continue;
    }
    if (character === "-" && next === "-") {
      const end = lineCommentEnd(statement, index);
      output += statement.slice(index, end);
      index = end;
      continue;
    }
    if (character === "/" && next === "*") {
      const end = blockCommentEnd(statement, index);
      output += statement.slice(index, end);
      index = end;
      continue;
    }
    if (character === "$") {
      const delimiter = dollarQuoteDelimiter(statement, index);
      if (delimiter) {
        const end = dollarQuoteEnd(statement, index, delimiter);
        output += statement.slice(index, end);
        index = end;
        continue;
      }
    }
    if (character === "?") {
      placeholderIndex += 1;
      output += `$${placeholderIndex}`;
      index += 1;
      continue;
    }

    output += character;
    index += 1;
  }

  if (placeholderIndex !== parameterCount) {
    throw new Error(
      `SQL placeholder count ${placeholderIndex} does not match parameter count ${parameterCount}`,
    );
  }
  return output;
}

function quotedEnd(statement: string, start: number, quote: string): number {
  let index = start + 1;
  while (index < statement.length) {
    if (statement[index] === quote) {
      if (statement[index + 1] === quote) {
        index += 2;
        continue;
      }
      return index + 1;
    }
    index += 1;
  }
  throw new Error("unterminated SQL quoted value");
}

function lineCommentEnd(statement: string, start: number): number {
  const end = statement.indexOf("\n", start + 2);
  return end === -1 ? statement.length : end + 1;
}

function blockCommentEnd(statement: string, start: number): number {
  const end = statement.indexOf("*/", start + 2);
  if (end === -1) throw new Error("unterminated SQL block comment");
  return end + 2;
}

function dollarQuoteDelimiter(statement: string, start: number): string | null {
  const match = statement
    .slice(start)
    .match(/^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/);
  return match?.[0] ?? null;
}

function dollarQuoteEnd(
  statement: string,
  start: number,
  delimiter: string,
): number {
  const end = statement.indexOf(delimiter, start + delimiter.length);
  if (end === -1) throw new Error("unterminated SQL dollar-quoted value");
  return end + delimiter.length;
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
