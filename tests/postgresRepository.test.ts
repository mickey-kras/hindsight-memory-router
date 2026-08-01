import { beforeEach, describe, expect, it, vi } from "vitest";

const transactionSql = {
  unsafe: vi.fn(async () => []),
};
const rootSql = {
  unsafe: vi.fn(async () => []),
  begin: vi.fn(async (operation: (sql: typeof transactionSql) => unknown) =>
    operation(transactionSql),
  ),
  end: vi.fn(async () => undefined),
};
const postgres = vi.fn(() => rootSql);

vi.mock("postgres", () => ({ default: postgres }));

beforeEach(() => {
  postgres.mockClear();
  rootSql.unsafe.mockClear();
  rootSql.begin.mockClear();
  rootSql.end.mockClear();
  transactionSql.unsafe.mockClear();
});

describe("PostgresQuarantineRepository", () => {
  it("initializes, executes transactional writes, and closes the pool", async () => {
    const { PostgresQuarantineRepository } = await import(
      "../src/quarantine/postgresRepository.js"
    );
    const repository = new PostgresQuarantineRepository(
      "postgresql://router:test@database/router",
    );

    await repository.initialize();
    await repository.insert({
      quarantine_id: "q_20260731070000000Z_0123456789abcdef",
      created_at: "2026-07-31T07:00:00.000Z",
      updated_at: "2026-07-31T07:00:00.000Z",
      kind: "retain_request",
      reason: "unknown_writer",
      sha256: "a".repeat(64),
      encrypted: {
        version: 1,
        quarantine_id: "q_20260731070000000Z_0123456789abcdef",
        created_at: "2026-07-31T07:00:00.000Z",
        reason: "unknown_writer",
        sha256: "a".repeat(64),
        encryption: {
          algorithm: "AES-256-GCM",
          key_wrap: "RSA-OAEP-SHA256",
          wrapped_key_b64: "AAAA",
          iv_b64: "AAAAAAAAAAAAAAAA",
          tag_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
        },
        ciphertext_b64: "AAAA",
      },
      status: "pending",
      postpone_count: 0,
    });
    await repository.close();

    expect(postgres).toHaveBeenCalledWith(
      "postgresql://router:test@database/router",
      { max: 5 },
    );
    expect(rootSql.unsafe).toHaveBeenCalledOnce();
    expect(rootSql.begin).toHaveBeenCalledOnce();
    expect(transactionSql.unsafe).toHaveBeenCalledTimes(2);
    expect(transactionSql.unsafe.mock.calls[0]?.[0]).toContain("$1");
    expect(rootSql.end).toHaveBeenCalledOnce();
  });
});
