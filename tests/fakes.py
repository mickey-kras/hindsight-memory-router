from __future__ import annotations

from collections.abc import Sequence

from memory_router.db import PostgresTx
from memory_router.models import WriterRegistry

QID = "q_item_0123456789abcdef"


class TxContext[T]:
    def __init__(self, tx: T) -> None:
        self.tx = tx

    async def __aenter__(self) -> T:
        return self.tx

    async def __aexit__(self, *args: object) -> None:
        return None


class FakeDatabase[T]:
    def __init__(self, tx: T) -> None:
        self.tx = tx

    def transaction(self, **kwargs: object) -> TxContext[T]:
        return TxContext(self.tx)


class FakeReviewTx:
    def __init__(self, row: dict[str, object], *, dialect: str = "sqlite") -> None:
        self.row: dict[str, object] | None = dict(row)
        self.dialect = dialect
        self.executed: list[tuple[str, object]] = []

    def select_for_update(self, sql: str) -> str:
        return sql + " FOR UPDATE" if self.dialect == "postgres" else sql

    async def fetchone(
        self, sql: str, params: Sequence[object] | None = None
    ) -> dict[str, object] | None:
        return None if self.row is None else dict(self.row)

    async def execute(self, sql: str, params: Sequence[object] | None = None) -> None:
        self.executed.append((sql, params))
        values = tuple(params or ())
        if sql.startswith("UPDATE quarantine_items SET status='postponed'") and self.row:
            self.row["status"] = "postponed"
            self.row["updated_at"] = values[0]
        elif sql.startswith("UPDATE quarantine_items SET status=?") and self.row:
            self.row["status"] = values[0]
            self.row["updated_at"] = values[1]
        elif sql.startswith("DELETE FROM quarantine_items"):
            self.row = None


def registry() -> WriterRegistry:
    return WriterRegistry.model_validate(
        {
            "writers": {
                "main": {
                    "role": "default",
                    "source": "application",
                    "write_bank": "main",
                    "read_banks": ["main"],
                }
            },
            "defaults": {
                "unknown_writer_action": "review_queue",
                "suspicious_content_action": "review_queue",
            },
        }
    )


class FakeHindsight:
    def __init__(
        self,
        recall_results: list[dict[str, object]] | None = None,
        *,
        response: dict[str, object] | None = None,
    ) -> None:
        self.response = response
        self.retain_calls: list[tuple[str, dict[str, object]]] = []
        self.recall_calls: list[tuple[str, dict[str, object]]] = []
        self.recall_results = recall_results or []
        self.recall_error: Exception | None = None

    async def retain(self, bank: str, body: dict[str, object]) -> dict[str, bool]:
        self.retain_calls.append((bank, body))
        return {"ok": True}

    async def recall(self, bank: str, body: dict[str, object]) -> dict[str, object]:
        self.recall_calls.append((bank, body))
        if self.recall_error:
            raise self.recall_error
        return self.response if self.response is not None else {"results": self.recall_results}


class FakeLimits:
    def __init__(self) -> None:
        self.retain: list[str] = []
        self.recall: list[str] = []

    async def consume_retain(self, writer: str) -> None:
        self.retain.append(writer)

    async def consume_recall(self, writer: str) -> None:
        self.recall.append(writer)


class FakeRepository:
    def __init__(self, state: dict[str, object] | None = None) -> None:
        self.state = state
        self.states: dict[tuple[str, str], dict[str, object]] = {}

    async def find_memory_state(self, bank: str, memory_id: str) -> dict[str, object] | None:
        return self.states.get((bank, memory_id), self.state)


class FakeStore:
    def __init__(
        self,
        errors: list[Exception | None] | None = None,
        *,
        error: Exception | None = None,
        quarantine_id: str = QID,
    ) -> None:
        self.errors = list(errors or [])
        self.error = error
        self.quarantine_id = quarantine_id
        self.items: list[dict[str, object]] = []

    async def put(self, item: dict[str, object]) -> dict[str, str]:
        self.items.append(item)
        error = self.errors.pop(0) if self.errors else self.error
        if error is not None:
            raise error
        return {"quarantine_id": self.quarantine_id, "sha256": "a" * 64}


class FakeRateLimitTx(PostgresTx):
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []
        self.state_reads = 0

    async def execute(self, sql: str, params: object = None) -> None:
        self.executed.append((sql, params))

    async def fetchone(self, sql: str, params: object = None) -> dict[str, int] | None:
        self.executed.append((sql, params))
        if "clock_timestamp" in sql:
            return {"now_ms": 100}
        if "SELECT max_window_ms" in sql:
            self.state_reads += 1
            return {"max_window_ms": 60_000}
        if "COUNT(*)" in sql:
            return {"count": 0}
        return None
