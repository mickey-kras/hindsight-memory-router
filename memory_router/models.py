from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

BankId = Literal["core", "main", "personal", "dev", "creative", "ops", "research"]
BANK_IDS: tuple[str, ...] = ("core", "main", "personal", "dev", "creative", "ops", "research")
ReviewReason = Literal[
    "unknown_writer",
    "suspicious_content",
    "suspicious_query",
    "recalled_suspicious_memory",
    "denied_endpoint",
    "auth_failed",
]
REVIEW_REASONS: tuple[str, ...] = (
    "unknown_writer",
    "suspicious_content",
    "suspicious_query",
    "recalled_suspicious_memory",
    "denied_endpoint",
    "auth_failed",
)
QuarantineKind = Literal["retain_request", "recall_request", "recalled_memory", "security_event"]
QuarantineStatus = Literal[
    "pending", "postponed", "review_in_progress", "reviewed_allowed", "reviewed_blocked"
]


class MemoryItem(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)

    content: str
    context: str | None = None
    document_id: str | None = None
    metadata: dict[str, str] | None = None
    tags: list[str] | None = None
    timestamp: str | None = None
    update_mode: Literal["replace", "append"] | None = None

    @field_validator("content")
    @classmethod
    def content_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("empty")
        return value


class RetainBody(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True, strict=True)
    items: list[MemoryItem]
    async_: bool | None = Field(default=None, alias="async")
    document_tags: list[str] | None = None

    def model_dump_wire(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, exclude_none=True)


class RecallBody(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    query: str
    max_tokens: int | None = None
    budget: Literal["low", "mid", "high"] | None = None
    types: list[str] | None = None
    tags: list[str] | None = None
    tags_match: str | None = None
    trace: bool | None = None

    @field_validator("query")
    @classmethod
    def query_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("empty")
        return value

    @field_validator("max_tokens")
    @classmethod
    def max_tokens_positive(cls, value: int | None) -> int | None:
        if value is not None and (isinstance(value, bool) or value <= 0):
            raise ValueError("positive")
        return value


class RecallResult(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    id: str
    text: str


class RecallResponse(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    results: list[RecallResult]
    chunks: dict[str, Any] | None = None
    entities: dict[str, Any] | None = None
    source_facts: dict[str, Any] | None = None
    trace: dict[str, Any] | None = None


class WriterRule(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    role: str
    source: str
    write_bank: BankId
    read_banks: list[BankId]

    @field_validator("role", "source")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("empty")
        return value


class RegistryDefaults(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    unknown_writer_action: Literal["review_queue"]
    suspicious_content_action: Literal["review_queue"]


class WriterRegistry(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    writers: dict[str, WriterRule]
    defaults: RegistryDefaults
