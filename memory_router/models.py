from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

BankId = Literal["core", "main", "personal", "dev", "creative", "ops", "research"]


class PassthroughModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class MemoryItem(PassthroughModel):
    content: str
    context: str | None = None
    document_id: str | None = None
    metadata: dict[str, str] | None = None
    tags: list[str] | None = None
    timestamp: str | None = None
    update_mode: Literal["replace", "append"] | None = None

    @field_validator("content")
    @classmethod
    def non_empty_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("empty")
        return value


class RetainBody(PassthroughModel):
    items: list[MemoryItem] = Field(min_length=1)
    async_: bool | None = Field(default=None, alias="async")
    document_tags: list[str] | None = None


class RecallBody(PassthroughModel):
    query: str
    max_tokens: int | None = Field(default=None, gt=0)
    budget: Literal["low", "mid", "high"] | None = None
    types: list[str] | None = None
    tags: list[str] | None = None
    tags_match: str | None = None
    trace: bool | None = None

    @field_validator("query")
    @classmethod
    def non_empty_query(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("empty")
        return value


class RecallResult(PassthroughModel):
    id: str
    text: str
    type: str | None = None
    metadata: dict[str, str] | None = None


class RecallResponse(PassthroughModel):
    results: list[RecallResult]
    chunks: dict[str, Any] | None = None
    entities: dict[str, Any] | None = None
    source_facts: dict[str, Any] | None = None
    trace: dict[str, Any] | None = None


class WriterRule(PassthroughModel):
    role: str
    source: str
    write_bank: BankId
    read_banks: list[BankId]


class RegistryDefaults(PassthroughModel):
    unknown_writer_action: Literal["review_queue"]
    suspicious_content_action: Literal["review_queue"]


class WriterRegistry(PassthroughModel):
    writers: dict[str, WriterRule]
    defaults: RegistryDefaults
