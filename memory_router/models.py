from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator

BankId = str


class PassthroughModel(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)


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
    async_: StrictBool | None = Field(default=None, alias="async")
    document_tags: list[str] | None = None

    @field_validator("async_", "document_tags", mode="before")
    @classmethod
    def reject_explicit_null(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("null is not allowed")
        return value


class RecallBody(PassthroughModel):
    query: str
    max_tokens: StrictInt | None = Field(default=None, gt=0)
    budget: Literal["low", "mid", "high"] | None = None
    types: list[str] | None = None
    tags: list[str] | None = None
    tags_match: str | None = None
    trace: StrictBool | None = None

    @field_validator("query")
    @classmethod
    def non_empty_query(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("empty")
        return value

    @field_validator("max_tokens", "budget", "tags_match", "trace", mode="before")
    @classmethod
    def reject_explicit_null(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("null is not allowed")
        return value


class RecallResult(PassthroughModel):
    id: str
    text: str


class RecallResponse(PassthroughModel):
    results: list[RecallResult]
    chunks: dict[str, Any] | None = None
    entities: dict[str, Any] | None = None
    source_facts: dict[str, Any] | None = None
    trace: dict[str, Any] | None = None


class WriterRule(PassthroughModel):
    role: str = Field(min_length=1)
    source: str = Field(min_length=1)
    write_bank: str = Field(min_length=1)
    read_banks: list[str]

    @field_validator("read_banks")
    @classmethod
    def non_empty_read_banks(cls, value: list[str]) -> list[str]:
        if any(not bank.strip() for bank in value):
            raise ValueError("bank id cannot be empty")
        return value

    @field_validator("write_bank")
    @classmethod
    def non_empty_write_bank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("bank id cannot be empty")
        return value


class RegistryDefaults(PassthroughModel):
    unknown_writer_action: Literal["review_queue"]
    suspicious_content_action: Literal["review_queue"]


class WriterRegistry(PassthroughModel):
    writers: dict[str, WriterRule]
    defaults: RegistryDefaults
