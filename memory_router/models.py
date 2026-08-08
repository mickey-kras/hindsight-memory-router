from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator

BankId = Literal["core", "main", "personal", "dev", "creative", "ops", "research"]


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
    async_: StrictBool = Field(default=False, alias="async")
    document_tags: list[str] = Field(default_factory=list)


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


class RecallResult(PassthroughModel):
    id: str
    text: str


class RecallResponse(PassthroughModel):
    results: list[RecallResult]
    chunks: dict[str, object] | None = None
    entities: dict[str, object] | None = None
    source_facts: dict[str, object] | None = None
    trace: dict[str, object] | None = None


class WriterRule(PassthroughModel):
    role: str = Field(min_length=1)
    source: str = Field(min_length=1)
    write_bank: BankId
    read_banks: list[BankId]


class RegistryDefaults(PassthroughModel):
    unknown_writer_action: Literal["review_queue"]
    suspicious_content_action: Literal["review_queue"]


class WriterRegistry(PassthroughModel):
    writers: dict[str, WriterRule]
    defaults: RegistryDefaults
