from __future__ import annotations

from dataclasses import dataclass, field
from typing import NoReturn


@dataclass(slots=True)
class HttpError(Exception):
    status: int
    code: str
    message: str
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)

    def body(self) -> dict[str, str]:
        return {"error": self.code, "message": self.message}


def rewrap_rate_limited(
    exc: HttpError, *, code: str, message: str, headers: dict[str, str] | None = None
) -> NoReturn:
    if exc.status == 429:
        raise HttpError(429, code, message, headers if headers is not None else {}) from exc
    raise exc
