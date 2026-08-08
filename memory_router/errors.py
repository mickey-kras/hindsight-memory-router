from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class HttpError(Exception):
    status: int
    code: str
    message: str
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def body(self) -> dict[str, str]:
        return {"error": self.code, "message": self.message}
