from __future__ import annotations

from typing import Mapping


class HttpError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = dict(headers or {})


def safe_error_body(error: BaseException) -> tuple[int, object, Mapping[str, str]]:
    if isinstance(error, HttpError):
        return error.status, {"error": error.code, "message": error.message}, error.headers
    return 500, {"error": "internal error"}, {}
