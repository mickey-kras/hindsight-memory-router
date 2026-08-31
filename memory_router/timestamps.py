from __future__ import annotations

from datetime import UTC, datetime


def iso_format(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso_now() -> str:
    return iso_format(datetime.now(UTC))
