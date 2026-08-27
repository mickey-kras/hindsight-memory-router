#!/usr/bin/env python3
"""Generate the vendored printable-ASCII UTS #39 skeleton map."""

from __future__ import annotations

import json
import re
import urllib.request
from functools import cache
from pathlib import Path

UNICODE_VERSION = "17.0.0"
SOURCE_URL = f"https://www.unicode.org/Public/{UNICODE_VERSION}/security/confusables.txt"
OUTPUT = Path(__file__).resolve().parents[1] / "memory_router" / "confusables_ascii.json"
_ENTRY = re.compile(r"^([0-9A-F]+)\s*;\s*([0-9A-F ]+)\s*;")


def main() -> None:
    with urllib.request.urlopen(SOURCE_URL, timeout=30) as response:  # noqa: S310
        source = response.read().decode("utf-8")
    if f"# Version: {UNICODE_VERSION}" not in source:
        raise RuntimeError("unexpected Unicode confusables version")

    raw: dict[int, tuple[int, ...]] = {}
    for line in source.splitlines():
        if match := _ENTRY.match(line):
            raw[int(match.group(1), 16)] = tuple(
                int(codepoint, 16) for codepoint in match.group(2).split()
            )

    @cache
    def skeleton(codepoint: int) -> str | None:
        if codepoint < 128:
            char = chr(codepoint)
            return char if char.isprintable() else None
        target = raw.get(codepoint)
        if target is None:
            return None
        parts = tuple(skeleton(part) for part in target)
        return "".join(part for part in parts if part is not None) if all(parts) else None

    generated = {
        codepoint: resolved
        for codepoint in sorted(raw)
        if codepoint > 127 and (resolved := skeleton(codepoint)) is not None
    }
    if not all(value.isascii() and value.isprintable() for value in generated.values()):
        raise RuntimeError("generated map contains a non-printable or non-ASCII skeleton")
    OUTPUT.write_text(
        json.dumps(generated, ensure_ascii=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
