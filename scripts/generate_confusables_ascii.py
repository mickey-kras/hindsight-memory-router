#!/usr/bin/env python3
"""Generate the vendored printable-ASCII UTS #39 skeleton map."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from functools import cache
from pathlib import Path

UNICODE_VERSION = "17.0.0"
SOURCE_URL = f"https://www.unicode.org/Public/{UNICODE_VERSION}/security/confusables.txt"
SOURCE_SHA256 = "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a"
OUTPUT = Path(__file__).resolve().parents[1] / "memory_router" / "confusables_ascii.json"
_ENTRY = re.compile(r"^([0-9A-F]+)\s*;\s*([0-9A-F ]+)\s*;")


def main() -> None:
    with urllib.request.urlopen(SOURCE_URL, timeout=30) as response:  # noqa: S310
        source_bytes = response.read()
    if hashlib.sha256(source_bytes).hexdigest() != SOURCE_SHA256:
        raise RuntimeError("unexpected Unicode confusables SHA-256")
    source = source_bytes.decode("utf-8")
    if f"# Version: {UNICODE_VERSION}" not in source:
        raise RuntimeError("unexpected Unicode confusables version")

    raw: dict[int, tuple[int, ...]] = {}
    for line in source.splitlines():
        if match := _ENTRY.match(line):
            raw[int(match.group(1), 16)] = tuple(
                int(codepoint, 16) for codepoint in match.group(2).split()
            )

    resolving: set[int] = set()

    @cache
    def skeleton(codepoint: int) -> str | None:
        if codepoint < 128:
            char = chr(codepoint)
            return char if char.isprintable() else None
        target = raw.get(codepoint)
        if target is None:
            return None
        if codepoint in resolving:
            raise RuntimeError(f"cycle in confusable skeleton for U+{codepoint:04X}")
        resolving.add(codepoint)
        try:
            parts = tuple(skeleton(part) for part in target)
            return "".join(part for part in parts if part is not None) if all(parts) else None
        finally:
            resolving.remove(codepoint)

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
