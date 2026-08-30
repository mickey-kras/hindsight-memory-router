from __future__ import annotations

import re
from pathlib import Path

ALLOWED_URL_LITERALS = {
    ("memory_router/config.py", "http://hindsight:8888"),
}
URL_PATTERN = re.compile(r"https?://[^\"'`\s\\]+")


def test_hardcoded_url_allowlist() -> None:
    found: set[tuple[str, str]] = set()
    for path in Path("memory_router").rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        found.update((path.as_posix(), match.group(0)) for match in URL_PATTERN.finditer(content))
    assert found == ALLOWED_URL_LITERALS
