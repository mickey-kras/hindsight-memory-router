from __future__ import annotations

import sys
from pathlib import Path

HEADER = "<!-- Generated from ../workspace.dsl by make architecture. Do not edit. -->\n"


def main() -> int:
    directory = Path(sys.argv[1])
    for diagram in sorted(directory.glob("*.mmd")):
        markdown = diagram.with_suffix(".md")
        source = diagram.read_text(encoding="utf-8").rstrip() + "\n"
        markdown.write_text(f"{HEADER}\n```mermaid\n{source}```\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
