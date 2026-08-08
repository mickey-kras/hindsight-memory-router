from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from memory_router.db import DEFAULT_DATABASE_URL
from memory_router.legacy_migration import migrate_legacy_quarantine


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import legacy filesystem quarantine state.")
    parser.add_argument("--queue", required=True)
    parser.add_argument("--objects", required=True)
    parser.add_argument("--database", default=os.environ.get("QUARANTINE_DATABASE_URL", DEFAULT_DATABASE_URL))
    args = parser.parse_args(argv)
    try:
        key_text = sys.stdin.read().strip()
        if not key_text:
            raise ValueError("decryption key is required on stdin")
        summary = asyncio.run(
            migrate_legacy_quarantine(args.queue, args.objects, args.database, key_text)
        )
        print(json.dumps(summary, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(f"legacy quarantine migration failed: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
