from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from ..config import DEFAULT_DATABASE_URL
from ..quarantine.legacy_migration import migrate_legacy_quarantine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--queue")
    parser.add_argument("--objects")
    parser.add_argument("--database")
    try:
        args = parser.parse_args(argv)
        if not args.queue or not args.objects:
            raise ValueError(
                "usage: migrate-legacy-quarantine --queue <review.jsonl> --objects <directory> [--database <connection-string>]"
            )
        private_key = sys.stdin.read().strip()
        if not private_key:
            raise ValueError("private key is required on stdin")
        summary = asyncio.run(
            migrate_legacy_quarantine(
                args.queue,
                args.objects,
                args.database or os.getenv("QUARANTINE_DATABASE_URL", DEFAULT_DATABASE_URL),
                private_key,
            )
        )
        print(json.dumps(summary, separators=(",", ":")))
        return 0
    except (Exception, SystemExit) as exc:
        message = str(exc) if not isinstance(exc, SystemExit) else "invalid arguments"
        print(f"legacy quarantine migration failed: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
