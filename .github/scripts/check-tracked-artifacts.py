from __future__ import annotations

import os
import subprocess
import sys

CACHE_NAMES = {".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__"}


def main() -> int:
    try:
        result = subprocess.run(  # noqa: S603 - fixed Git index query
            ["git", "ls-files", "--full-name", "-z", "--", ":/"],  # noqa: S607
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        print("Unable to inspect tracked files with git ls-files.", file=sys.stderr)
        return 1

    artifacts = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = os.fsdecode(raw_path)
        if any(part in CACHE_NAMES or part.endswith(".egg-info") for part in path.split("/")):
            artifacts.append(path)

    if artifacts:
        print("Generated Python artifacts must not be tracked:", file=sys.stderr)
        for path in artifacts:
            print(f"  {path!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
