from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: check_coverage.py <coverage.json> <min-lines> <min-branches>")
    path, min_lines, min_branches = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    totals = data["totals"]
    lines = float(totals["percent_covered"])
    total_branches = int(totals.get("num_branches", 0))
    covered_branches = int(totals.get("covered_branches", 0))
    branches = 100.0 if total_branches == 0 else covered_branches * 100.0 / total_branches
    print(f"coverage: lines={lines:.2f}% branches={branches:.2f}%")
    if lines < min_lines or branches < min_branches:
        print(
            f"coverage threshold failed: require lines>={min_lines:.2f}% branches>={min_branches:.2f}%",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
