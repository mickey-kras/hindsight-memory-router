#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
python="${PYTHON:-python3}"
unset PYTHONPATH

# Download first so the rejection test cannot pass due to a registry outage.
"$python" -m pip download --disable-pip-version-check --require-hashes \
  --only-binary=:all: --dest "$work/backend" -r "$repo/build-requirements.txt"
"$python" -m venv "$work/builder"
builder="$work/builder/bin/python"
"$builder" -m pip install --disable-pip-version-check --no-index \
  --find-links "$work/backend" --require-hashes --only-binary=:all: \
  -r "$repo/build-requirements.txt"

"$python" - "$repo/build-requirements.txt" "$work/bad-hashes.txt" <<'PY'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text()
corrupted, count = re.subn(r"sha256:[0-9a-f]{64}", "sha256:" + "0" * 64, source)
assert count > 0, "builder lock must contain hashes"
Path(sys.argv[2]).write_text(corrupted)
PY
if "$builder" -m pip install --disable-pip-version-check --no-cache-dir \
  --force-reinstall --no-index --find-links "$work/backend" --require-hashes \
  --only-binary=:all: -r "$work/bad-hashes.txt" > "$work/rejection.log" 2>&1; then
  echo "build backend with incorrect hashes was accepted" >&2
  exit 1
fi
cat "$work/rejection.log"
grep -q 'DO NOT MATCH THE HASHES' "$work/rejection.log"

# Match the Docker builder inputs and keep generated build files out of the checkout.
mkdir "$work/source"
cp "$repo/pyproject.toml" "$repo/LICENSE" "$repo/THIRD_PARTY_NOTICES.md" "$work/source/"
cp -R "$repo/memory_router" "$repo/licenses" "$work/source/"
cd "$work/source"
PIP_NO_INDEX=1 "$builder" -m pip wheel --disable-pip-version-check --no-cache-dir \
  --no-index --no-build-isolation --no-deps --wheel-dir "$work/wheels" .

"$python" -m venv "$work/runtime"
"$work/runtime/bin/python" -m pip install --disable-pip-version-check \
  --require-hashes -r "$repo/requirements.txt"
"$work/runtime/bin/python" -m pip install --disable-pip-version-check \
  --no-index --no-deps "$work"/wheels/*.whl
cd "$work"
"$work/runtime/bin/python" -I "$repo/tests/integration/python-package.py" "$repo"
