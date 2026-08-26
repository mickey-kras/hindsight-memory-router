"""Load generated Unicode UTS #39 17.0.0 ASCII skeletons."""

from __future__ import annotations

import json
from importlib.resources import files

ASCII_CONFUSABLES: dict[int, str] = {
    int(codepoint): skeleton
    for codepoint, skeleton in json.loads(
        files("memory_router").joinpath("confusables_ascii.json").read_text(encoding="utf-8")
    ).items()
}
