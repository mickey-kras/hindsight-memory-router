"""Load generated Unicode UTS #39 17.0.0 ASCII skeletons."""

from __future__ import annotations

import json
from importlib.resources import files

_loaded: object = json.loads(
    files("memory_router").joinpath("confusables_ascii.json").read_text(encoding="utf-8")
)
if not isinstance(_loaded, dict):
    raise RuntimeError("invalid confusables map")

ASCII_CONFUSABLES: dict[int, str] = {}
for codepoint, skeleton in _loaded.items():
    if not isinstance(codepoint, str) or not codepoint.isdigit() or not isinstance(skeleton, str):
        raise RuntimeError("invalid confusables map entry")
    parsed = int(codepoint)
    if parsed <= 127 or not skeleton or not skeleton.isascii() or not skeleton.isprintable():
        raise RuntimeError("invalid confusables map entry")
    ASCII_CONFUSABLES[parsed] = skeleton
