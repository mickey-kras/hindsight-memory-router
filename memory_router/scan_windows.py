from __future__ import annotations

from collections.abc import Iterator, Sequence
from itertools import combinations


def bounded_skip_fragments(values: Sequence[str], *, max_skips: int = 2) -> Iterator[list[str]]:
    """Yield nearby fragment groups with one or two interleaved values omitted."""
    for start, first in enumerate(values):
        for end in range(start + 2, min(len(values), start + max_skips + 2)):
            middle = values[start + 1 : end]
            for skipped in range(1, min(max_skips, len(middle)) + 1):
                for omitted in combinations(range(len(middle)), skipped):
                    fragments = [
                        first,
                        *(value for index, value in enumerate(middle) if index not in omitted),
                        values[end],
                    ]
                    yield fragments
                    if end + 1 < len(values):
                        yield [*fragments, values[end + 1]]
