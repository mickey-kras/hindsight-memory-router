from __future__ import annotations

import pytest

from memory_router import security
from memory_router.security_provenance import ReviewedText


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, ["0"]),
        (1.0, ["1.0", "1"]),
        (-0.0, ["-0.0", "0"]),
        (1.25, ["1.25"]),
        (1e20, ["1e+20", "100000000000000000000"]),
        (float("inf"), ["inf"]),
        (float("-inf"), ["-inf"]),
        (float("nan"), ["nan"]),
        (True, []),
        (None, []),
    ],
)
def test_numeric_walk_preserves_spellings_and_paths(value: object, expected: list[str]) -> None:
    fields = list(security._walk_strings({"nested": [value]}, "root", include_numbers=True))
    assert fields == [("root.nested", "nested", True)] + [
        ("root.nested.0", spelling, False) for spelling in expected
    ]
    assert list(security._walk_strings(value, "root")) == []


@pytest.mark.parametrize("is_key", [False, True])
@pytest.mark.parametrize("origin", [0, 7, (7, 7, 7, 7, 7)])
def test_direct_canonicalization_preserves_value_origin_but_never_key_approval(
    is_key: bool, origin: int | tuple[int, ...]
) -> None:
    raw = ReviewedText("hello", origin)
    output: list[tuple[str, str, bool]] = []
    security._scan_fields(
        [("field", raw, is_key)],
        operation="recall",
        canonical_output=output,
        reviewed_fields=frozenset({"field"}),
    )
    assert len(output) == 1
    canonical = output[0][1]
    assert isinstance(canonical, ReviewedText)
    assert canonical.trusted == (0 if is_key else origin)


@pytest.mark.parametrize("is_key", [False, True])
def test_direct_plain_field_approval_is_value_only(is_key: bool) -> None:
    output: list[tuple[str, str, bool]] = []
    security._scan_fields(
        [("field", "hello", is_key)],
        operation="recall",
        canonical_output=output,
        reviewed_fields=frozenset({"field"}),
    )
    canonical = output[0][1]
    assert isinstance(canonical, ReviewedText)
    assert canonical.trusted == (0 if is_key else 1)
