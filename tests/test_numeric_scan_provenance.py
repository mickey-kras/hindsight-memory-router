from __future__ import annotations

import re

import pytest

from memory_router import security, security_provenance, security_rules
from memory_router.security_provenance import ReviewedText, bounded_join, join, slice_text


@pytest.mark.parametrize("location", ["scores", "metadata", "chunks"])
@pytest.mark.parametrize("reviewed", [False, True])
def test_unrelated_float_tokens_do_not_assemble_a_card(location: str, reviewed: bool) -> None:
    values = {"final": 0.5956395172012323, "reranker": 0.25146369743096875}
    result = {"id": "m1", "text": "ordinary", location: [values]}
    assert security.scan_recall_response(
        {"results": [result]}, reviewed_result_positions=frozenset({0}) if reviewed else frozenset()
    ).safe


@pytest.mark.parametrize(
    "values",
    [
        [0.5956395172012323, 0.25146369743096875],
        [-0.5956395172012323, -0.25146369743096875],
        [5.956395172012323e-18, 2.5146369743096875e-18],
        [True, False, None, 0.25, -0.5],
    ],
)
def test_nested_numeric_shapes_are_not_textual_cards(values: list[object]) -> None:
    assert security.scan_recall_response({"results": [], "nested": [{"values": values}]}).safe


@pytest.mark.parametrize(
    "values",
    [
        ["0.5956395172012323", "0.25146369743096875"],
        [0.5956395172012323, "0.25146369743096875"],
        ["0.5956395172012323", 0.25146369743096875],
        ["41111111", "11111111"],
        [41111111, 11111111],
        [41111111.0, 11111111.0],
        ["credit card", 0.5956395172012323, 0.25146369743096875],
        ["credit card", 2026123456789012],
        ["credit card", 2026123456789012.0],
        ["ignore", 0.5956395172012323, "previous instructions"],
        ["api_key=", "abcdefghijklmnopqrstuvwx"],
    ],
)
def test_numeric_provenance_cannot_exempt_real_or_textual_detections(values: list[object]) -> None:
    assert not security.scan_recall_response({"results": [], "values": values}).safe


@pytest.mark.parametrize("value", [4111111111111111, 4111111111111111.0, -4111111111111111])
def test_direct_numeric_card_detection_is_unchanged(value: int | float) -> None:
    assert not security.scan_recall_response({"results": [], "value": value}).safe


def test_single_fractional_numeric_detection_is_unchanged() -> None:
    # This source's fractional digits are independently Luhn-valid, not assembled.
    value = 0.4111111111111111
    assert not security.scan_recall_response({"results": [], "value": value}).safe


@pytest.mark.parametrize("budget", ["MAX_SCAN_FIELDS", "MAX_ROLLING_WINDOWS", "MAX_SKIP_WINDOWS"])
def test_numeric_provenance_preserves_fail_closed_budgets(
    monkeypatch: pytest.MonkeyPatch, budget: str
) -> None:
    monkeypatch.setattr(security, budget, 0)
    assert not security.scan_recall_response({"results": [], "values": [0.25, 0.5]}).safe


def test_numeric_spans_keep_clipped_original_boundaries_and_never_approve() -> None:
    numeric = ReviewedText("0.5956395172012323", numeric_spans=((0, 18, True),))
    suffix = slice_text(numeric, 2)
    assert suffix.numeric_spans == ((0, 16, False),)
    combined = join([suffix, ReviewedText("0.25", numeric_spans=((0, 4, True),))], " ")
    assert combined.numeric_spans == ((0, 16, False), (17, 21, True))
    assert not security_provenance.reviewed(combined)
    assert bounded_join([numeric]).numeric_spans == numeric.numeric_spans


def test_partial_numeric_card_filter_requires_only_numeric_digits_and_no_context() -> None:
    value = "0.5956395172012323 0.25146369743096875"
    match = next(security_rules._CARD_NUMBER.finditer(value))
    spans = ((0, 18, True), (19, len(value), True))
    assert security_rules._synthetic_numeric_card(value, match, spans)
    assert not security_rules._synthetic_numeric_card(value, match, spans[:1])
    contextual = "credit card " + value
    contextual_match = next(security_rules._CARD_NUMBER.finditer(contextual))
    assert not security_rules._synthetic_numeric_card(
        contextual,
        contextual_match,
        tuple((left + 12, right + 12, complete) for left, right, complete in spans),
    )
    non_card = re.search("card", contextual)
    assert non_card is not None
    assert not security_rules._synthetic_numeric_card(contextual, non_card, spans)


def test_same_text_numeric_and_untrusted_occurrences_do_not_share_filtered_cache() -> None:
    left, right = 0.5956395172012323, 0.25146369743096875
    assert not security.scan_recall_response(
        {"results": [], "values": [left, right, str(left), str(right)]}
    ).safe


@pytest.mark.parametrize("values", [[-41111111, -11111111], [-41111111.0, -11111111.0]])
def test_signed_whole_numeric_fragments_still_detect(values: list[int | float]) -> None:
    assert not security.scan_recall_response({"results": [], "values": values}).safe


def test_bounded_numeric_spans_preserve_original_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security_provenance.security_windows, "MAX_SPLIT_WINDOW_BYTES", 12)
    numeric = ReviewedText("0.5956395172012323", numeric_spans=((0, 18, True),))
    assert bounded_join([numeric]).numeric_spans == ((0, 12, False),)
    assert bounded_join([numeric], prefix=True).numeric_spans == ((0, 12, False),)


def test_review_approval_does_not_transfer_to_numeric_or_duplicate_string_occurrences() -> None:
    left, right = 0.5956395172012323, 0.25146369743096875
    response = {
        "results": [
            {"id": "m1", "text": str(left)},
            {"id": "m2", "text": "ordinary", "metadata": [str(left), right]},
        ]
    }
    assert not security.scan_recall_response(
        response, reviewed_result_positions=frozenset({0, 1})
    ).safe


def test_clipped_numeric_provenance_cannot_claim_adjacent_string_digits() -> None:
    numeric = ReviewedText("0.5956395172012323", numeric_spans=((0, 18, True),))
    # Prefix/suffix clipping must not extend source ownership into a neighbor.
    prefix = join([slice_text(numeric, 0, 2), "4111111111111111"])
    suffix = join(["4111111111111111", slice_text(numeric, 16)])
    assert prefix.numeric_spans == ((0, 2, False),)
    assert suffix.numeric_spans == ((16, 18, False),)
    for value in (prefix, suffix):
        for match in security_rules._CARD_NUMBER.finditer(value):
            assert not security_rules._synthetic_numeric_card(value, match, value.numeric_spans)
