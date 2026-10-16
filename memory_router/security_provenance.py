# Approval belongs to field occurrences, never matching strings or rule names.
# Unknown provenance is untrusted.


from __future__ import annotations

import re
import time
from collections.abc import Iterable

from . import security_rules, security_windows
from .security_models import SafetyFinding
from .unicode_security import (
    confusable_rule_variant_set,
    official_confusable_variant,
    preferred_confusable_variant,
)


class ReviewedText(str):
    trusted: int | tuple[int, ...]
    numeric_spans: tuple[tuple[int, int, bool], ...]

    def __new__(
        cls,
        value: str,
        trusted: int | tuple[int, ...] = False,
        *,
        numeric_spans: tuple[tuple[int, int, bool], ...] = (),
    ) -> ReviewedText:
        instance = super().__new__(cls, value)
        instance.trusted = trusted
        instance.numeric_spans = numeric_spans
        return instance


def occurrence_origin(value: str) -> int:
    if not isinstance(value, ReviewedText):
        return 0
    if isinstance(value.trusted, int):
        return max(0, value.trusted)
    units = set(value.trusted) - {-1}  # Synthetic separators are neutral.
    return units.pop() if len(units) == 1 and 0 not in units else 0


def reviewed(value: str) -> bool:
    return occurrence_origin(value) > 0


def flags_for(value: str) -> tuple[int, ...]:
    if isinstance(value, ReviewedText) and isinstance(value.trusted, tuple):
        return value.trusted
    return (occurrence_origin(value),) * len(value)


def join(parts: Iterable[str], separator: str = "") -> ReviewedText:
    entries = list(parts)
    value = separator.join(entries)
    flags: list[int] = []
    numeric_spans: list[tuple[int, int, bool]] = []
    for index, entry in enumerate(entries):
        if index:
            # Inserted separators do not introduce unreviewed source content.
            flags.extend([-1] * len(separator))
        if isinstance(entry, ReviewedText):
            numeric_spans.extend(
                (start + len(flags), end + len(flags), complete)
                for start, end, complete in entry.numeric_spans
            )
        flags.extend(flags_for(entry))
    return ReviewedText(value, tuple(flags), numeric_spans=tuple(numeric_spans))


def slice_text(value: ReviewedText, start: int, stop: int | None = None) -> ReviewedText:
    trusted = value.trusted if isinstance(value.trusted, int) else value.trusted[start:stop]
    start, end, _ = slice(start, stop).indices(len(value))
    # A clipped token remains incomplete, but cannot claim adjacent source characters.
    numeric_spans = tuple(
        (
            max(left, start) - start,
            min(right, end) - start,
            complete and left >= start and right <= end,
        )
        for left, right, complete in value.numeric_spans
        if left < end and right > start
    )
    return ReviewedText(value[start:end], trusted, numeric_spans=numeric_spans)


def bound(value: ReviewedText, *, prefix: bool = False) -> ReviewedText:
    render = (
        security_windows._bounded_utf8_prefix if prefix else security_windows._bounded_utf8_suffix
    )
    bounded = render(value.encode())
    return (
        slice_text(value, 0, len(bounded))
        if prefix
        else slice_text(value, len(value) - len(bounded))
    )


def bounded_join(
    parts: Iterable[str], separator: str = "", *, prefix: bool = False
) -> ReviewedText:
    entries = list(parts)
    text = ReviewedText("")
    sequence = entries if prefix else list(reversed(entries))
    for index, entry in enumerate(sequence):
        original_size = (
            len(entry.encode()) + len(text.encode()) + (len(separator.encode()) if index else 0)
        )
        entry = bound(
            entry if isinstance(entry, ReviewedText) else ReviewedText(entry), prefix=prefix
        )
        pieces = [text, entry] if prefix else [entry, text]
        combined = join(pieces, separator if index else "")
        text = bound(combined, prefix=prefix)
        if original_size >= security_windows.MAX_SPLIT_WINDOW_BYTES:
            break
    return text


def mixed_suffix(fragments: list[str]) -> ReviewedText:
    tail = bounded_join(fragments[1:])
    if (
        sum(len(fragment.encode()) for fragment in fragments[1:])
        >= security_windows.MAX_SPLIT_WINDOW_BYTES
    ):
        return tail
    return bounded_join([fragments[0], tail], " ")


def trim(value: str, *, from_start: bool) -> ReviewedText:
    marked = value if isinstance(value, ReviewedText) else ReviewedText(value)
    trimmed = security_rules._trim_boundary_padding(value, from_start=from_start)
    return (
        slice_text(marked, len(marked) - len(trimmed))
        if from_start
        else slice_text(marked, 0, len(trimmed))
    )


def sequence_windows(fragments: list[str], *, deadline: float | None) -> Iterable[ReviewedText]:
    # Retain exact source fields through bounded joins and slicing.
    if len(fragments) < 2 or (deadline is not None and time.monotonic() >= deadline):
        return
    spaced_prefix = bounded_join(fragments[:-1], " ")
    compact_prefix = bounded_join(fragments[:-1])
    current = fragments[-1]
    if (
        len(spaced_prefix.encode()) + 1 + len(current.encode())
        > security_windows.MAX_SPLIT_WINDOW_BYTES
        or len(compact_prefix.encode()) + len(current.encode())
        > security_windows.MAX_SPLIT_WINDOW_BYTES
    ):
        prefix = bounded_join([current], prefix=True)
        yield join([spaced_prefix, prefix], " ")
        yield join([compact_prefix, prefix])
    yield bounded_join(fragments, " ")
    yield bounded_join(fragments)
    yield mixed_suffix(fragments)
    # Rolling scans retain the first field's bounded prefix in their mixed join.
    yield join([bounded_join([fragments[0]], prefix=True), bounded_join(fragments[1:])], " ")
    trimmed: list[ReviewedText] = []
    for index, fragment in enumerate(fragments):
        if deadline is not None and time.monotonic() >= deadline:
            return
        value = trim(fragment, from_start=index > 0)
        trimmed.append(trim(value, from_start=False) if index < len(fragments) - 1 else value)
    yield bounded_join(trimmed, " ")
    yield bounded_join(trimmed)
    yield mixed_suffix(list(trimmed))
    if len(fragments) == 2:
        left = bound(trim(fragments[0], from_start=False))
        right = bound(trim(fragments[1], from_start=True), prefix=True)
        yield join([left, right], " ")
        yield join([left, right])
        # Synthesized edge matches always depend on both fields.
        origin = occurrence_origin(fragments[0])
        trusted = origin if origin == occurrence_origin(fragments[1]) else 0
        for edge in security_rules._rule_edge_matches(*fragments, deadline=deadline):
            yield ReviewedText(edge, trusted)


def wholly_reviewed(finding: SafetyFinding, window: ReviewedText) -> bool:
    # Every occurrence must have proven approved provenance, including compact forms.
    if finding.reason == "span_limit" or not finding.hits:
        return False
    originals = [window]
    if not window.isascii():
        flags = flags_for(window)
        for fold in (preferred_confusable_variant, official_confusable_variant):
            pieces = [fold(char) for char in window]
            originals.append(
                ReviewedText(
                    "".join(pieces),
                    tuple(flags[index] for index, piece in enumerate(pieces) for _ in piece),
                )
            )
    if not window.isascii():
        variants_to_prove = confusable_rule_variant_set(window)
        known = set(originals)
        if variants_to_prove.exhausted or any(
            value not in known for value in variants_to_prove.variants
        ):
            # A hit string alone cannot establish which ambiguous source variant
            # produced it. Mixed-origin windows therefore cannot be exempted.
            return reviewed(window)
    variants: list[ReviewedText] = []
    for original in originals:
        flags = flags_for(original)
        removed = {match.start() for match in security_rules._IN_WORD_DIGIT.finditer(original)}
        keep = [index for index in range(len(original)) if index not in removed]
        without_digits = ReviewedText(
            "".join(original[index] for index in keep), tuple(flags[index] for index in keep)
        )
        for value in (original, without_digits):
            for rendered in (
                value,
                ReviewedText(security_rules._RULE_PUNCTUATION.sub(" ", value), value.trusted),
            ):
                variants.append(rendered)
                flags = flags_for(rendered)
                keep = [index for index, char in enumerate(rendered) if not char.isspace()]
                variants.append(
                    ReviewedText(
                        "".join(rendered[index] for index in keep),
                        tuple(flags[index] for index in keep),
                    )
                )
    for hit in finding.hits:
        found = False
        for variant in variants:
            for match in re.finditer(re.escape(hit), variant, re.I):
                found = True
                if not reviewed(slice_text(variant, match.start(), match.end())):
                    return False
        if not found:
            return False
    return True
