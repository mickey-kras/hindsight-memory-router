from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations, product
from time import monotonic

from .confusables_data import ASCII_CONFUSABLES

MAX_CONFUSABLE_RULE_VARIANTS = 32
_DEADLINE_CHECK_INTERVAL = 1_024
_LATIN_NAME_PREFIX = "LATIN "
_DEFAULT_IGNORABLE_RANGES = (
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


class UnicodeScanDeadlineExceeded(RuntimeError):
    """Raised when bounded Unicode work reaches the caller's scan deadline."""


def _check_deadline(deadline: float | None, index: int = 0) -> None:
    if deadline is not None and index % _DEADLINE_CHECK_INTERVAL == 0 and monotonic() >= deadline:
        raise UnicodeScanDeadlineExceeded


@dataclass(frozen=True, slots=True)
class ConfusableVariantSet:
    variants: tuple[str, ...]
    exhausted: bool


@lru_cache(maxsize=1_024)
def _ascii_confusable_options(char: str) -> tuple[str, ...]:
    if char.isascii():
        return (char,)
    cp = ord(char)
    semantic = None
    if 0x1CCD6 <= cp <= 0x1CCEF:
        semantic = chr(ord("A") + cp - 0x1CCD6)
    elif 0x1CCF0 <= cp <= 0x1CCF9:
        semantic = str(cp - 0x1CCF0)
    elif 0x1F1E6 <= cp <= 0x1F1FF:
        semantic = chr(ord("A") + cp - 0x1F1E6)
    elif 0x1F150 <= cp <= 0x1F169:
        semantic = chr(ord("A") + cp - 0x1F150)
    elif 0x1F170 <= cp <= 0x1F189:
        semantic = chr(ord("A") + cp - 0x1F170)
    normalized = unicodedata.normalize("NFKC", char)
    nfkc_ascii = normalized if normalized != char and normalized.isascii() else None
    skeleton = ASCII_CONFUSABLES.get(cp)
    return tuple(dict.fromkeys(option for option in (semantic, nfkc_ascii, skeleton) if option))


def _fold_confusable_char(char: str) -> str:
    if unicodedata.category(char).startswith("M"):
        return char
    options = _ascii_confusable_options(char)
    return options[0] if len(options) == 1 else char


def _has_mixed_script_word(value: str, *, deadline: float | None = None) -> bool:
    has_ascii = False
    has_confusable_script = False
    for index, char in enumerate(value):
        _check_deadline(deadline, index)
        if char.isalpha():
            has_ascii |= char.isascii()
            name = unicodedata.name(char, "")
            has_confusable_script |= bool(
                name.startswith(("CYRILLIC ", "GREEK ")) and _ascii_confusable_options(char)
            )
            if has_ascii and has_confusable_script:
                return True
        elif not char.isdigit() and not unicodedata.category(char).startswith("M"):
            has_ascii = False
            has_confusable_script = False
    return False


def _build_confusable_rule_variants(  # NOSONAR
    value: str, *, deadline: float | None = None
) -> ConfusableVariantSet:
    if value.isascii():
        return ConfusableVariantSet((), False)
    ambiguous: list[tuple[int, tuple[str, ...]]] = []
    for index, char in enumerate(value):
        _check_deadline(deadline, index)
        options = _ascii_confusable_options(char)
        if not char.isascii() and options:
            ambiguous.append((index, options))
    if not ambiguous:
        return ConfusableVariantSet((), False)
    variants: list[str] = []

    def render(selected: tuple[str, ...]) -> None:
        parts: list[str] = []
        cursor = 0
        for (index, _), replacement in zip(ambiguous, selected, strict=True):
            _check_deadline(deadline, cursor)
            parts.extend((value[cursor:index], replacement))
            cursor = index + 1
        parts.append(value[cursor:])
        variant = "".join(parts)
        if variant != value and variant not in variants:
            variants.append(variant)

    preferred = tuple(options[0] for _, options in ambiguous)
    render(preferred)
    option_count = 1
    for _, options in ambiguous:
        option_count = min(MAX_CONFUSABLE_RULE_VARIANTS + 1, option_count * len(options))

    # Prefer fewer deviations from the alpha-prioritized skeleton. Within each
    # deviation count, earlier positions are explored first.
    deviable = tuple(
        position for position, (_, options) in enumerate(ambiguous) if len(options) > 1
    )
    explored = 0
    for deviation_count in range(1, len(deviable) + 1):
        for positions in combinations(deviable, deviation_count):
            alternatives = tuple(ambiguous[position][1][1:] for position in positions)
            for replacements in product(*alternatives):
                _check_deadline(deadline, explored)
                explored += 1
                if explored >= MAX_CONFUSABLE_RULE_VARIANTS:
                    return ConfusableVariantSet(tuple(variants), option_count > len(variants))
                selected = list(preferred)
                for position, replacement in zip(positions, replacements, strict=True):
                    selected[position] = replacement
                render(tuple(selected))
                if len(variants) >= MAX_CONFUSABLE_RULE_VARIANTS:
                    return ConfusableVariantSet(tuple(variants), option_count > len(variants))
    return ConfusableVariantSet(tuple(variants), option_count > len(variants))


def confusable_rule_variant_set(
    value: str, *, deadline: float | None = None
) -> ConfusableVariantSet:
    """Return bounded rule variants and whether further variants were omitted."""

    return _build_confusable_rule_variants(value, deadline=deadline)


def confusable_rule_variants(value: str) -> tuple[str, ...]:
    """Return at most 32 full-value alternatives, including a preferred skeleton."""

    return confusable_rule_variant_set(value).variants


def preferred_confusable_variant(value: str, *, deadline: float | None = None) -> str:
    """Return the deterministic semantic fold used by pattern detectors."""

    if value.isascii():
        return value
    chars: list[str] = []
    for index, char in enumerate(value):
        _check_deadline(deadline, index)
        options = _ascii_confusable_options(char)
        chars.append(options[0] if not char.isascii() and options else char)
    return "".join(chars)


def official_confusable_variant(value: str, *, deadline: float | None = None) -> str:
    """Return the vendored UTS #39 ASCII skeleton where one exists."""

    if value.isascii():
        return value
    chars: list[str] = []
    for index, char in enumerate(value):
        _check_deadline(deadline, index)
        chars.append(ASCII_CONFUSABLES.get(ord(char), char))
    return "".join(chars)


def canonicalize_content(  # NOSONAR
    content: str, *, deadline: float | None = None
) -> tuple[str, set[str]]:
    if content.isascii() and all(char.isprintable() or char in "\t\n\r" for char in content):
        return content, set()
    transformations: set[str] = set()
    if _has_mixed_script_word(content, deadline=deadline):
        transformations.add("mixed_script")
    if _has_unmapped_spoof_word(content, deadline=deadline):
        transformations.add("unmapped_confusable")
    pre_nfkc_chars: list[str] = []
    for index, char in enumerate(content):
        _check_deadline(deadline, index)
        pre_nfkc_chars.append(_pre_nfkc_ascii_fold(char))
    pre_nfkc = "".join(pre_nfkc_chars)
    if pre_nfkc != content:
        transformations.add("confusable")
    original_nfkc = _nfkc_preserving_ambiguous(pre_nfkc, deadline=deadline)
    (
        modifier_cleaned,
        invisible_removed,
        modifier_removed,
        modifier_evasion,
        keycap_folded,
    ) = _strip_ignorables(original_nfkc, deadline=deadline)
    mark_cleaned, pre_fold_mark_removed = _strip_evasive_marks(modifier_cleaned, deadline=deadline)
    diacritic_cleaned = _strip_latin_diacritics(mark_cleaned, deadline=deadline)
    if diacritic_cleaned != mark_cleaned:
        transformations.add("diacritic")
    pre_folded_chars: list[str] = []
    for index, char in enumerate(diacritic_cleaned):
        _check_deadline(deadline, index)
        pre_folded_chars.append(_fold_confusable_char(char))
    pre_folded = "".join(pre_folded_chars)
    if pre_folded != diacritic_cleaned:
        transformations.add("confusable")
    normalized = _nfkc_preserving_ambiguous(pre_folded, deadline=deadline)
    if original_nfkc != content:
        transformations.add("nfkc")
    canonical = normalized
    if pre_fold_mark_removed or invisible_removed:
        transformations.add("invisible")
    if modifier_removed:
        transformations.add("display_modifier")
    if modifier_evasion:
        transformations.add("display_modifier_evasion")
    if keycap_folded:
        transformations.add("keycap")
    return canonical, transformations


def _pre_nfkc_ascii_fold(char: str) -> str:
    if unicodedata.category(char).startswith("M"):
        return char
    options = _ascii_confusable_options(char)
    if len(options) == 1:
        return options[0]
    if options:
        return char
    normalized = unicodedata.normalize("NFKC", char)
    return normalized if normalized != char and normalized.isascii() else char


def _nfkc_preserving_ambiguous(value: str, *, deadline: float | None = None) -> str:
    parts: list[str] = []
    cursor = 0
    for index, char in enumerate(value):
        _check_deadline(deadline, index)
        if len(_ascii_confusable_options(char)) <= 1:
            continue
        parts.append(unicodedata.normalize("NFKC", value[cursor:index]))
        parts.append(char)
        cursor = index + 1
    if not parts:
        return unicodedata.normalize("NFKC", value)
    parts.append(unicodedata.normalize("NFKC", value[cursor:]))
    return "".join(parts)


def _strip_latin_diacritics(value: str, *, deadline: float | None = None) -> str:
    chars: list[str] = []
    for index, char in enumerate(value):
        _check_deadline(deadline, index)
        if not unicodedata.name(char, "").startswith(_LATIN_NAME_PREFIX):
            chars.append(char)
            continue
        decomposed = unicodedata.normalize("NFD", char)
        base = "".join(
            part for part in decomposed if not unicodedata.category(part).startswith("M")
        )
        chars.append(base if base.isascii() and base else char)
    return "".join(chars)


def _strip_ignorables(  # NOSONAR
    value: str, *, deadline: float | None = None
) -> tuple[str, bool, bool, bool, bool]:
    chars: list[str] = []
    invisible_removed = False
    modifier_removed = False
    modifier_evasion = False
    keycap_folded = False
    index = 0
    while index < len(value):
        _check_deadline(deadline, index)
        char = value[index]
        cp = ord(char)
        keycap_length = _keycap_sequence_length(value, index)
        if keycap_length:
            chars.append(char)
            keycap_folded = True
            index += keycap_length
            continue
        if unicodedata.category(char) == "Cc":
            if char in "\t\n\r":
                chars.append(char)
            else:
                invisible_removed = True
            index += 1
            continue
        if cp == 0x2800:
            invisible_removed = True
            index += 1
            continue
        if cp == 0x0640:
            left = chars[-1] if chars else ""
            right = value[index + 1] if index + 1 < len(value) else ""
            if _ascii_like_alnum(left) or _ascii_like_alnum(right):
                invisible_removed = True
                index += 1
                continue
        display_modifier = cp in {0x200C, 0x200D} or 0xFE00 <= cp <= 0xFE0F
        if display_modifier:
            modifier_removed = True
            end = index + 1
            while end < len(value):
                following_cp = ord(value[end])
                if following_cp not in {0x200C, 0x200D} and not 0xFE00 <= following_cp <= 0xFE0F:
                    break
                end += 1
            left = chars[-1] if chars else ""
            right = value[end] if end < len(value) else ""
            modifier_evasion |= _ascii_like_alnum(left) and _ascii_like_alnum(right)
            index = end
            continue
        if _is_default_ignorable(cp, unicodedata.category(char)):
            invisible_removed = True
            index += 1
            continue
        chars.append(char)
        index += 1
    return "".join(chars), invisible_removed, modifier_removed, modifier_evasion, keycap_folded


def _keycap_sequence_length(value: str, index: int) -> int:
    if value[index] not in "#*0123456789" or index + 1 >= len(value):
        return 0
    if ord(value[index + 1]) == 0x20E3:
        return 2
    if (
        ord(value[index + 1]) == 0xFE0F
        and index + 2 < len(value)
        and ord(value[index + 2]) == 0x20E3
    ):
        return 3
    return 0


def _mark_run_evasion(  # NOSONAR
    value: str, start: int, *, deadline: float | None = None
) -> tuple[int, bool]:
    end = start + 1
    while end < len(value) and unicodedata.category(value[end]).startswith("M"):
        _check_deadline(deadline, end)
        end += 1
    left = value[start - 1] if start > 0 else ""
    right = value[end] if end < len(value) else ""
    if _is_keycap_mark_run(value, start, end):
        base_index = _keycap_base_index(value, end - 1)
        keycap_left = value[base_index - 1] if base_index > 0 else ""
        keycap_right = value[end] if end < len(value) else ""
        return end, _ascii_like_alnum(keycap_left) and _ascii_like_alnum(keycap_right)
    in_word = _ascii_like_alnum(left) and _ascii_like_alnum(right)
    left_separator = not left or (left.isascii() and not left.isalnum())
    right_separator = not right or (right.isascii() and not right.isalnum())
    separator_adjacent = (
        (_ascii_like_alnum(left) and right_separator)
        or (_ascii_like_alnum(right) and left_separator)
        or (left_separator and right_separator)
    )
    return end, in_word or separator_adjacent


def _keycap_base_index(value: str, mark_index: int) -> int:
    base_index = mark_index - 1
    if base_index >= 0 and ord(value[base_index]) == 0xFE0F:
        base_index -= 1
    return base_index


def _keycap_base(value: str, mark_index: int) -> bool:
    base_index = _keycap_base_index(value, mark_index)
    return base_index >= 0 and value[base_index] in "#*0123456789"


def _is_keycap_mark_run(value: str, start: int, end: int) -> bool:
    return "\u20e3" in value[start:end] and _keycap_base(value, end - 1)


def _ascii_like_alnum(char: str) -> bool:
    if not char:
        return False
    if char.isascii():
        return char.isalnum()
    name = unicodedata.name(char, "")
    if name.startswith(_LATIN_NAME_PREFIX) and char.isalpha():
        return True
    if name and not name.startswith((_LATIN_NAME_PREFIX, "CYRILLIC ", "GREEK ")):
        return False
    return any(option.isalnum() for option in _ascii_confusable_options(char))


def _has_unmapped_spoof_word(  # NOSONAR
    value: str, *, deadline: float | None = None
) -> bool:
    has_ascii_like = False
    has_unmapped = False
    word_length = 0
    for index, char in enumerate(value):
        _check_deadline(deadline, index)
        name = unicodedata.name(char, "")
        options = _ascii_confusable_options(char)
        if (char.isascii() and char.isalnum()) or (
            options and any(option.isalnum() for option in options)
        ):
            has_ascii_like = True
            word_length += 1
        elif name.startswith("CHEROKEE ") and char.isalpha():
            has_unmapped = True
            word_length += 1
        elif not unicodedata.category(char).startswith("M"):
            if has_unmapped and (has_ascii_like or word_length >= 4):
                return True
            has_ascii_like = False
            has_unmapped = False
            word_length = 0
    return has_unmapped and (has_ascii_like or word_length >= 4)


def _strip_evasive_marks(value: str, *, deadline: float | None = None) -> tuple[str, bool]:
    chars: list[str] = []
    removed = False
    index = 0
    while index < len(value):
        _check_deadline(deadline, index)
        cp = ord(value[index])
        if unicodedata.category(value[index]).startswith("M") and not 0xFE00 <= cp <= 0xFE0F:
            end, evasion = _mark_run_evasion(value, index, deadline=deadline)
            if evasion:
                removed = True
            else:
                chars.extend(value[index:end])
            index = end
            continue
        chars.append(value[index])
        index += 1
    return "".join(chars), removed


@lru_cache(maxsize=4_096)
def _is_default_ignorable(cp: int, category: str) -> bool:
    return category == "Cf" or any(start <= cp <= end for start, end in _DEFAULT_IGNORABLE_RANGES)
