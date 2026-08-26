from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations, product

from .confusables_data import ASCII_CONFUSABLES

MAX_CONFUSABLE_RULE_VARIANTS = 32


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
    skeleton = ASCII_CONFUSABLES.get(cp)
    return tuple(dict.fromkeys(option for option in (semantic, skeleton) if option))


def _fold_confusable_char(char: str) -> str:
    if unicodedata.category(char).startswith("M"):
        return char
    options = _ascii_confusable_options(char)
    return options[0] if len(options) == 1 else char


def _has_mixed_script_word(value: str) -> bool:
    has_ascii = False
    has_confusable_script = False
    for char in value:
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


def _build_confusable_rule_variants(value: str) -> ConfusableVariantSet:
    ambiguous: list[tuple[int, tuple[str, ...]]] = []
    for index, char in enumerate(value):
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


def confusable_rule_variant_set(value: str) -> ConfusableVariantSet:
    """Return bounded rule variants and whether further variants were omitted."""

    return _build_confusable_rule_variants(value)


def confusable_rule_variants(value: str) -> tuple[str, ...]:
    """Return at most 32 full-value alternatives, including a preferred skeleton."""

    return confusable_rule_variant_set(value).variants


def canonicalize_content(content: str) -> tuple[str, set[str]]:
    if content.isascii():
        return content, set()
    transformations: set[str] = set()
    pre_nfkc = "".join(_pre_nfkc_ascii_fold(char) for char in content)
    if pre_nfkc != content:
        transformations.add("confusable")
    original_nfkc = unicodedata.normalize("NFKC", pre_nfkc)
    mark_cleaned, pre_fold_mark_removed = _strip_evasive_marks(original_nfkc)
    cleaned, invisible_removed, modifier_removed, modifier_evasion = _strip_ignorables(mark_cleaned)
    pre_folded = "".join(_fold_confusable_char(char) for char in cleaned)
    if pre_folded != cleaned:
        transformations.add("confusable")
    normalized = unicodedata.normalize("NFKC", pre_folded)
    if original_nfkc != content:
        transformations.add("nfkc")
    if _has_mixed_script_word(original_nfkc):
        transformations.add("mixed_script")
    canonical = normalized
    if pre_fold_mark_removed or invisible_removed:
        transformations.add("invisible")
    if modifier_removed:
        transformations.add("display_modifier")
    if modifier_evasion:
        transformations.add("display_modifier_evasion")
    return canonical, transformations


def _pre_nfkc_ascii_fold(char: str) -> str:
    normalized = unicodedata.normalize("NFKC", char)
    if unicodedata.category(char).startswith("M") or normalized == char:
        return char
    if normalized.isascii():
        return normalized
    options = _ascii_confusable_options(char)
    return options[0] if len(options) == 1 else char


def _strip_ignorables(value: str) -> tuple[str, bool, bool, bool]:
    chars: list[str] = []
    invisible_removed = False
    modifier_removed = False
    modifier_evasion = False
    index = 0
    while index < len(value):
        char = value[index]
        cp = ord(char)
        display_modifier = cp in {0x200C, 0x200D} or 0xFE00 <= cp <= 0xFE0F
        if display_modifier and _is_keycap_selector(value, index):
            chars.append(char)
            index += 1
            continue
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
    return "".join(chars), invisible_removed, modifier_removed, modifier_evasion


def _is_keycap_selector(value: str, index: int) -> bool:
    return (
        ord(value[index]) == 0xFE0F
        and index > 0
        and value[index - 1] in "#*0123456789"
        and index + 1 < len(value)
        and ord(value[index + 1]) == 0x20E3
    )


def _mark_run_evasion(value: str, start: int) -> tuple[int, bool]:
    end = start + 1
    while end < len(value) and unicodedata.category(value[end]).startswith("M"):
        end += 1
    left = value[start - 1] if start > 0 else ""
    right = value[end] if end < len(value) else ""
    if _is_keycap_mark_run(value, start, end):
        return end, False
    in_word = _ascii_like_alnum(left) and _ascii_like_alnum(right)
    left_separator = not left or (left.isascii() and not left.isalnum())
    right_separator = not right or (right.isascii() and not right.isalnum())
    separator_adjacent = (
        (_ascii_like_alnum(left) and right_separator)
        or (_ascii_like_alnum(right) and left_separator)
        or (left_separator and right_separator)
    )
    return end, in_word or separator_adjacent


def _keycap_base(value: str, mark_index: int) -> bool:
    base_index = mark_index - 1
    if base_index >= 0 and ord(value[base_index]) == 0xFE0F:
        base_index -= 1
    return base_index >= 0 and value[base_index] in "#*0123456789"


def _is_keycap_mark_run(value: str, start: int, end: int) -> bool:
    return "\u20e3" in value[start:end] and _keycap_base(value, end - 1)


def _ascii_like_alnum(char: str) -> bool:
    if not char:
        return False
    if char.isascii():
        return char.isalnum()
    name = unicodedata.name(char, "")
    if name.startswith("LATIN ") and char.isalpha():
        return True
    if name and not name.startswith(("LATIN ", "CYRILLIC ", "GREEK ")):
        return False
    return any(option.isalnum() for option in _ascii_confusable_options(char))


def _strip_evasive_marks(value: str) -> tuple[str, bool]:
    chars: list[str] = []
    removed = False
    index = 0
    while index < len(value):
        cp = ord(value[index])
        if unicodedata.category(value[index]).startswith("M") and not 0xFE00 <= cp <= 0xFE0F:
            end, evasion = _mark_run_evasion(value, index)
            if evasion:
                removed = True
            else:
                chars.extend(value[index:end])
            index = end
            continue
        chars.append(value[index])
        index += 1
    return "".join(chars), removed


def _is_default_ignorable(cp: int, category: str) -> bool:
    return category == "Cf" or any(
        start <= cp <= end
        for start, end in (
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
    )
