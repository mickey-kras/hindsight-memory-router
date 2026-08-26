from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations, product

from confusables import normalize as normalize_confusables  # type: ignore[import-untyped]

MAX_CONFUSABLE_RULE_VARIANTS = 32

_CONFUSABLE_SUPPLEMENT: dict[int, tuple[str, ...]] = {
    0x00D8: ("O",),
    0x00DE: ("P", "T"),
    0x00F8: ("o",),
    0x00FE: ("p", "t"),
    0x0110: ("D",),
    0x0111: ("d",),
    0x0141: ("L",),
    0x0142: ("l",),
    0x0192: ("f",),
    0x01BF: ("p",),
    0x0448: ("w",),
    0x0969: ("3",),
    0x2C82: ("B",),
    0x2C83: ("b",),
    0x11DE0: ("O",),
    0x11DE1: ("l",),
    0x16EAA: ("l",),
}


@dataclass(frozen=True, slots=True)
class ConfusableVariantSet:
    variants: tuple[str, ...]
    exhausted: bool


@lru_cache(maxsize=1_024)
def _ascii_confusable_options(char: str) -> tuple[str, ...]:
    if char.isascii():
        return (char,)
    cp = ord(char)
    if 0x1CCD6 <= cp <= 0x1CCEF:
        return (chr(ord("A") + cp - 0x1CCD6),)
    if 0x1CCF0 <= cp <= 0x1CCF9:
        digit = cp - 0x1CCF0
        return ("O", "0") if digit == 0 else ("l", "1") if digit == 1 else (str(digit),)
    if cp in _CONFUSABLE_SUPPLEMENT:
        return _CONFUSABLE_SUPPLEMENT[cp]
    options: list[str] = []
    for option in normalize_confusables(char, prioritize_alpha=True):
        stripped = "".join(
            item for item in option if not unicodedata.category(item).startswith("M")
        )
        if stripped.isascii() and stripped:
            options.append(stripped)
    return tuple(
        sorted(
            dict.fromkeys(options),
            key=lambda option: (not option.isalpha(), len(option), option.lower(), option),
        )
    )


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
            has_confusable_script |= name.startswith(("CYRILLIC ", "GREEK "))
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
    original_nfkc = unicodedata.normalize("NFKC", content)
    mark_cleaned, pre_fold_mark_removed = _strip_evasive_marks(original_nfkc)
    pre_folded = "".join(_fold_confusable_char(char) for char in mark_cleaned)
    if pre_folded != mark_cleaned:
        transformations.add("confusable")
    normalized = unicodedata.normalize("NFKC", pre_folded)
    if original_nfkc != content:
        transformations.add("nfkc")
    if _has_mixed_script_word(original_nfkc):
        transformations.add("mixed_script")
    if _has_unmapped_ascii_word_char(original_nfkc):
        transformations.add("unmapped_confusable")
    chars: list[str] = []
    removed = pre_fold_mark_removed
    display_modifier_removed = False
    display_modifier_evasion = False
    index = 0
    last_non_modifier = ""
    while index < len(normalized):
        char = normalized[index]
        cp = ord(char)
        display_modifier = cp in {0x200C, 0x200D} or 0xFE00 <= cp <= 0xFE0F
        invisible = _is_default_ignorable(cp, unicodedata.category(char))
        if display_modifier:
            display_modifier_removed = True
            end = index + 1
            while end < len(normalized):
                following_cp = ord(normalized[end])
                if following_cp not in {0x200C, 0x200D} and not 0xFE00 <= following_cp <= 0xFE0F:
                    break
                end += 1
            following = normalized[end] if end < len(normalized) else ""
            if _ascii_like_alnum(last_non_modifier) or _ascii_like_alnum(following):
                display_modifier_evasion = True
            index = end
            continue
        elif invisible:
            removed = True
        elif unicodedata.category(char).startswith("M"):
            end, mark_evasion = _mark_run_evasion(normalized, index)
            if mark_evasion:
                removed = True
            else:
                chars.extend(normalized[index:end])
                last_non_modifier = normalized[end - 1]
            index = end
            continue
        else:
            chars.append(char)
            last_non_modifier = char
        index += 1
    canonical = "".join(chars)
    if removed:
        transformations.add("invisible")
    if display_modifier_removed:
        transformations.add("display_modifier")
    if display_modifier_evasion:
        transformations.add("display_modifier_evasion")
    if not canonical.isascii():
        skeleton = "".join(_fold_confusable_char(char) for char in canonical)
        if skeleton != canonical:
            canonical = skeleton
            transformations.add("confusable")
    return canonical, transformations


def _mark_run_evasion(value: str, start: int) -> tuple[int, bool]:
    end = start + 1
    while end < len(value) and unicodedata.category(value[end]).startswith("M"):
        end += 1
    left = value[start - 1] if start > 0 else ""
    right = value[end] if end < len(value) else ""
    left_ascii = bool(left and left.isascii())
    right_ascii = bool(right and right.isascii())
    in_word = _ascii_like_alnum(left) and _ascii_like_alnum(right)
    separator_adjacent = (
        _ascii_like_alnum(left) or _ascii_like_alnum(right) or (left_ascii and right_ascii)
    ) and (not _ascii_like_alnum(left) or not _ascii_like_alnum(right))
    return end, in_word or separator_adjacent


def _ascii_like_alnum(char: str) -> bool:
    if not char:
        return False
    if char.isascii():
        return char.isalnum()
    name = unicodedata.name(char, "")
    if (
        "LATIN" not in name
        and ord(char) not in _CONFUSABLE_SUPPLEMENT
        and not (0x1CCD6 <= ord(char) <= 0x1CCF9)
    ):
        return False
    return any(option.isalnum() for option in _ascii_confusable_options(char))


def _has_unmapped_ascii_word_char(value: str) -> bool:
    for index, char in enumerate(value):
        if char.isascii() or _ascii_confusable_options(char):
            continue
        if not unicodedata.name(char, "").startswith(("LATIN ", "CYRILLIC ", "GREEK ")):
            continue
        left = value[index - 1] if index else ""
        right = value[index + 1] if index + 1 < len(value) else ""
        if (left.isascii() and left.isalnum()) or (right.isascii() and right.isalnum()):
            return True
    return False


def _strip_evasive_marks(value: str) -> tuple[str, bool]:
    chars: list[str] = []
    removed = False
    index = 0
    while index < len(value):
        if unicodedata.category(value[index]).startswith("M"):
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
