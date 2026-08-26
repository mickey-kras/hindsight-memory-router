from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations, product

from confusables import normalize as normalize_confusables  # type: ignore[import-untyped]

MAX_CONFUSABLE_RULE_VARIANTS = 32


@dataclass(frozen=True, slots=True)
class ConfusableVariantSet:
    variants: tuple[str, ...]
    exhausted: bool


@lru_cache(maxsize=1_024)
def _ascii_confusable_options(char: str) -> tuple[str, ...]:
    if char.isascii():
        return (char,)
    return tuple(
        sorted(
            dict.fromkeys(
                option
                for option in normalize_confusables(char, prioritize_alpha=True)
                if option.isascii()
            ),
            key=lambda option: (not option.isalpha(), len(option), option.lower(), option),
        )
    )


def _fold_confusable_char(char: str) -> str:
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
    for deviation_count in range(1, len(ambiguous) + 1):
        for positions in combinations(range(len(ambiguous)), deviation_count):
            alternatives = tuple(ambiguous[position][1][1:] for position in positions)
            if any(not options for options in alternatives):
                continue
            for replacements in product(*alternatives):
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
    transformations: set[str] = set()
    original_nfkc = unicodedata.normalize("NFKC", content)
    pre_folded = "".join(_fold_confusable_char(char) for char in content)
    if pre_folded != content:
        transformations.add("confusable")
    normalized = unicodedata.normalize("NFKC", pre_folded)
    if original_nfkc != content:
        transformations.add("nfkc")
    if _has_mixed_script_word(original_nfkc):
        transformations.add("mixed_script")
    chars: list[str] = []
    removed = False
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
            if (
                last_non_modifier.isascii()
                and last_non_modifier.isalnum()
                and following.isascii()
                and following.isalnum()
            ):
                display_modifier_evasion = True
            index = end
            continue
        elif (
            invisible
            or _is_separator_mark_evasion(normalized, index)
            or _is_ascii_overlay_evasion(normalized, index)
        ):
            removed = True
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


def _is_separator_mark_evasion(value: str, index: int) -> bool:
    if not unicodedata.category(value[index]).startswith("M"):
        return False
    left = index - 1
    while left >= 0 and unicodedata.category(value[left]).startswith("M"):
        left -= 1
    right = index + 1
    while right < len(value) and unicodedata.category(value[right]).startswith("M"):
        right += 1
    if left < 0 or right >= len(value):
        return False
    return (value[left].isspace() and value[right].isascii() and value[right].isalnum()) or (
        value[left].isascii() and value[left].isalnum() and value[right].isspace()
    )


def _is_ascii_overlay_evasion(value: str, index: int) -> bool:
    cp = ord(value[index])
    if not (0x0334 <= cp <= 0x0338):
        return False
    return (
        index > 0
        and index + 1 < len(value)
        and value[index - 1].isascii()
        and value[index - 1].isalnum()
        and value[index + 1].isascii()
        and value[index + 1].isalnum()
    )


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
