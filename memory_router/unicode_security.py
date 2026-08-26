from __future__ import annotations

import unicodedata
from functools import lru_cache
from itertools import islice, product

from confusables import normalize as normalize_confusables  # type: ignore[import-untyped]

MAX_CONFUSABLE_RULE_VARIANTS = 32


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


def confusable_rule_variants(value: str) -> tuple[str, ...]:
    """Return at most 32 full-value alternatives, including a preferred skeleton."""
    ambiguous: list[tuple[int, tuple[str, ...]]] = []
    for index, char in enumerate(value):
        options = _ascii_confusable_options(char)
        if not char.isascii() and options:
            ambiguous.append((index, options))
    if not ambiguous:
        return ()
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
    for option_index, (_, options) in enumerate(ambiguous):
        for replacement in options[1:]:
            selected = list(preferred)
            selected[option_index] = replacement
            render(tuple(selected))
            if len(variants) >= MAX_CONFUSABLE_RULE_VARIANTS:
                return tuple(variants)
    choices = product(*(options for _, options in ambiguous))
    for selected_variant in islice(choices, MAX_CONFUSABLE_RULE_VARIANTS):
        render(selected_variant)
        if len(variants) >= MAX_CONFUSABLE_RULE_VARIANTS:
            break
    return tuple(dict.fromkeys(variants))


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
        elif invisible or unicodedata.category(char).startswith("M") and _joins_alnum(normalized, index):
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


def _joins_alnum(value: str, index: int) -> bool:
    return (
        index > 0
        and index + 1 < len(value)
        and value[index - 1].isalnum()
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
            (0x3164, 0x3164),
            (0xFE00, 0xFE0F),
            (0xFFA0, 0xFFA0),
            (0xFFF0, 0xFFF8),
            (0x1BCA0, 0x1BCA3),
            (0x1D173, 0x1D17A),
            (0xE0000, 0xE0FFF),
        )
    )
