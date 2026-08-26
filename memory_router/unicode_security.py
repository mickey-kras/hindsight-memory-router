from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from functools import lru_cache
from itertools import islice, product

from confusables import normalize as normalize_confusables  # type: ignore[import-untyped]

MAX_CONFUSABLE_RULE_VARIANTS = 32


@lru_cache(maxsize=1_024)
def _ascii_confusable_options(char: str) -> tuple[str, ...]:
    if char.isascii():
        return (char,)
    return tuple(
        dict.fromkeys(
            option
            for option in normalize_confusables(char, prioritize_alpha=True)
            if option.isascii()
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
        elif not unicodedata.category(char).startswith("M"):
            has_ascii = False
            has_confusable_script = False
    return False


def confusable_rule_variants(value: str) -> tuple[str, ...]:
    """Build bounded alternatives one word at a time."""
    variants: list[str] = []
    for word_match in re.finditer(r"\w+", value, re.UNICODE):
        word = word_match.group(0)
        for variant in _confusable_word_variants(word):
            variants.append(f"{value[: word_match.start()]}{variant}{value[word_match.end() :]}")
    return tuple(dict.fromkeys(variants))


def _confusable_word_variants(value: str) -> tuple[str, ...]:
    ambiguous: list[tuple[int, tuple[str, ...]]] = []
    for index, char in enumerate(value):
        options = _ascii_confusable_options(char)
        if not char.isascii() and options:
            ambiguous.append((index, options))
    variants: list[str] = []
    choices = product(*(options for _, options in ambiguous))
    for selected in islice(choices, MAX_CONFUSABLE_RULE_VARIANTS):
        parts: list[str] = []
        cursor = 0
        for (index, _), replacement in zip(ambiguous, selected, strict=True):
            parts.extend((value[cursor:index], replacement))
            cursor = index + 1
        parts.append(value[cursor:])
        variant = "".join(parts)
        if variant != value:
            variants.append(variant)
    return tuple(dict.fromkeys(variants))


def canonicalize_content(content: str) -> tuple[str, set[str]]:
    transformations: set[str] = set()
    pre_folded = "".join(_fold_confusable_char(char) for char in content)
    if pre_folded != content:
        transformations.add("confusable")
    normalized = unicodedata.normalize("NFKC", pre_folded)
    if unicodedata.normalize("NFKC", content) != content:
        transformations.add("nfkc")
    if _has_mixed_script_word(unicodedata.normalize("NFKC", content)):
        transformations.add("mixed_script")
    chars: list[str] = []
    removed = False
    display_modifier_removed = False
    display_modifier_evasion = False
    for index, char in enumerate(normalized):
        cp = ord(char)
        display_modifier = cp in {0x200C, 0x200D} or 0xFE00 <= cp <= 0xFE0F
        invisible = (
            unicodedata.category(char) == "Cf"
            or 0x202A <= cp <= 0x202E
            or 0x2066 <= cp <= 0x2069
            or 0xE0000 <= cp <= 0xE007F
        )
        if display_modifier:
            display_modifier_removed = True
            previous = _nearest_non_modifier(reversed(normalized[:index]))
            following = _nearest_non_modifier(iter(normalized[index + 1 :]))
            if (
                previous.isascii()
                and previous.isalnum()
                and following.isascii()
                and following.isalnum()
            ):
                display_modifier_evasion = True
        elif invisible:
            removed = True
        else:
            chars.append(char)
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


def _nearest_non_modifier(chars: Iterable[str]) -> str:
    return next(
        (
            candidate
            for candidate in chars
            if candidate not in "\u200c\u200d" and not 0xFE00 <= ord(candidate) <= 0xFE0F
        ),
        "",
    )
