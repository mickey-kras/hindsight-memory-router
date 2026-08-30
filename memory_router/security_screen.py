from __future__ import annotations

import re
import sys

from .security_rules import _COMPACT_SPLIT_RULES, _DETECTORS, _SPLIT_RULES

_DETECTOR_PATTERN_TABLES = {
    "ToolAbuseDetector": ("TOOL_ABUSE_PATTERNS", "UNSAFE_TOOL_OUTPUT_PATTERNS"),
    "PrivilegeEscalationDetector": ("ESCALATION_PATTERNS",),
    "ExcessiveAutonomyDetector": ("AUTONOMY_PATTERNS",),
}


_ZERO_WIDTH_ESCAPES = frozenset("bBAZzG")


_WINDOW_WHITESPACE = re.compile(r"\s+")


def _regex_class_end(source: str, start: int) -> int | None:
    """Index just past the ']' closing the class at source[start]."""
    index = start + 1
    if index < len(source) and source[index] == "^":
        index += 1
    if index < len(source) and source[index] == "]":
        index += 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == "]":
            return index + 1
        index += 1
    return None


_REGEX_SKIP_CHARS = frozenset({"\\", "["})


_REGEX_DEPTH_DELTA = {"(": 1, ")": -1}


def _regex_skip_forward(source: str, index: int) -> int | None:
    """Index past an escape or class at source[index]; None for other chars."""
    char = source[index]
    if char == "\\":
        return index + 2
    if char == "[":
        return _regex_class_end(source, index)
    return None


def _regex_group_end(source: str, start: int) -> int | None:
    """Index just past the ')' matching the '(' at source[start]."""
    depth = 0
    index = start
    while index < len(source):
        char = source[index]
        if char in _REGEX_SKIP_CHARS:
            skipped = _regex_skip_forward(source, index)
            if skipped is None:
                return None
            index = skipped
            continue
        delta = _REGEX_DEPTH_DELTA.get(char, 0)
        depth += delta
        if delta < 0 and depth == 0:
            return index + 1
        index += 1
    return None


def _regex_top_alternatives(source: str) -> list[str] | None:
    """Split on top-level '|' operators; None when there are none."""
    depth = 0
    index = 0
    last = 0
    parts: list[str] = []
    while index < len(source):
        char = source[index]
        if char in _REGEX_SKIP_CHARS:
            skipped = _regex_skip_forward(source, index)
            if skipped is None:
                return None
            index = skipped
            continue
        if char == "|" and depth == 0:
            parts.append(source[last:index])
            last = index + 1
        else:
            depth += _REGEX_DEPTH_DELTA.get(char, 0)
            if depth < 0:
                return None
        index += 1
    if depth != 0:
        return None
    if not parts:
        return None
    parts.append(source[last:])
    return parts


_MAX_SCREEN_ALTERNATIVES = 64


def _stage_walk(source: str, depth: int = 0) -> list[list[frozenset[str]]] | None:  # NOSONAR
    """Required literal stages of a pattern, as alternatives of stage lists.

    Returns a list of alternatives; each alternative is a list of stages and
    each stage a set of literals. Any match of ``source`` must, for at least
    one alternative, contain one literal from every stage of that alternative
    (stage order is preserved but callers may ignore it conservatively).
    Elements whose bytes cannot be determined (classes, wildcards, optional
    groups, alternation groups with an evidence-free branch) contribute no
    stage. Returns None on malformed or excessively branching input.
    """
    if depth > 8:
        return None
    alternatives: list[list[frozenset[str]]] = [[]]
    index = 0
    run: list[str] = []

    def flush() -> None:
        nonlocal run
        if run:
            stage = frozenset({"".join(run)})
            run = []
            for alternative in alternatives:
                alternative.append(stage)

    while index < len(source):
        char = source[index]
        if char == "\\":
            following = source[index + 1] if index + 1 < len(source) else ""
            if not following:
                return None
            if following in _ZERO_WIDTH_ESCAPES:
                index += 2
                continue
            if following.isalpha():
                flush()  # consuming class escape (\d, \s, \w, ...): unknown bytes
                index += 2
                continue
            run.append(following)
            index += 2
            continue
        if char in "[.":
            flush()  # character class or wildcard: undetermined element
            if char == "[":
                end = _regex_class_end(source, index)
                if end is None:
                    return None
                index = end
            else:
                index += 1
            continue
        if char in "^$":
            index += 1
            continue
        if char in "*+?":
            if run:
                run.pop()  # the quantified char itself is not required
            flush()
            index += 1
            continue
        if char == "{":
            if run:
                run.pop()
            flush()
            end = source.find("}", index)
            if end == -1:
                return None
            index = end + 1
            continue
        if char in "|)":
            return None  # handled by the caller's group/alternation logic
        if char == "(":
            flush()
            end = _regex_group_end(source, index)
            if end is None:
                return None
            inner = source[index + 1 : end - 1]
            if inner.startswith("?P=") or inner.startswith("?("):
                return None
            if inner.startswith("?#"):
                index = end
                continue
            if inner.startswith("?P<"):
                close = inner.find(">")
                if close == -1:
                    return None
                inner = inner[close + 1 :]
            elif inner.startswith("?"):
                body = inner[1:]
                colon = body.find(":")
                if colon == -1:
                    if body.startswith(("=", "!", "<")):
                        index = end  # lookarounds are zero-width
                        continue
                    if not body or any(letter not in "aiLmsux-" for letter in body):
                        return None
                    index = end  # (?i)-style global flag group consumes nothing
                    continue
                inner = body[colon + 1 :]
            required = True
            after = end
            if after < len(source) and source[after] in "*?":
                required = False
                after += 1
            elif after < len(source) and source[after] == "{":
                close = source.find("}", after)
                if close == -1:
                    return None
                lower_bound = source[after + 1 : close].split(",")[0]
                if not lower_bound.isdigit():
                    return None
                required = int(lower_bound) >= 1
                after = close + 1
            if not required:
                index = after  # optional group: nothing it matches is required
                continue
            inner_alternatives = _regex_top_alternatives(inner)
            branches = inner_alternatives if inner_alternatives is not None else [inner]
            best_stages: list[frozenset[str]] = []
            determined = True
            for branch in branches:
                branch_alternatives = _stage_walk(branch, depth + 1)
                if branch_alternatives is None:
                    return None
                for alternative in branch_alternatives:
                    if not alternative:
                        # A branch that can match without literal evidence
                        # makes the whole group undetermined: no stage.
                        determined = False
                        break
                    best_stages.append(
                        max(alternative, key=lambda stage: min(len(o) for o in stage))
                    )
                if not determined:
                    break
            if determined:
                stage = frozenset().union(*best_stages)
                for alternative in alternatives:
                    alternative.append(stage)
            index = after
            continue
        run.append(char)
        index += 1
    flush()
    return alternatives


def _option_is_strong(option: str) -> bool:
    """Strong options are long enough or symbolic enough to be discriminating."""
    return len(option) >= 3 or any(not (char.isalnum() or char in " -_") for char in option)


def _pattern_screen_stages(  # NOSONAR
    pattern: re.Pattern[str],
) -> tuple[tuple[frozenset[str], tuple[frozenset[str], ...]], ...] | None:
    """Per-alternative (index stage, all stages) pairs, or None when unscreenable.

    Every alternative must offer an index stage whose options are all strong;
    weak stages are still kept for refinement, where they discriminate well.
    """
    try:
        alternatives = _regex_top_alternatives(pattern.pattern)
        branches = alternatives if alternatives is not None else [pattern.pattern]
        staged: list[tuple[frozenset[str], tuple[frozenset[str], ...]]] = []
        for branch in branches:
            branch_alternatives = _stage_walk(branch)
            if branch_alternatives is None:
                return None
            for alternative in branch_alternatives:
                if not alternative:
                    return None  # an alternative without literal evidence
                index_candidates = [
                    stage
                    for stage in alternative
                    if stage and all(_option_is_strong(option) for option in stage)
                ]
                if index_candidates:
                    index_stage = max(
                        index_candidates, key=lambda stage: min(len(o) for o in stage)
                    )
                elif len(set(alternative)) >= 2:
                    # No all-strong stage, but at least two distinct stages:
                    # a weak index is acceptable because the remaining stages
                    # still discriminate during refinement. (A single repeated
                    # weak stage, e.g. ("-", "-"), would not.)
                    index_stage = max(alternative, key=lambda stage: min(len(o) for o in stage))
                else:
                    return None  # no discriminating stage to index on
                staged.append((index_stage, tuple(alternative)))
                if len(staged) > _MAX_SCREEN_ALTERNATIVES:
                    return None
    except (IndexError, ValueError, RecursionError):
        return None
    return tuple(staged)


def _literal_screen(
    patterns: list[re.Pattern[str]],
) -> tuple[
    frozenset[str],
    dict[str, list[tuple[frozenset[str], ...]]],
    tuple[re.Pattern[str], ...],
]:
    """Split patterns into index literals, refinements, and direct searches."""
    first_literals: set[str] = set()
    refinements: dict[str, list[tuple[frozenset[str], ...]]] = {}
    unscreened: list[re.Pattern[str]] = []
    for pattern in patterns:
        alternatives = _pattern_screen_stages(pattern)
        if alternatives is None:
            unscreened.append(pattern)
            continue
        for index_stage, stages in alternatives:
            lowered_stages = tuple(
                frozenset(option.lower() for option in stage) for stage in stages
            )
            for literal in index_stage:
                lowered = literal.lower()
                first_literals.add(lowered)
                refinements.setdefault(lowered, []).append(lowered_stages)
    return frozenset(first_literals), refinements, tuple(unscreened)


def _query_window_screen() -> (  # NOSONAR
    tuple[
        frozenset[str],
        dict[str, list[tuple[frozenset[str], ...]]],
        tuple[re.Pattern[str], ...],
        frozenset[str],
        dict[str, list[tuple[frozenset[str], ...]]],
        tuple[re.Pattern[str], ...],
    ]
    | None
):
    """Build the conservative literal screen for query window scans."""
    value_patterns: list[re.Pattern[str]] = [pattern for pattern, _, _ in _SPLIT_RULES]
    try:
        for detector in _DETECTORS:
            own = getattr(detector, "_patterns", None)
            if isinstance(own, dict):
                value_patterns.extend(own.values())
                continue
            if isinstance(own, list):
                value_patterns.extend(own)
                continue
            tables = _DETECTOR_PATTERN_TABLES.get(type(detector).__name__)
            module = sys.modules.get(type(detector).__module__)
            if tables is None or module is None:
                return None
            for table_name in tables:
                table = getattr(module, table_name, None)
                if not isinstance(table, (list, tuple)):
                    return None
                for entry in table:
                    pattern = entry[0] if isinstance(entry, tuple) else entry
                    if not isinstance(pattern, re.Pattern):
                        return None
                    value_patterns.append(pattern)
    except (AttributeError, TypeError):
        return None
    value_screen = _literal_screen(value_patterns)
    compact_screen = _literal_screen([pattern for pattern, _, _ in _COMPACT_SPLIT_RULES])
    return (*value_screen, *compact_screen)


_QUERY_WINDOW_SCREEN = _query_window_screen()


def _window_form_scan_needed(
    first_literals: frozenset[str],
    refinements: dict[str, list[tuple[frozenset[str], ...]]],
    unscreened: tuple[re.Pattern[str], ...],
    text: str,
    lowered: str,
) -> bool:
    """True when some pattern of this form could match the text."""
    for literal in first_literals:
        if literal not in lowered:
            continue
        for stages in refinements[literal]:
            if all(any(option in lowered for option in stage) for stage in stages):
                return True
    return any(pattern.search(text) for pattern in unscreened)
