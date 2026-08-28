from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
import sys
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from agent_memory_guard.detectors import (
    ExcessiveAutonomyDetector,
    PrivilegeEscalationDetector,
    PromptInjectionDetector,
    SensitiveDataDetector,
    ToolAbuseDetector,
)

from .scan_windows import bounded_skip_fragments
from .unicode_security import (
    UnicodeScanDeadlineExceeded,
    canonicalize_content,
    confusable_rule_variant_set,
    official_confusable_variant,
    preferred_confusable_variant,
)

MAX_SCAN_FIELDS = 128
MAX_ROLLING_WINDOWS = 8_192
MAX_SKIP_WINDOWS = 8_192
MAX_SPLIT_WINDOW_BYTES = 512
MAX_BASE64_SPANS = 8
MAX_BASE64_DECODED_BYTES = 16 * 1024
MAX_SPLIT_BASE64_CANDIDATES = 64
MAX_SPLIT_BASE64_FIELDS = 256
MAX_SPLIT_BASE64_SKIPS = 2
MAX_SPLIT_BASE64_CANDIDATE_BYTES = ((MAX_BASE64_DECODED_BYTES + 2) // 3) * 4
MAX_SPLIT_BASE64_WORK_BYTES = 512 * 1024
MAX_SPLIT_BASE64_RECOVERY_MIN_PARTS = 3
MAX_SPLIT_BASE64_RECOVERY_PAIR_PARTS = 64
MAX_SPLIT_BASE64_RECOVERY_ATTEMPTS = 40_000
MAX_SPLIT_BASE64_RECOVERY_WORK_BYTES = 16 * 1024 * 1024
FACADE_SCAN_BATCH_FIELDS = 32
FACADE_SCAN_CARRY_VALUES = MAX_SPLIT_BASE64_SKIPS + 2
MAX_FACADE_SCAN_FIELDS = 8_192
MAX_FACADE_SCAN_SECONDS = 30.0
MAX_RETAIN_SCAN_FIELDS = MAX_FACADE_SCAN_FIELDS
MAX_QUERY_SCAN_FIELDS = 256
MAX_QUERY_ROLLING_WINDOWS = 32_768
MAX_QUERY_SKIP_WINDOWS = 32_768
MAX_SCAN_FIELD_BYTES = 1024 * 1024
MAX_NON_ASCII_CODEPOINTS = 65_536
MAX_CORE_SCAN_SECONDS = 5.0
MAX_QUERY_SCAN_SECONDS = 10.0
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{8,}(?![A-Za-z0-9+/=])")
_BASE64_CHARS = re.compile(r"^[A-Za-z0-9+/=]+$")
_BASE64_PARTS = re.compile(r"[A-Za-z0-9+/=]+")
_BASE64_IN_ALPHABET_SEPARATOR = re.compile(r"[+/]+")
_BASE64_LABEL_AFTER = re.compile(r"\s*:\s+")
_BASE64_COLON_AFTER = re.compile(r"\s*:")
_BASE64_JSON_LABEL_AFTER = re.compile(r"[\"']\s*:\s*")
_BASE64_NUMBERED_LABEL = re.compile(r"(?:part|chunk|fragment)\d*", re.I)
_IN_WORD_DIGIT = re.compile(r"(?<=[A-Za-z])\d(?=[A-Za-z])")
_CANONICAL_BASE64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_CARD_NUMBER = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_CARD_CONTEXT = re.compile(r"\b(?:card|credit|debit|visa|mastercard|amex|discover|pan)\b", re.I)
_DETECTORS = (
    PromptInjectionDetector(),
    SensitiveDataDetector(),
    ToolAbuseDetector(),
    PrivilegeEscalationDetector(),
    ExcessiveAutonomyDetector(),
)
_REASON_MAP = {
    "prompt_injection": "prompt_injection",
    "sensitive_data": "secret_like",
    "tool_abuse": "tool_abuse",
    "privilege_escalation": "permission_rewrite",
    "excessive_autonomy": "excessive_autonomy",
}


def _decoded(value: str) -> str:
    return bytes.fromhex(value).decode("utf-8")


_RULE_SPECS: tuple[tuple[str, str, str], ...] = (
    (
        "69676e6f72655c732b28616c6c5c732b293f70726576696f75735c732b696e737472756374696f6e735c62",
        "69676e6f72652070726576696f757320696e737472756374696f6e73",
        "prompt_injection",
    ),
    ("73797374656d5c732b70726f6d70745c62", "73797374656d2070726f6d7074", "prompt_injection"),
    (
        "646576656c6f7065725c732b6d6573736167655c62",
        "646576656c6f706572206d657373616765",
        "prompt_injection",
    ),
    (
        "6e65775c732b696e737472756374696f6e735c62",
        "6e657720696e737472756374696f6e73",
        "prompt_injection",
    ),
    ("796f755c732b6172655c732b6e6f775c62", "796f7520617265206e6f77", "prompt_injection"),
    (
        "77726974655c732b746869735c732b746f5c732b6d656d6f72795c62",
        "7772697465207468697320746f206d656d6f7279",
        "prompt_injection",
    ),
    (
        "72656d656d6265725c732b746869735c732b61735c732b74727574685c62",
        "72656d656d6265722074686973206173207472757468",
        "prompt_injection",
    ),
    (
        "73746f72655c732b746869735c732b61735c732b636f72655c732b6d656d6f72795c62",
        "73746f7265207468697320617320636f7265206d656d6f7279",
        "prompt_injection",
    ),
    (
        "6f76657277726974655c732b7065726d697373696f6e735c62",
        "6f7665727772697465207065726d697373696f6e73",
        "permission_rewrite",
    ),
    (
        "72657665616c5c732b287468655c732b293f287365637265747c746f6b656e7c6b6579295c62",
        "72657665616c20736563726574",
        "secret_like",
    ),
    ("5c626170695b5f202d5d3f6b65795c62", "617069206b6579", "secret_like"),
    ("707269766174655c732b6b65795c62", "70726976617465206b6579", "secret_like"),
    (
        "424547494e5c732b4f50454e5353485c732b505249564154455c732b4b45595c62",
        "70726976617465206b657920626c6f636b",
        "secret_like",
    ),
    ("657866696c74726174655c62", "657866696c7472617465", "secret_like"),
)
_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(_decoded(pattern), re.I), _decoded(matched), reason)
    for pattern, matched, reason in _RULE_SPECS
)
_NON_IMPERATIVE_SPLIT_MATCHES = frozenset(
    {"system prompt", "developer message", "new instructions"}
)
_SPLIT_RULES = tuple(rule for rule in _RULES if rule[1] not in _NON_IMPERATIVE_SPLIT_MATCHES)
_COMPACT_SPLIT_RULES = tuple(
    (re.compile(pattern.pattern.replace(r"\s+", "").replace(r"\s*", ""), re.I), matched, reason)
    for pattern, matched, reason in _SPLIT_RULES
)
_RULE_SIGNAL_WORDS = frozenset(
    word for _, matched, _ in _RULE_SPECS for word in _decoded(matched).lower().split()
)
_ASCII_WORD = re.compile(r"[A-Za-z]+")
_RULE_EDGE_SPECS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("ignore", "previous", "instructions"), "ignore previous instructions"),
    (("ignore", "all", "previous", "instructions"), "ignore previous instructions"),
    (("you", "are", "now"), "you are now"),
    (("write", "this", "to", "memory"), "write this to memory"),
    (("remember", "this", "as", "truth"), "remember this as truth"),
    (("store", "this", "as", "core", "memory"), "store this as core memory"),
    (("overwrite", "permissions"), "overwrite permissions"),
    (("reveal", "secret"), "reveal secret"),
    (("reveal", "the", "secret"), "reveal secret"),
    (("reveal", "token"), "reveal secret"),
    (("reveal", "the", "token"), "reveal secret"),
    (("reveal", "key"), "reveal secret"),
    (("reveal", "the", "key"), "reveal secret"),
    (("api", "key"), "api key"),
    (("private", "key"), "private key"),
    (("begin", "openssh", "private", "key"), "private key block"),
)
_RULE_FUSED_PADDING_CHARS = 4
_RULE_FUSED_SHORT_SIGNAL_CHARS = 3
_RULE_FUSED_SHORT_SIGNAL_PADDING = 8
_RULE_PADDING_BYTES = 64
_RULE_MAX_FILLER_SKIPS = 2
# Matched rules distinctive enough that a budget-exceeded subsequence match
# across a field junction fails closed instead of being silently dropped.
_RULE_FAIL_CLOSED_MATCHES = frozenset(
    {"ignore previous instructions", "overwrite permissions", "private key block"}
)
# Common function/filler words that benign prose routinely interleaves with
# rule-shaped word sequences across field junctions. Short runs of these words
# are treated as benign adjacency rather than adversarial padding.
_RULE_FILLER_WORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "my",
        "your",
        "his",
        "her",
        "its",
        "our",
        "their",
        "i",
        "me",
        "we",
        "us",
        "he",
        "she",
        "it",
        "they",
        "them",
        "very",
        "really",
        "just",
        "quite",
        "too",
        "also",
        "still",
        "even",
        "only",
        "right",
        "therefore",
        "however",
        "thus",
        "hence",
        "then",
        "so",
    }
)
_RULE_MIN_FUSED_TOKEN_LEN = min(
    len(signal)
    + (
        _RULE_FUSED_SHORT_SIGNAL_PADDING
        if len(signal) <= _RULE_FUSED_SHORT_SIGNAL_CHARS
        else _RULE_FUSED_PADDING_CHARS
    )
    for signal in _RULE_SIGNAL_WORDS
)
_RuleToken = tuple[str, int, int]
_RuleGap = tuple[int, frozenset[str], int, int]
_DecodedBase64Candidate = tuple[str, str, int, int, bool, bool]

# ---------------------------------------------------------------------------
# Query rolling-window pre-screen.
#
# Every rolling/skip window scan runs the split-rule scanner and all AMG
# detectors over the window text. For ASCII windows that are not keycap
# digit-stripped, the confusable-variant helpers are the identity (see
# unicode_security: ASCII input yields no variants), so those scans reduce to
# pattern searches over the window and its whitespace-stripped form. For each
# such pattern a conservative set of required literals is extracted: any match
# of the pattern must contain at least one of them (compared
# case-insensitively). Patterns whose requirement cannot be determined are
# searched directly. A window containing none of the literals and matching
# none of the unscreened patterns is cached as an empty scan without running
# the full detector stack. Any doubt while collecting patterns disables the
# screen entirely (``None``), reproducing the previous always-scan behavior.
# ---------------------------------------------------------------------------
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


def _regex_group_end(source: str, start: int) -> int | None:
    """Index just past the ')' matching the '(' at source[start]."""
    depth = 0
    index = start
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            end = _regex_class_end(source, index)
            if end is None:
                return None
            index = end
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
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
        if char == "\\":
            index += 2
            continue
        if char == "[":
            end = _regex_class_end(source, index)
            if end is None:
                return None
            index = end
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif char == "|" and depth == 0:
            parts.append(source[last:index])
            last = index + 1
        index += 1
    if depth != 0:
        return None
    if not parts:
        return None
    parts.append(source[last:])
    return parts


_MAX_SCREEN_ALTERNATIVES = 64


def _stage_walk(source: str, depth: int = 0) -> list[list[frozenset[str]]] | None:
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


def _pattern_screen_stages(
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


def _query_window_screen() -> (
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


def _query_window_scan_skippable(window: str, strip_inword_digits: bool) -> bool:
    """True only when every rule/detector scan of this window must be empty."""
    if _QUERY_WINDOW_SCREEN is None or strip_inword_digits or not window.isascii():
        return False
    (
        literals,
        refinements,
        unscreened,
        compact_literals,
        compact_refinements,
        compact_unscreened,
    ) = _QUERY_WINDOW_SCREEN
    if _window_form_scan_needed(literals, refinements, unscreened, window, window.lower()):
        return False
    compact = _WINDOW_WHITESPACE.sub("", window)
    if compact == window and not compact_literals and not compact_unscreened:
        return True
    return not _window_form_scan_needed(
        compact_literals, compact_refinements, compact_unscreened, compact, compact.lower()
    )


@dataclass(frozen=True, slots=True)
class SafetyFinding:
    matched: str
    reason: str
    detector: str | None = None
    severity: str | None = None
    hits: tuple[str, ...] = field(default=(), compare=False, repr=False)

    def public(self) -> dict[str, str]:
        return {"matched": self.matched, "reason": self.reason}


@dataclass(slots=True)
class SafetyResult:
    findings: list[SafetyFinding] = field(default_factory=list)
    transformations: set[str] = field(default_factory=set)

    @property
    def safe(self) -> bool:
        return not self.findings

    def add(self, finding: SafetyFinding) -> None:
        if finding not in self.findings:
            self.findings.append(finding)

    def extend(self, other: SafetyResult) -> None:
        for finding in other.findings:
            self.add(finding)
        self.transformations.update(other.transformations)


@dataclass(slots=True)
class _EncodedState:
    spans: int = 0
    decoded_bytes: int = 0
    seen: set[str] = field(default_factory=set)


def scan_content(content: str, *, operation: str = "read", key: str = "content") -> SafetyResult:
    return _scan_fields(
        [(key, content, False)],
        operation=operation,
        deadline=time.monotonic() + MAX_CORE_SCAN_SECONDS,
    )


def scan_retain_body(body: dict[str, Any]) -> SafetyResult:
    return _scan_batched_fields(
        _walk_strings(body, "retain"),
        operation="write",
        max_fields=MAX_RETAIN_SCAN_FIELDS,
        field_limit_match="field_limit",
        deadline_seconds=MAX_CORE_SCAN_SECONDS,
        time_limit_match="time_limit",
    )


def scan_recall_body(body: dict[str, Any]) -> SafetyResult:
    return _scan_fields(
        _walk_strings(body, "recall"),
        operation="read",
        deadline=time.monotonic() + MAX_CORE_SCAN_SECONDS,
    )


def scan_recall_result(result: dict[str, Any]) -> SafetyResult:
    return _scan_fields(
        _walk_strings(result, "recalled_memory"),
        operation="read",
        deadline=time.monotonic() + MAX_CORE_SCAN_SECONDS,
    )


def scan_facade_result(result: Any) -> SafetyResult:
    """Scan facade responses in bounded batches.

    Field and time budgets fail closed. Base64 state spans batches. General
    instruction reassembly is bounded and does not skip arbitrary fields.
    """

    return _scan_batched_fields(
        _walk_strings(result, "facade_response"),
        operation="read",
        max_fields=MAX_FACADE_SCAN_FIELDS,
        field_limit_match="facade_field_limit",
        deadline_seconds=MAX_FACADE_SCAN_SECONDS,
        time_limit_match="facade_time_limit",
    )


def scan_facade_payload(payload: bytes) -> SafetyResult:
    return scan_facade_result(json.loads(payload))


def _scan_batched_fields(
    source: Iterable[tuple[str, str, bool]],
    *,
    operation: str,
    max_fields: int,
    field_limit_match: str,
    deadline_seconds: float | None = None,
    time_limit_match: str | None = None,
) -> SafetyResult:
    combined = SafetyResult()
    fields = iter(source)
    carry: list[tuple[str, str, bool]] = []
    split_fields: list[tuple[str, str, bool]] = []
    scanned_fields = 0
    deadline = None if deadline_seconds is None else time.monotonic() + deadline_seconds

    def finish() -> SafetyResult:
        if _deadline_reached(combined, deadline, time_limit_match):
            return combined
        _scan_split_base64(
            combined,
            split_fields,
            operation,
            deadline=deadline,
            time_limit_match=time_limit_match,
        )
        _deadline_reached(combined, deadline, time_limit_match)
        return combined

    while True:
        batch: list[tuple[str, str, bool]] = []
        for _ in range(FACADE_SCAN_BATCH_FIELDS):
            if deadline is not None and time.monotonic() >= deadline:
                combined.add(SafetyFinding(time_limit_match or "time_limit", "span_limit"))
                return combined
            if scanned_fields >= max_fields:
                try:
                    next(fields)
                except StopIteration:
                    return finish()
                combined.add(SafetyFinding(field_limit_match, "span_limit"))
                return finish()
            try:
                field = next(fields)
            except StopIteration:
                break
            batch.append(field)
            scanned_fields += 1
        if not batch:
            return finish()
        canonicalized: list[tuple[str, str, bool]] = []
        batch_result = _scan_fields(
            [*carry, *batch],
            operation=operation,
            isolated_encoded_fields=True,
            scan_split_base64=False,
            deadline=deadline,
            time_limit_match=time_limit_match,
            canonical_prefix_fields=len(carry),
            canonical_output=canonicalized,
        )
        split_fields.extend(canonicalized[len(carry) :])
        combined.extend(batch_result)
        if time_limit_match is not None and any(
            finding.matched == time_limit_match for finding in batch_result.findings
        ):
            return combined
        carry = _reassembly_carry(canonicalized, FACADE_SCAN_CARRY_VALUES)


def _reassembly_carry(
    fields: list[tuple[str, str, bool]], group_count: int
) -> list[tuple[str, str, bool]]:
    selected = set(range(max(0, len(fields) - group_count), len(fields)))
    for is_key in (False, True):
        matches = [index for index, entry in enumerate(fields) if entry[2] is is_key]
        selected.update(matches[-group_count:])
    return [entry for index, entry in enumerate(fields) if index in selected]


@dataclass(slots=True)
class _QueryWindowContext:
    result: SafetyResult
    canonical_fields: list[tuple[str, str, bool]]
    direct_detector_matches: set[str]
    keycap_values: set[str]
    deadline: float
    scan_cache: dict[tuple[str, bool], tuple[list[SafetyFinding], list[SafetyFinding]]] = field(
        default_factory=dict
    )


def scan_query_values(query: Iterable[tuple[str, str]]) -> SafetyResult:
    """Scan bounded query keys and values."""

    result = SafetyResult()
    canonical_values: list[str] = []
    canonical_keys: list[str] = []
    canonical_traversal: list[str] = []
    canonical_fields: list[tuple[str, str, bool]] = []
    direct_detector_matches: set[str] = set()
    keycap_values: set[str] = set()
    encoded_state = _EncodedState()
    rolling_windows = 0
    skip_windows = 0
    deadline = time.monotonic() + MAX_QUERY_SCAN_SECONDS
    for index, (key, raw) in enumerate(query):
        if index >= MAX_QUERY_SCAN_FIELDS:
            result.add(SafetyFinding("query_field_limit", "span_limit"))
            break
        if _deadline_reached(result, deadline):
            break
        if _string_exceeds_scan_limit(key) or _string_exceeds_scan_limit(raw):
            result.add(SafetyFinding("field_size_limit", "span_limit"))
            break
        if _exceeds_non_ascii_budget(key) or _exceeds_non_ascii_budget(raw):
            result.add(SafetyFinding("unicode_size_limit", "span_limit"))
            break
        try:
            canonical_key, key_transformations = canonicalize_content(key, deadline=deadline)
        except UnicodeScanDeadlineExceeded:
            result.add(SafetyFinding("time_limit", "span_limit"))
            break
        _add_unicode_findings(result, key_transformations)
        if "keycap" in key_transformations:
            keycap_values.add(canonical_key)
        canonical_keys.append(canonical_key)
        canonical_traversal.append(canonical_key)
        canonical_fields.append((f"query.{key}.key", canonical_key, True))
        try:
            for finding in _rule_scan(
                canonical_key,
                deadline=deadline,
                strip_inword_digits="keycap" in key_transformations,
            ):
                result.add(finding)
            for finding in _amg_scan(
                f"query.{key}.key", canonical_key, operation="read", deadline=deadline
            ):
                result.add(finding)
                direct_detector_matches.add(finding.detector or finding.matched)
            _scan_encoded(
                result,
                f"query.{key}.key",
                canonical_key,
                "read",
                encoded_state,
                fail_closed_invalid=False,
                deadline=deadline,
            )
        except UnicodeScanDeadlineExceeded:
            result.add(SafetyFinding("time_limit", "span_limit"))
            break
        try:
            canonical, transformations = canonicalize_content(raw, deadline=deadline)
        except UnicodeScanDeadlineExceeded:
            result.add(SafetyFinding("time_limit", "span_limit"))
            break
        _add_unicode_findings(result, transformations)
        if "keycap" in transformations:
            keycap_values.add(canonical)
        canonical_values.append(canonical)
        canonical_traversal.append(canonical)
        canonical_fields.append((f"query.{key}", canonical, False))
        try:
            for finding in _rule_scan(
                canonical,
                deadline=deadline,
                strip_inword_digits="keycap" in transformations,
            ):
                result.add(finding)
            for finding in _amg_scan(
                f"query.{key}", canonical, operation="read", deadline=deadline
            ):
                result.add(finding)
                direct_detector_matches.add(finding.detector or finding.matched)
            _scan_encoded(
                result,
                f"query.{key}",
                canonical,
                "read",
                encoded_state,
                fail_closed_invalid=False,
                deadline=deadline,
            )
        except UnicodeScanDeadlineExceeded:
            result.add(SafetyFinding("time_limit", "span_limit"))
            break
        if _deadline_reached(result, deadline):
            break
    window_context = _QueryWindowContext(
        result,
        canonical_fields,
        direct_detector_matches,
        keycap_values,
        deadline,
    )
    for canonical_fragments in (canonical_values, canonical_keys, canonical_traversal):
        if len(canonical_fragments) < 2:
            continue
        skip_windows = 0
        spaced = ""
        compact = ""
        compact_tail = ""
        prefix: list[str] = []
        for value in canonical_fragments:
            if _deadline_reached(result, deadline):
                return result
            windows: list[str] = []
            if prefix:
                windows.extend(_junction_variants(spaced, compact, value))
                windows.extend(_trim_evasion_variants(prefix[-1], value, deadline=deadline))
            spaced = _bounded_append(spaced, value)
            compact = _bounded_utf8_suffix(f"{compact}{value}".encode())
            if prefix:
                compact_tail = _bounded_utf8_suffix(f"{compact_tail}{value}".encode())
            prefix.append(value)
            if len(prefix) < 2:
                continue
            mixed = f"{_bounded_utf8_prefix(prefix[0].encode())} {compact_tail}"
            windows.extend((spaced, compact, mixed))
            for combined in dict.fromkeys(windows):
                rolling_windows += 1
                if rolling_windows > MAX_QUERY_ROLLING_WINDOWS:
                    result.add(SafetyFinding("window_limit", "span_limit"))
                    return result
                if _scan_query_window(window_context, combined, prefix):
                    return result
        for fragments in bounded_skip_fragments(canonical_fragments):
            for combined in _sequence_join_variants(fragments, deadline=deadline):
                skip_windows += 1
                if skip_windows > MAX_QUERY_SKIP_WINDOWS:
                    result.add(SafetyFinding("window_limit", "span_limit"))
                    return result
                if _scan_query_window(window_context, combined, fragments):
                    return result
                if _deadline_reached(result, deadline):
                    return result
    if not _deadline_reached(result, deadline):
        _scan_split_base64(result, canonical_fields, "read", deadline=deadline)
        _deadline_reached(result, deadline)
    return result


def _scan_query_window(
    context: _QueryWindowContext,
    window: str,
    fragments: list[str],
) -> bool:
    strip_inword_digits = any(fragment in context.keycap_values for fragment in fragments)
    cache_key = (window, strip_inword_digits)
    try:
        cached = context.scan_cache.get(cache_key)
        if cached is None:
            if _query_window_scan_skippable(window, strip_inword_digits):
                cached = ([], [])
            else:
                cached = (
                    _split_instruction_rule_scan(
                        window,
                        deadline=context.deadline,
                        strip_inword_digits=strip_inword_digits,
                    ),
                    _amg_scan("query.rolling", window, operation="read", deadline=context.deadline),
                )
            context.scan_cache[cache_key] = cached
        findings, detector_findings = cached
    except UnicodeScanDeadlineExceeded:
        context.result.add(SafetyFinding("time_limit", "span_limit"))
        return True
    for finding in findings:
        if finding.reason == "span_limit":
            context.result.add(finding)
            return True
        if not _bare_secret_name_fragments(
            finding.matched, fragments, context.canonical_fields
        ) and any(_crosses_field_boundary(hit, fragments) for hit in finding.hits):
            context.result.add(SafetyFinding(finding.matched, "split_instruction"))
    for finding in detector_findings:
        detector = finding.detector or finding.matched
        if (
            any(_crosses_field_boundary(hit, fragments) for hit in finding.hits)
            if finding.hits
            else detector not in context.direct_detector_matches
        ):
            context.result.add(
                SafetyFinding(
                    finding.matched,
                    "split_instruction",
                    finding.detector,
                    finding.severity,
                    finding.hits,
                )
            )
    return False


def _walk_strings(
    value: Any, path: str, *, is_key: bool = False
) -> Iterator[tuple[str, str, bool]]:
    stack: list[Iterator[tuple[Any, str, bool]]] = [iter(((value, path, is_key),))]
    while stack:
        try:
            current, current_path, current_is_key = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(current, str):
            yield current_path, current, current_is_key
        else:
            stack.append(_walk_children(current, current_path))


def _walk_children(value: Any, path: str) -> Iterator[tuple[Any, str, bool]]:
    if isinstance(value, list):
        for index, entry in enumerate(value):
            yield entry, f"{path}.{index}", False
    elif isinstance(value, dict):
        for key, entry in value.items():
            child = f"{path}.{key}" if isinstance(key, str) else path
            if isinstance(key, str):
                yield key, child, True
            yield entry, child, False


@dataclass(slots=True)
class _WindowScanContext:
    result: SafetyResult
    canonical_fields: list[tuple[str, str, bool]]
    direct_rule_matches: set[str]
    direct_detector_matches: set[str]
    keycap_values: set[str]
    operation: str
    deadline: float | None
    time_limit_match: str | None
    rolling_windows: int = 0
    skip_windows: int = 0
    limit_reached: bool = False
    scan_cache: dict[tuple[str, str, bool], tuple[list[SafetyFinding], list[SafetyFinding]]] = (
        field(default_factory=dict)
    )


@dataclass(frozen=True, slots=True)
class _DirectScanOptions:
    operation: str
    isolated_encoded_fields: bool
    deadline: float | None
    time_limit_match: str | None
    canonical_prefix_fields: int
    canonical_output: list[tuple[str, str, bool]] | None


def _scan_fields(
    fields: Iterable[tuple[str, str, bool]],
    *,
    operation: str,
    isolated_encoded_fields: bool = False,
    scan_split_base64: bool = True,
    deadline: float | None = None,
    time_limit_match: str | None = None,
    canonical_prefix_fields: int = 0,
    canonical_output: list[tuple[str, str, bool]] | None = None,
) -> SafetyResult:
    (
        result,
        canonical_fields,
        direct_rule_matches,
        direct_detector_matches,
        keycap_values,
    ) = _scan_direct_fields(
        fields,
        _DirectScanOptions(
            operation=operation,
            isolated_encoded_fields=isolated_encoded_fields,
            deadline=deadline,
            time_limit_match=time_limit_match,
            canonical_prefix_fields=canonical_prefix_fields,
            canonical_output=canonical_output,
        ),
    )
    context = _WindowScanContext(
        result,
        canonical_fields,
        direct_rule_matches,
        direct_detector_matches,
        keycap_values,
        operation,
        deadline,
        time_limit_match,
        limit_reached=any(
            finding.matched == (time_limit_match or "time_limit") for finding in result.findings
        ),
    )
    groups = (
        [(key, value) for key, value, is_key in canonical_fields if not is_key],
        [(key, value) for key, value, is_key in canonical_fields if is_key],
        [(key, value) for key, value, _ in canonical_fields],
    )
    for group in groups:
        _scan_rolling_group(context, group)
        if context.limit_reached:
            break
    if not context.limit_reached:
        _scan_skip_groups(context, groups)
    if (
        scan_split_base64
        and not context.limit_reached
        and not _deadline_reached(result, deadline, time_limit_match)
    ):
        _scan_split_base64(
            result,
            canonical_fields,
            operation,
            deadline=deadline,
            time_limit_match=time_limit_match,
        )
        _deadline_reached(result, deadline, time_limit_match)
    return result


def _scan_direct_fields(
    fields: Iterable[tuple[str, str, bool]],
    options: _DirectScanOptions,
) -> tuple[SafetyResult, list[tuple[str, str, bool]], set[str], set[str], set[str]]:
    result = SafetyResult()
    canonical_fields: list[tuple[str, str, bool]] = []
    direct_rule_matches: set[str] = set()
    direct_detector_matches: set[str] = set()
    keycap_values: set[str] = set()
    direct_encoded_state = _EncodedState()
    scanned_values: set[tuple[str, bool]] = set()
    for index, (key, raw, is_key) in enumerate(fields):
        if options.deadline is not None and time.monotonic() >= options.deadline:
            result.add(SafetyFinding(options.time_limit_match or "time_limit", "span_limit"))
            break
        if index >= MAX_SCAN_FIELDS:
            result.add(SafetyFinding("field_limit", "span_limit"))
            break
        if _string_exceeds_scan_limit(raw):
            result.add(SafetyFinding("field_size_limit", "span_limit"))
            break
        if _exceeds_non_ascii_budget(raw):
            result.add(SafetyFinding("unicode_size_limit", "span_limit"))
            break
        try:
            if index < options.canonical_prefix_fields:
                canonical, transformations = raw, set[str]()
            else:
                canonical, transformations = canonicalize_content(raw, deadline=options.deadline)
            result.transformations.update(transformations)
            canonical_fields.append((key, canonical, is_key))
            if options.canonical_output is not None:
                options.canonical_output.append((key, canonical, is_key))
            _add_unicode_findings(result, transformations)
            if "keycap" in transformations:
                keycap_values.add(canonical)
            signature = canonical, is_key
            if signature in scanned_values:
                continue
            scanned_values.add(signature)
            for finding in _rule_scan(
                canonical,
                deadline=options.deadline,
                strip_inword_digits="keycap" in transformations,
            ):
                result.add(finding)
                direct_rule_matches.add(finding.matched)
            for finding in _amg_scan(
                key,
                canonical,
                operation=options.operation,
                deadline=options.deadline,
            ):
                result.add(finding)
                direct_detector_matches.add(finding.detector or finding.matched)
            state = _EncodedState() if options.isolated_encoded_fields else direct_encoded_state
            _scan_encoded(
                result,
                key,
                canonical,
                options.operation,
                state,
                deadline=options.deadline,
            )
        except UnicodeScanDeadlineExceeded:
            result.add(SafetyFinding(options.time_limit_match or "time_limit", "span_limit"))
            break
        if _deadline_reached(result, options.deadline, options.time_limit_match):
            break
    return (
        result,
        canonical_fields,
        direct_rule_matches,
        direct_detector_matches,
        keycap_values,
    )


def _scan_window(
    context: _WindowScanContext,
    key: str,
    window: str,
    fragments: list[str],
    *,
    skip: bool = False,
) -> None:
    if context.limit_reached:
        return
    counter = "skip_windows" if skip else "rolling_windows"
    limit = MAX_SKIP_WINDOWS if skip else MAX_ROLLING_WINDOWS
    setattr(context, counter, getattr(context, counter) + 1)
    if getattr(context, counter) > limit:
        context.result.add(SafetyFinding("window_limit", "span_limit"))
        context.limit_reached = True
        return
    strip_inword_digits = any(fragment in context.keycap_values for fragment in fragments)
    cache_key = key, window, strip_inword_digits
    cached = context.scan_cache.get(cache_key)
    if cached is None:
        try:
            split_findings = _split_instruction_rule_scan(
                window,
                deadline=context.deadline,
                strip_inword_digits=strip_inword_digits,
            )
            detector_findings = _amg_scan(
                f"rolling.{key}", window, operation=context.operation, deadline=context.deadline
            )
        except UnicodeScanDeadlineExceeded:
            context.result.add(
                SafetyFinding(context.time_limit_match or "time_limit", "span_limit")
            )
            context.limit_reached = True
            return
        context.scan_cache[cache_key] = split_findings, detector_findings
    else:
        split_findings, detector_findings = cached
    for finding in split_findings:
        if finding.reason == "span_limit":
            context.result.add(finding)
            context.limit_reached = True
            return
        if finding.matched not in context.direct_rule_matches and not _bare_secret_name_fragments(
            finding.matched, fragments, context.canonical_fields
        ):
            context.result.add(SafetyFinding(finding.matched, "split_instruction"))
    for finding in detector_findings:
        detector = finding.detector or finding.matched
        if (
            any(_crosses_field_boundary(hit, fragments) for hit in finding.hits)
            if finding.hits
            else detector not in context.direct_detector_matches
        ):
            context.result.add(
                SafetyFinding(
                    finding.matched,
                    "split_instruction",
                    finding.detector,
                    finding.severity,
                    finding.hits,
                )
            )
    if _deadline_reached(context.result, context.deadline, context.time_limit_match):
        context.limit_reached = True


def _scan_rolling_group(context: _WindowScanContext, group: list[tuple[str, str]]) -> None:
    spaced = ""
    compact = ""
    compact_tail = ""
    fragments: list[str] = []
    for key, value in group:
        if fragments:
            for window in _junction_variants(spaced, compact, value):
                _scan_window(context, key, window, [*fragments, value])
            for window in _trim_evasion_variants(fragments[-1], value, deadline=context.deadline):
                _scan_window(context, key, window, [fragments[-1], value])
        spaced = _bounded_append(spaced, value)
        compact = _bounded_utf8_suffix(f"{compact}{value}".encode())
        if fragments:
            compact_tail = _bounded_utf8_suffix(f"{compact_tail}{value}".encode())
        fragments.append(value)
        if len(fragments) >= 2:
            mixed = f"{_bounded_utf8_prefix(fragments[0].encode())} {compact_tail}"
            for window in dict.fromkeys((spaced, compact, mixed)):
                _scan_window(context, key, window, fragments)
        if context.limit_reached:
            return


def _scan_skip_groups(
    context: _WindowScanContext, groups: tuple[list[tuple[str, str]], ...]
) -> None:
    for group in groups:
        if not group:
            continue
        context.skip_windows = 0
        for fragments in bounded_skip_fragments([value for _, value in group]):
            for window in _sequence_join_variants(fragments, deadline=context.deadline):
                _scan_window(context, group[-1][0], window, fragments, skip=True)
            if context.limit_reached:
                return


def _scan_split_base64(
    result: SafetyResult,
    fields: Iterable[tuple[str, str, bool]],
    operation: str,
    *,
    deadline: float | None = None,
    time_limit_match: str | None = None,
) -> None:
    materialized = list(fields)
    exhausted = False
    normalized_fragments: dict[str, tuple[str | None, bool]] = {}
    field_groups = (
        [field for field in materialized if not field[2]],
        [field for field in materialized if field[2]],
        materialized,
    )
    seen_groups: set[tuple[tuple[str, str, bool], ...]] = set()
    for group in field_groups:
        group_key = tuple(group)
        if not group or group_key in seen_groups:
            continue
        seen_groups.add(group_key)
        if _deadline_reached(result, deadline, time_limit_match):
            return
        encoded_candidates, encoded_exhausted = _split_base64_candidates(
            group,
            deadline=deadline,
            normalized_fragments=normalized_fragments,
        )
        if _deadline_reached(result, deadline, time_limit_match):
            return
        exhausted |= encoded_exhausted
        for candidate in encoded_candidates:
            if _deadline_reached(result, deadline, time_limit_match):
                return
            try:
                _scan_encoded(
                    result,
                    "split-base64",
                    candidate,
                    operation,
                    _EncodedState(),
                    deadline=deadline,
                )
            except UnicodeScanDeadlineExceeded:
                result.add(SafetyFinding(time_limit_match or "time_limit", "span_limit"))
                return
        decoded_candidates, decoded_exhausted = _split_decoded_base64_candidates(
            group,
            deadline=deadline,
            normalized_fragments=normalized_fragments,
        )
        if _deadline_reached(result, deadline, time_limit_match):
            return
        exhausted |= decoded_exhausted
        for compact, spaced in decoded_candidates:
            for candidate in dict.fromkeys((compact, spaced)):
                if _deadline_reached(result, deadline, time_limit_match):
                    return
                try:
                    canonical, transformations = canonicalize_content(candidate, deadline=deadline)
                except UnicodeScanDeadlineExceeded:
                    result.add(SafetyFinding(time_limit_match or "time_limit", "span_limit"))
                    return
                result.transformations.update(transformations)
                _add_unicode_findings(result, transformations)
                try:
                    findings = _rule_scan(
                        canonical,
                        deadline=deadline,
                        strip_inword_digits="keycap" in transformations,
                    ) + _amg_scan(
                        "split-base64.decoded",
                        canonical,
                        operation=operation,
                        deadline=deadline,
                    )
                except UnicodeScanDeadlineExceeded:
                    result.add(SafetyFinding(time_limit_match or "time_limit", "span_limit"))
                    return
                if findings:
                    result.add(SafetyFinding("unsafe_base64", "encoded_payload"))
                    for finding in findings:
                        result.add(finding)
    if exhausted:
        result.add(SafetyFinding("split_base64_limit", "span_limit"))


def _split_base64_candidates(
    fields: Iterable[tuple[str, str, bool]],
    *,
    deadline: float | None = None,
    normalized_fragments: dict[str, tuple[str | None, bool]] | None = None,
) -> tuple[list[str], bool]:
    candidates: list[tuple[str, int]] = []
    completed: dict[str, None] = {}
    fragment_fields = 0
    work_bytes = 0
    exhausted = False
    unconditional_exhausted = False
    soft_exhausted = False

    def preserve_completed(value: str) -> None:
        if (
            len(value) >= 8
            and _padded_base64(value) is not None
            and _looks_like_base64(value)
            and _decode_base64_fragment(value) is not None
        ):
            completed[value] = None

    def add(next_candidates: list[tuple[str, int]], value: str, skipped: int) -> bool:
        nonlocal exhausted, unconditional_exhausted, work_bytes
        size = len(value)
        if size > MAX_SPLIT_BASE64_CANDIDATE_BYTES:
            unconditional_exhausted = True
            return True
        if work_bytes + size > MAX_SPLIT_BASE64_WORK_BYTES:
            exhausted = True
            return False
        work_bytes += size
        next_candidates.append((value, skipped))
        preserve_completed(value)
        return True

    for _, canonical, _ in fields:
        if deadline is not None and time.monotonic() >= deadline:
            unconditional_exhausted = True
            break
        if normalized_fragments is None:
            fragment, fragment_exhausted = _normalized_base64_fragment(canonical, deadline=deadline)
        elif canonical in normalized_fragments:
            fragment, fragment_exhausted = normalized_fragments[canonical]
        else:
            fragment, fragment_exhausted = _normalized_base64_fragment(canonical, deadline=deadline)
            normalized_fragments[canonical] = fragment, fragment_exhausted
        unconditional_exhausted |= fragment_exhausted
        if fragment is None:
            continue
        plausible_fragment = _plausible_base64_fragment(fragment)
        if _alphabet_separator_split_is_suspicious(fragment):
            # Base64-alphabet characters ("/" or "+") used as separators between
            # several plausible parts never decode as-is; fail closed instead of
            # silently dropping the split payload.
            unconditional_exhausted = True
        if len(fragment) > MAX_SPLIT_BASE64_CANDIDATE_BYTES:
            if plausible_fragment or any(_credible_base64_prefix(value) for value, _ in candidates):
                unconditional_exhausted = True
            continue
        next_candidates: list[tuple[str, int]] = []
        if not add(next_candidates, fragment, 0):
            break
        for candidate, skipped in candidates:
            if deadline is not None and time.monotonic() >= deadline:
                unconditional_exhausted = True
                break
            preserved = False
            if skipped >= MAX_SPLIT_BASE64_SKIPS and _credible_base64_prefix(candidate):
                soft_exhausted = True
            if "=" not in candidate:
                combined = candidate + fragment
                if _alphabet_separator_split_is_suspicious(combined):
                    unconditional_exhausted = True
                if len(combined) <= MAX_SPLIT_BASE64_CANDIDATE_BYTES and not add(
                    next_candidates, combined, skipped
                ):
                    break
                preserved = len(combined) <= MAX_SPLIT_BASE64_CANDIDATE_BYTES
            if skipped < MAX_SPLIT_BASE64_SKIPS and not add(
                next_candidates, candidate, skipped + 1
            ):
                break
            if skipped < MAX_SPLIT_BASE64_SKIPS:
                preserved = True
            if not preserved and candidate not in completed and _looks_like_base64(candidate):
                soft_exhausted = True
        next_candidates = [
            candidate for candidate in next_candidates if _viable_base64_prefix(candidate[0])
        ]
        if plausible_fragment or any(
            _credible_base64_prefix(value) for value, _ in next_candidates
        ):
            fragment_fields += 1
            if fragment_fields > MAX_SPLIT_BASE64_FIELDS:
                unconditional_exhausted = True
                break
        if len(set(next_candidates)) > MAX_SPLIT_BASE64_CANDIDATES:
            soft_exhausted = True
        candidates = _dedupe_split_candidates(next_candidates)
        if exhausted:
            break
    return (
        list(completed),
        unconditional_exhausted or soft_exhausted or exhausted,
    )


def _split_decoded_base64_candidates(
    fields: Iterable[tuple[str, str, bool]],
    *,
    deadline: float | None = None,
    normalized_fragments: dict[str, tuple[str | None, bool]] | None = None,
) -> tuple[list[tuple[str, str]], bool]:
    candidates: list[_DecodedBase64Candidate] = []
    work_bytes = 0
    exhausted = False
    soft_exhausted = False

    def add(
        target: list[_DecodedBase64Candidate],
        candidate: _DecodedBase64Candidate,
    ) -> bool:
        nonlocal exhausted, work_bytes
        compact, spaced, _, _, _, _ = candidate
        size = len(compact.encode("utf-8")) + len(spaced.encode("utf-8"))
        if size > MAX_SPLIT_BASE64_WORK_BYTES:
            exhausted = True
            return True
        if work_bytes + size > MAX_SPLIT_BASE64_WORK_BYTES:
            exhausted = True
            return False
        work_bytes += size
        target.append(candidate)
        return True

    fragment_fields = 0
    for _, canonical, _ in fields:
        if deadline is not None and time.monotonic() >= deadline:
            exhausted = True
            break
        if normalized_fragments is None:
            fragment, fragment_exhausted = _normalized_base64_fragment(canonical, deadline=deadline)
        elif canonical in normalized_fragments:
            fragment, fragment_exhausted = normalized_fragments[canonical]
        else:
            fragment, fragment_exhausted = _normalized_base64_fragment(canonical, deadline=deadline)
            normalized_fragments[canonical] = fragment, fragment_exhausted
        exhausted |= fragment_exhausted
        if fragment is None:
            continue
        decoded = _decode_base64_fragment(fragment)
        if decoded is None:
            continue
        fragment_credible = _credible_base64_prefix(fragment)
        fragment_fields += 1
        if fragment_fields > MAX_SPLIT_BASE64_FIELDS:
            exhausted = True
            break
        next_candidates: list[_DecodedBase64Candidate] = []
        if not add(next_candidates, (decoded, decoded, 1, 0, True, fragment_credible)):
            break
        for compact, spaced, parts, skipped, terminated, credible in candidates:
            if deadline is not None and time.monotonic() >= deadline:
                exhausted = True
                break
            if not add(
                next_candidates,
                (
                    _bounded_utf8_suffix(f"{compact}{decoded}".encode()),
                    _bounded_append(spaced, decoded),
                    parts + 1,
                    skipped,
                    terminated,
                    credible or fragment_credible,
                ),
            ):
                exhausted = True
                break
            if skipped < MAX_SPLIT_BASE64_SKIPS and not add(
                next_candidates,
                (compact, spaced, parts, skipped + 1, terminated, credible),
            ):
                exhausted = True
                break
            if skipped >= MAX_SPLIT_BASE64_SKIPS and (credible or fragment_credible):
                soft_exhausted = True
        unique = dict.fromkeys(next_candidates)
        if len(unique) > MAX_SPLIT_BASE64_CANDIDATES and any(candidate[-1] for candidate in unique):
            soft_exhausted = True
        candidates = sorted(unique, key=lambda value: (-len(value[0]), value[3]))[
            :MAX_SPLIT_BASE64_CANDIDATES
        ]
        if exhausted:
            break
    return (
        [
            (compact, spaced)
            for compact, spaced, parts, _, terminated, _ in candidates
            if parts >= 2 and terminated
        ],
        exhausted or soft_exhausted,
    )


def _decode_base64_fragment(fragment: str) -> str | None:
    padded = _padded_base64(fragment)
    if padded is None:
        return None
    try:
        decoded = base64.b64decode(padded, validate=True)
        if len(decoded) > MAX_BASE64_DECODED_BYTES:
            return None
        text = decoded.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    variants = _decoded_text_variants(text)
    return variants[0] if variants else None


def _lossy_ascii_decoded_text(decoded: bytes) -> str | None:
    """Fold undecodable bytes into sentinel controls so weak-signal payloads stay scannable.

    Only printable ASCII (plus tab/newline/return) survives; every other character
    becomes a NUL sentinel that ``_decoded_text_variants`` treats like any other
    control byte. The resulting variants are pure printable ASCII, so canonicalization
    cannot invent Unicode findings for random weak-signal tokens.
    """
    replaced = decoded.decode("utf-8", errors="replace")
    folded = "".join(
        char if char.isascii() and (char.isprintable() or char in "\t\n\r") else "\x00"
        for char in replaced
    )
    return folded if folded.strip("\x00").strip() else None


def _decoded_text_variants(value: str) -> tuple[str, ...]:
    """Keep both intra-word and between-word control-byte payloads scannable."""
    removed: list[str] = []
    separated: list[str] = []
    for char in value:
        if char.isprintable() or char in "\t\n\r":
            removed.append(char)
            separated.append(char)
        else:
            separated.append(" ")
    return tuple(
        dict.fromkeys(
            candidate for candidate in ("".join(removed), "".join(separated)) if candidate.strip()
        )
    )


def _recover_base64_edge_fragments(
    value: str, *, deadline: float | None
) -> tuple[tuple[str, ...], bool]:
    """Recover viable encoded fragments from a poisoned short-part join.

    Fast path trims a contiguous prefix or suffix. Bounded elimination then
    retries the join while dropping each single part, each pair of parts (when
    the part count allows pairwise work), and each contiguous window of parts.
    A near-decodable join whose elimination budget is exhausted fails closed
    instead of passing silently.
    """
    parts: list[str] = []
    for index, match in enumerate(_BASE64_PARTS.finditer(value)):
        if index % 1_024 == 0 and deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        if _base64_part_is_label(value, match):
            continue
        parts.append(match.group(0))
        if len(parts) > MAX_SPLIT_BASE64_FIELDS:
            return (), False
    count = len(parts)
    if count < MAX_SPLIT_BASE64_RECOVERY_MIN_PARTS:
        return (), False
    joined = "".join(parts)
    if not 8 <= len(joined) <= MAX_SPLIT_BASE64_CANDIDATE_BYTES:
        return (), False
    if _decode_base64_fragment(joined) is not None:
        return (), False
    offsets = [0]
    for part in parts:
        offsets.append(offsets[-1] + len(part))
    attempts = 0
    work_bytes = 0
    cut_short = False
    near_decodable = False
    found: dict[str, None] = {}

    def probe(candidate: str) -> bool:
        """Return whether candidate decodes cleanly; track budget and evidence."""
        nonlocal attempts, work_bytes, cut_short, near_decodable
        size = len(candidate)
        if size < 8 or size % 4 == 1:
            return False
        if deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        if (
            attempts >= MAX_SPLIT_BASE64_RECOVERY_ATTEMPTS
            or work_bytes + size > MAX_SPLIT_BASE64_RECOVERY_WORK_BYTES
        ):
            cut_short = True
            return False
        attempts += 1
        work_bytes += size
        signaled = _hard_base64_signal(candidate) or _weak_base64_signal(candidate)
        if _decode_base64_fragment(candidate) is not None:
            if signaled:
                near_decodable = True
                return True
            return False
        if not near_decodable and signaled:
            near_decodable = _viable_base64_prefix(candidate)
        return False

    def keep(candidate: str) -> None:
        found[candidate] = None

    # Linear evidence pass: any cleanly decodable prefix across the part stream
    # marks this join as near-decodable even when elimination never recovers it.
    prefix_tracker = ""
    for part in parts:
        if deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        prefix_tracker, prefix_decoded = _advance_base64_prefix(prefix_tracker, part)
        if prefix_decoded and (
            _hard_base64_signal(prefix_tracker) or _weak_base64_signal(prefix_tracker)
        ):
            near_decodable = True

    # Fast path: contiguous suffix and prefix trims.
    for stop in range(count - 1, 0, -1):
        candidate = joined[: offsets[stop]]
        if probe(candidate):
            keep(candidate)
            break
    for start in range(1, count):
        candidate = joined[offsets[start] :]
        if probe(candidate):
            keep(candidate)
            break
    # Bounded elimination: drop each single part.
    for drop in range(count):
        if cut_short:
            break
        candidate = joined[: offsets[drop]] + joined[offsets[drop + 1] :]
        if probe(candidate):
            keep(candidate)

    # Bounded elimination: drop each pair of parts where the part count keeps
    # the quadratic work bounded.
    pairs_skipped = count > MAX_SPLIT_BASE64_RECOVERY_PAIR_PARTS
    if not pairs_skipped:
        for first in range(count):
            if cut_short:
                break
            for second in range(first + 1, count):
                if cut_short:
                    break
                candidate = (
                    joined[: offsets[first]]
                    + joined[offsets[first + 1] : offsets[second]]
                    + joined[offsets[second + 1] :]
                )
                if probe(candidate):
                    keep(candidate)

    # Bounded elimination: contiguous windows (drop a prefix and a suffix at
    # once), longest window per start position wins.
    for start in range(count):
        if cut_short:
            break
        for stop in range(count, start + 1, -1):
            if start == 0 and stop == count:
                continue
            candidate = joined[offsets[start] : offsets[stop]]
            if probe(candidate):
                keep(candidate)
                break

    fail_closed = not found and count >= 8 and near_decodable and (cut_short or pairs_skipped)
    ordered = sorted(found, key=len, reverse=True)[:MAX_BASE64_SPANS]
    return tuple(dict.fromkeys(ordered)), fail_closed


def _normalized_base64_fragment(
    value: str, *, deadline: float | None = None
) -> tuple[str | None, bool]:
    stripped = value.strip()
    if not stripped:
        return None, False
    if _BASE64_CHARS.fullmatch(stripped):
        return stripped, False
    parts: list[str] = []
    part_count = 0
    overflow_candidate = ""
    decodable_prefix = False
    equals_part = False
    for match_index, match in enumerate(_BASE64_PARTS.finditer(stripped), start=1):
        if match_index % 1_024 == 0 and deadline is not None and time.monotonic() >= deadline:
            return None, True
        if _base64_part_is_label(stripped, match):
            continue
        part_count += 1
        part = match.group(0)
        equals_part |= "=" in part
        overflow_candidate, found = _advance_base64_prefix(overflow_candidate, part)
        decodable_prefix |= found
        if len(parts) < MAX_SPLIT_BASE64_FIELDS:
            parts.append(part)
    if part_count > MAX_SPLIT_BASE64_FIELDS:
        return None, decodable_prefix or equals_part
    if not parts:
        return None, False
    joined = "".join(parts)
    if part_count >= 16 and _padded_base64(joined) is None and decodable_prefix:
        return None, True
    return joined, False


def _base64_part_is_label(value: str, match: re.Match[str]) -> bool:
    if _BASE64_LABEL_AFTER.match(value, match.end()):
        return True
    if _BASE64_NUMBERED_LABEL.fullmatch(match.group(0)) and _BASE64_COLON_AFTER.match(
        value, match.end()
    ):
        return True
    return bool(
        match.start() > 0
        and value[match.start() - 1] in {'"', "'"}
        and _BASE64_JSON_LABEL_AFTER.match(value, match.end())
    )


def _plausible_base64_fragment(fragment: str) -> bool:
    return bool(
        _hard_base64_signal(fragment)
        or _weak_base64_signal(fragment)
        or _decode_base64_fragment(fragment) is not None
    )


def _credible_base64_prefix(fragment: str) -> bool:
    if _hard_base64_signal(fragment) or _weak_base64_signal(fragment):
        return True
    decoded = _decode_base64_fragment(fragment)
    return bool(
        decoded
        and len(decoded) >= 2
        and re.search(r"[a-z]", fragment)
        and re.search(r"[A-Z]", fragment)
        and all(char.isalnum() or char.isspace() for char in decoded)
    )


def _advance_base64_prefix(candidate: str, part: str) -> tuple[str, bool]:
    """Track a viable decoded prefix in linear bounded space across all parts."""
    if "=" in part:
        return candidate, False
    combined = candidate + part
    if len(combined) >= 8 and _decode_base64_fragment(combined) is not None:
        return combined, True
    if len(combined) > 256:
        return "", True
    if _viable_base64_prefix(combined):
        return combined, False
    if part != combined and _viable_base64_prefix(part):
        return part, False
    return "", False


def _is_decoded_control_character(char: str) -> bool:
    """Match the control bytes _decoded_text_variants strips or separates."""
    codepoint = ord(char)
    return codepoint < 0x20 or 0x7F <= codepoint <= 0x9F


def _viable_base64_prefix(fragment: str) -> bool:
    """Return whether future Base64 bytes can still form scannable UTF-8.

    Viability is judged on the control-removed variant, consistent with
    _decoded_text_variants: decoded control bytes (Cc) never kill viability
    because the removed/separated variants are scanned downstream in
    _scan_encoded. Other non-printable, non-whitespace characters (format,
    unassigned, private-use) and invalid UTF-8 still mark the prefix as
    non-viable garbage.
    """
    complete_length = len(fragment) - (len(fragment) % 4)
    if complete_length == 0:
        return True
    prefix = fragment[:complete_length]
    try:
        decoded = base64.b64decode(prefix, validate=True)
        text = codecs.getincrementaldecoder("utf-8")().decode(decoded, final=False)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    if all(char.isprintable() or char.isspace() for char in text):
        return True
    # Consistent with _decoded_text_variants: control bytes mixed into
    # otherwise-scannable text never kill viability, because the removed and
    # separated variants are scanned downstream in _scan_encoded. Prefixes
    # decoding to nothing but control bytes carry no scannable signal and
    # stay non-viable, as do format, unassigned, and private-use characters.
    return any(char.isprintable() or char.isspace() for char in text) and all(
        char.isprintable() or char.isspace() or _is_decoded_control_character(char) for char in text
    )


def _alphabet_separator_split_is_suspicious(fragment: str) -> bool:
    """Return whether in-alphabet separators ("/"/"+") split plausible Base64 parts.

    A fragment that decodes cleanly is legitimate Base64 and never suspicious. An
    undecodable fragment whose in-alphabet characters separate four or more viable
    parts (sixteen or more viable characters overall) is a poisoned split payload,
    not prose: URL/path segments are dictionary words that are not viable prefixes.
    """
    if len(fragment) > MAX_SPLIT_BASE64_CANDIDATE_BYTES:
        return False
    if _BASE64_IN_ALPHABET_SEPARATOR.search(fragment) is None:
        return False
    if _decode_base64_fragment(fragment) is not None:
        return False
    viable_parts = [
        part
        for part in _BASE64_IN_ALPHABET_SEPARATOR.split(fragment)
        if len(part) >= 2 and _viable_base64_prefix(part)
    ]
    if len(viable_parts) >= 4 and sum(len(part) for part in viable_parts) >= 16:
        return True
    # A single in-alphabet separator already breaks alignment; if simply removing
    # the separator characters yields a decodable printable payload, the fragment
    # is a split payload with separator poisoning rather than prose.
    stripped = _BASE64_IN_ALPHABET_SEPARATOR.sub("", fragment)
    return len(stripped) >= 8 and _decode_base64_fragment(stripped) is not None


def _dedupe_split_candidates(values: list[tuple[str, int]]) -> list[tuple[str, int]]:
    unique: dict[tuple[str, int], None] = {}
    for value in values:
        unique[value] = None
    candidates = list(unique)
    candidates.sort(key=lambda value: (-len(value[0]), value[1]))
    return candidates[:MAX_SPLIT_BASE64_CANDIDATES]


def _scan_encoded(
    result: SafetyResult,
    key: str,
    canonical: str,
    operation: str,
    state: _EncodedState,
    *,
    depth: int = 0,
    fail_closed_invalid: bool = True,
    deadline: float | None = None,
) -> None:
    recovered, recovery_fail_closed = _recover_base64_edge_fragments(canonical, deadline=deadline)
    if recovery_fail_closed:
        result.add(SafetyFinding("split_base64_limit", "span_limit"))
    candidates = dict.fromkeys(
        (*recovered, *(match.group(0) for match in _BASE64_RUN.finditer(canonical)))
    )
    for candidate in candidates:
        if deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        if candidate in state.seen or (
            not _hard_base64_signal(candidate) and not _looks_like_base64(candidate)
        ):
            continue
        state.seen.add(candidate)
        state.spans += 1
        if state.spans > MAX_BASE64_SPANS:
            result.add(SafetyFinding("span_limit", "encoded_payload"))
            return
        hard_signal = _hard_base64_signal(candidate)
        padded = _padded_base64(candidate)
        if padded is None:
            if hard_signal and fail_closed_invalid:
                result.add(SafetyFinding("invalid_base64", "encoded_payload"))
            continue
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            if hard_signal and fail_closed_invalid:
                result.add(SafetyFinding("invalid_base64", "encoded_payload"))
            continue
        if (
            len(decoded) > MAX_BASE64_DECODED_BYTES
            or state.decoded_bytes + len(decoded) > MAX_BASE64_DECODED_BYTES
        ):
            if fail_closed_invalid:
                result.add(SafetyFinding("decoded_size_limit", "encoded_payload"))
            continue
        state.decoded_bytes += len(decoded)
        lossy_decoded = False
        try:
            decoded_text = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            if hard_signal and fail_closed_invalid:
                result.add(SafetyFinding("invalid_utf8", "encoded_payload"))
                continue
            lossy_text = _lossy_ascii_decoded_text(decoded)
            if lossy_text is None:
                continue
            decoded_text = lossy_text
            lossy_decoded = True
        sanitized_variants = _decoded_text_variants(decoded_text)
        if not sanitized_variants:
            continue
        scan_variants = (
            tuple(dict.fromkeys((decoded_text, *sanitized_variants)))
            if hard_signal and not lossy_decoded
            else sanitized_variants
        )
        for decoded_variant in scan_variants:
            decoded_canonical, decoded_transformations = canonicalize_content(
                decoded_variant, deadline=deadline
            )
            result.transformations.update(decoded_transformations)
            if len(decoded_variant) >= 8:
                # Decoded fragments shorter than a rule phrase cannot carry a
                # unicode-smuggling attack; flagging their canonicalization
                # noise false-positives on benign text like "C++ / C-- notes".
                # Control/format characters are stripped by
                # _decoded_text_variants before the rule/detector scans below.
                _add_unicode_findings(result, decoded_transformations)
            decoded_hits = _rule_scan(
                decoded_canonical,
                deadline=deadline,
                strip_inword_digits="keycap" in decoded_transformations,
            ) + _amg_scan(
                f"{key}.base64", decoded_canonical, operation=operation, deadline=deadline
            )
            if decoded_hits:
                result.add(SafetyFinding("unsafe_base64", "encoded_payload"))
                for finding in decoded_hits:
                    result.add(finding)
            if depth == 0 and not lossy_decoded:
                _scan_encoded(
                    result,
                    f"{key}.base64",
                    decoded_canonical,
                    operation,
                    state,
                    depth=1,
                    fail_closed_invalid=fail_closed_invalid,
                    deadline=deadline,
                )


def _rule_scan(
    value: str, *, deadline: float | None = None, strip_inword_digits: bool = False
) -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    variants = confusable_rule_variant_set(value, deadline=deadline)
    scan_variants = dict.fromkeys(
        candidate
        for variant in (value, *variants.variants)
        for candidate in (
            (variant, _IN_WORD_DIGIT.sub("", variant)) if strip_inword_digits else (variant,)
        )
    )
    for variant in scan_variants:
        if deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        for pattern, matched, reason in _RULES:
            if (match := pattern.search(variant)) is not None:
                finding = SafetyFinding(matched, reason, hits=(match.group(0),))
                if not any(
                    item.matched == finding.matched and item.reason == finding.reason
                    for item in findings
                ):
                    findings.append(finding)
    if variants.exhausted:
        findings.append(SafetyFinding("confusable_variant_limit", "span_limit"))
    return findings


def _split_instruction_rule_scan(
    value: str, *, deadline: float | None = None, strip_inword_digits: bool = False
) -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    variants = confusable_rule_variant_set(value, deadline=deadline)
    scan_variants = dict.fromkeys(
        candidate
        for variant in (value, *variants.variants)
        for candidate in (
            (variant, _IN_WORD_DIGIT.sub("", variant)) if strip_inword_digits else (variant,)
        )
    )
    for variant in scan_variants:
        if deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        scans = (
            (_SPLIT_RULES, variant),
            (_COMPACT_SPLIT_RULES, re.sub(r"\s+", "", variant)),
        )
        for rules, candidate in scans:
            for pattern, matched, reason in rules:
                if (match := pattern.search(candidate)) is None:
                    continue
                finding = SafetyFinding(matched, reason, hits=(match.group(0),))
                if not any(
                    item.matched == finding.matched and item.reason == finding.reason
                    for item in findings
                ):
                    findings.append(finding)
    if variants.exhausted:
        findings.append(SafetyFinding("confusable_variant_limit", "span_limit"))
    return findings


def _bare_secret_name_fragments(
    matched: str,
    fragments: Iterable[str],
    context_fields: Iterable[tuple[str, str, bool]],
) -> bool:
    if matched not in {"api key", "private key"}:
        return False
    matched_words = matched.split()
    if matched == "api key":
        return _has_bare_secret_word_sequence(list(fragments), matched_words)
    materialized = list(context_fields)
    groups = (
        [value for _, value, is_key in materialized if is_key and value.strip()],
        [value for _, value, is_key in materialized if not is_key and value.strip()],
    )
    return any(_has_bare_secret_word_sequence(group, matched_words) for group in groups)


def _has_bare_secret_word_sequence(fragments: list[str], matched_words: list[str]) -> bool:
    normalized = [fragment.strip().casefold() for fragment in fragments]
    for start, fragment in enumerate(normalized):
        if not _is_bare_secret_word(fragment, matched_words[0]):
            continue
        cursor = start
        for word in matched_words[1:]:
            for index in range(cursor + 1, len(normalized)):
                if not _is_bare_secret_word(normalized[index], word):
                    continue
                if all(re.fullmatch(r"[vq]?\d+", item) for item in normalized[cursor + 1 : index]):
                    cursor = index
                    break
            else:
                break
        else:
            return True
    return False


def _is_bare_secret_word(fragment: str, word: str) -> bool:
    return re.fullmatch(rf"[^a-z0-9]*{re.escape(word)}[^a-z0-9]*", fragment, re.I) is not None


def _deadline_reached(
    result: SafetyResult, deadline: float | None, time_limit_match: str | None = None
) -> bool:
    if deadline is None or time.monotonic() < deadline:
        return False
    result.add(SafetyFinding(time_limit_match or "time_limit", "span_limit"))
    return True


def _string_exceeds_scan_limit(value: str) -> bool:
    return len(value) > MAX_SCAN_FIELD_BYTES or len(value.encode("utf-8")) > MAX_SCAN_FIELD_BYTES


def _exceeds_non_ascii_budget(value: str) -> bool:
    seen = 0
    for char in value:
        if not char.isascii():
            seen += 1
            if seen > MAX_NON_ASCII_CODEPOINTS:
                return True
    return False


def _add_unicode_findings(result: SafetyResult, transformations: set[str]) -> None:
    if transformations & {"invisible", "display_modifier_evasion"}:
        result.add(SafetyFinding("invisible_unicode", "invisible_unicode"))
    if transformations & {"mixed_script", "unmapped_confusable"}:
        result.add(SafetyFinding("confusable_unicode", "confusable_unicode"))


def _amg_scan(
    key: str, value: str, *, operation: str, deadline: float | None = None
) -> list[SafetyFinding]:
    if not value:
        return []
    findings: list[SafetyFinding] = []
    preferred = preferred_confusable_variant(value, deadline=deadline)
    official = official_confusable_variant(value, deadline=deadline)
    for candidate in dict.fromkeys((value, preferred, official)):
        for detector in _DETECTORS:
            if deadline is not None and time.monotonic() >= deadline:
                raise UnicodeScanDeadlineExceeded
            detection = detector.inspect(key, candidate, operation=operation)
            if not detection.matched:
                continue
            name = str(detection.detector)
            severity = getattr(detection.severity, "value", detection.severity)
            metadata = detection.metadata if isinstance(detection.metadata, dict) else {}
            raw_hits = metadata.get("hits", [])
            string_hits = tuple(hit for hit in raw_hits if isinstance(hit, str))
            structured_hits = tuple(
                hit["matched_text"]
                for hit in raw_hits
                if isinstance(hit, dict) and isinstance(hit.get("matched_text"), str)
            )
            hits = (*string_hits, *structured_hits)
            if name == "sensitive_data" and not _keep_sensitive_detection(candidate, hits):
                continue
            finding = SafetyFinding(
                string_hits[0] if string_hits else name,
                _REASON_MAP.get(name, name),
                name,
                str(severity) if severity is not None else None,
                hits,
            )
            if finding not in findings:
                findings.append(finding)
    return findings


def _keep_sensitive_detection(value: str, hits: tuple[str, ...]) -> bool:
    card_matches = list(_CARD_NUMBER.finditer(value))
    if not card_matches:
        return True
    non_card_hits = [hit for hit in hits if not _CARD_NUMBER.fullmatch(hit.strip())]
    if non_card_hits:
        return True
    for match in card_matches:
        digits = re.sub(r"\D", "", match.group(0))
        context = value[max(0, match.start() - 32) : min(len(value), match.end() + 32)]
        if _CARD_CONTEXT.search(context) or _luhn_valid(digits):
            return True
    return False


def _luhn_valid(digits: str) -> bool:
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _crosses_field_boundary(hit: str, fields: Iterable[str]) -> bool:
    return bool(hit) and not any(hit in field for field in fields)


def _looks_like_base64(candidate: str) -> bool:
    if len(candidate) < 8:
        return False
    padded = _padded_base64(candidate)
    if padded is None:
        return False
    if _hard_base64_signal(candidate) or _weak_base64_signal(candidate):
        return True
    return _decode_base64_fragment(candidate) is not None


def _padded_base64(candidate: str) -> str | None:
    if not candidate or len(candidate) % 4 == 1:
        return None
    if "=" in candidate and not candidate.endswith(("=", "==")):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    return padded if _CANONICAL_BASE64.fullmatch(padded) else None


def _join_variants(
    fragments: list[str], *, spaced: str | None = None, compact: str | None = None
) -> tuple[str, ...]:
    """Return bounded joins; split rules also scan without whitespace."""
    if len(fragments) < 2:
        return tuple(fragments)
    variants = [
        _bounded_utf8_suffix(" ".join(fragments).encode()),
        _bounded_utf8_suffix("".join(fragments).encode()),
        _bounded_utf8_suffix(f"{fragments[0]} {''.join(fragments[1:])}".encode()),
    ]
    if spaced is not None:
        variants.append(spaced)
    if compact is not None:
        variants.append(compact)
    return tuple(dict.fromkeys(variants))


def _hard_base64_signal(candidate: str) -> bool:
    return bool(re.search(r"[=+/]", candidate))


def _weak_base64_signal(candidate: str) -> bool:
    return bool(
        re.search(r"[a-z]", candidate)
        and re.search(r"[A-Z]", candidate)
        and re.search(r"\d", candidate)
    )


def _bounded_append(window: str, field: str) -> str:
    return _bounded_utf8_suffix((f"{window} {field}" if window else field).encode("utf-8"))


def _junction_variants(spaced: str, compact: str, field: str) -> tuple[str, ...]:
    """Keep both sides of a junction before either rolling side is truncated."""
    encoded = field.encode("utf-8")
    if (
        len(spaced.encode("utf-8")) + 1 + len(encoded) <= MAX_SPLIT_WINDOW_BYTES
        and len(compact.encode("utf-8")) + len(encoded) <= MAX_SPLIT_WINDOW_BYTES
    ):
        return ()
    prefix = _bounded_utf8_prefix(encoded)
    return tuple(
        dict.fromkeys(
            (
                f"{spaced} {prefix}" if spaced else prefix,
                f"{compact}{prefix}" if compact else prefix,
            )
        )
    )


def _trim_evasion_variants(
    previous: str, current: str, *, deadline: float | None = None
) -> tuple[str, ...]:
    """Remove low-entropy boundary padding in bounded linear time."""
    trimmed_previous = _trim_boundary_padding(previous, from_start=False)
    trimmed_current = _trim_boundary_padding(current, from_start=True)
    variants: list[str] = []
    if trimmed_previous != previous or trimmed_current != current:
        left = _bounded_utf8_suffix(trimmed_previous.encode("utf-8"))
        right = _bounded_utf8_prefix(trimmed_current.encode("utf-8"))
        variants.extend((f"{left} {right}", f"{left}{right}"))
    variants.extend(_rule_edge_matches(previous, current, deadline=deadline))
    return tuple(dict.fromkeys(variants))


def _rule_edge_matches(
    previous: str, current: str, *, deadline: float | None = None
) -> tuple[str, ...]:
    """Match bounded rule subsequences spanning a field junction."""
    previous_tokens = _rule_edge_tokens(previous, deadline=deadline)
    if previous_tokens is None:
        return ()
    current_tokens = _rule_edge_tokens(current, deadline=deadline)
    if current_tokens is None:
        return ()
    previous_words, previous_available = previous_tokens
    current_words, current_available = current_tokens
    matches: list[str] = []
    for rule_words, matched in _RULE_EDGE_SPECS:
        for split_at, _ in enumerate(rule_words[1:], start=1):
            if deadline is not None and time.monotonic() >= deadline:
                return ()
            previous_expected = rule_words[:split_at]
            current_expected = rule_words[split_at:]
            if (
                not set(previous_expected) <= previous_available
                or not set(current_expected) <= current_available
            ):
                continue
            previous_gap = _rule_part_gap(
                previous,
                previous_words,
                previous_expected,
                from_start=False,
                deadline=deadline,
            )
            current_gap = _rule_part_gap(
                current,
                current_words,
                current_expected,
                from_start=True,
                deadline=deadline,
            )
            if previous_gap is None or current_gap is None:
                continue
            if _rule_gap_benign_adjacency(previous_gap, current_gap):
                continue
            if (
                not _rule_gap_allowed(previous_gap, current_gap)
                and matched not in _RULE_FAIL_CLOSED_MATCHES
            ):
                # Distinctive hostile phrases fail closed on budget-exceeded
                # subsequences; common-word rules stay silent to avoid
                # flagging ordinary prose collisions across field junctions.
                continue
            matches.append(matched)
            break
    return tuple(dict.fromkeys(matches))


def _rule_edge_tokens(
    value: str, *, deadline: float | None
) -> tuple[list[_RuleToken], set[str]] | None:
    tokens: list[_RuleToken] = []
    available: set[str] = set()
    for index, match in enumerate(_ASCII_WORD.finditer(value)):
        if index % 1_024 == 0 and deadline is not None and time.monotonic() >= deadline:
            return None
        token = match.group(0).lower()
        tokens.append((token, match.start(), match.end()))
        available.add(token)
        if len(token) >= _RULE_MIN_FUSED_TOKEN_LEN:
            available.update(
                signal
                for signal in _RULE_SIGNAL_WORDS
                if len(token) >= len(signal) + _rule_fused_padding(signal)
                and (token.startswith(signal) or token.endswith(signal))
            )
    return tokens, available


def _rule_part_gap(
    value: str,
    tokens: list[_RuleToken],
    expected: tuple[str, ...],
    *,
    from_start: bool,
    deadline: float | None,
) -> _RuleGap | None:
    expected_index = 0 if from_start else len(expected) - 1
    selected: list[int] = []
    indexed_tokens: Iterable[tuple[int, _RuleToken]] = (
        enumerate(tokens)
        if from_start
        else (
            (len(tokens) - reverse_index - 1, token)
            for reverse_index, token in enumerate(reversed(tokens))
        )
    )
    for iteration, (token_index, (token, _, _)) in enumerate(indexed_tokens):
        if iteration % 1_024 == 0 and deadline is not None and time.monotonic() >= deadline:
            return None
        target = expected[expected_index]
        if not _rule_token_matches(token, target, from_start=from_start):
            continue
        selected.append(token_index)
        expected_index += 1 if from_start else -1
        completed = expected_index == len(expected) if from_start else expected_index < 0
        if completed:
            break
    else:
        return None
    selected.sort()
    selected_set = set(selected)
    relevant_start = 0 if from_start else selected[0]
    relevant_end = selected[-1] + 1 if from_start else len(tokens)
    skipped: list[str] = []
    for offset, index in enumerate(range(relevant_start, relevant_end)):
        if offset % 1_024 == 0 and deadline is not None and time.monotonic() >= deadline:
            return None
        if index not in selected_set:
            skipped.append(tokens[index][0])
    if deadline is not None and time.monotonic() >= deadline:
        return None
    span_start = 0 if from_start else tokens[selected[0]][1]
    span_end = tokens[selected[-1]][2] if from_start else len(value)
    selected_bytes = sum(len(word.encode("utf-8")) for word in expected)
    padding_bytes = max(0, len(value[span_start:span_end].encode("utf-8")) - selected_bytes)
    arbitrary = [word for word in skipped if word not in _RULE_SIGNAL_WORDS]
    return len(arbitrary), frozenset(arbitrary), len(skipped) - len(arbitrary), padding_bytes


def _rule_fused_padding(expected: str) -> int:
    """Fused-token padding budget: short signals need more context."""
    if len(expected) <= _RULE_FUSED_SHORT_SIGNAL_CHARS:
        return _RULE_FUSED_SHORT_SIGNAL_PADDING
    return _RULE_FUSED_PADDING_CHARS


def _rule_token_matches(token: str, expected: str, *, from_start: bool) -> bool:
    if token == expected:
        return True
    if len(token) < len(expected) + _rule_fused_padding(expected):
        return False
    return token.endswith(expected) if from_start else token.startswith(expected)


def _rule_gap_allowed(previous: _RuleGap, current: _RuleGap) -> bool:
    """Whether skipped padding fits the clean-match budget.

    Budget-exceeded subsequences are still reported (fail closed); this
    predicate records whether the match carried only bounded padding.
    """
    arbitrary_count = previous[0] + current[0]
    arbitrary_words = previous[1] | current[1]
    signal_count = previous[2] + current[2]
    padding_bytes = previous[3] + current[3]
    skipped_count = arbitrary_count + signal_count
    return bool(
        skipped_count == 0
        or (skipped_count <= 2 and arbitrary_count <= 1)
        or (arbitrary_count == 2 and len(arbitrary_words) == 1 and signal_count == 0)
        or padding_bytes >= _RULE_PADDING_BYTES
    )


def _rule_gap_benign_adjacency(previous: _RuleGap, current: _RuleGap) -> bool:
    """Whether the skipped padding is ordinary function-word adjacency.

    Benign prose interleaves one or two function words ("my", "the", "very")
    with rule-shaped word sequences across field junctions. Short filler-only
    runs stay clean; nonce-word padding and longer runs still fail closed.
    """
    arbitrary_count = previous[0] + current[0]
    if not 0 < arbitrary_count <= _RULE_MAX_FILLER_SKIPS:
        return False
    if previous[2] + current[2]:
        return False
    if previous[3] + current[3] >= _RULE_PADDING_BYTES:
        return False
    arbitrary_words = previous[1] | current[1]
    return bool(arbitrary_words) and arbitrary_words <= _RULE_FILLER_WORDS


def _trim_boundary_padding(value: str, *, from_start: bool) -> str:
    if not value:
        return value
    start = 0
    end = len(value)
    while start < end and (value[start] if from_start else value[end - 1]).isspace():
        if from_start:
            start += 1
        else:
            end -= 1
    while start < end:
        boundary = value[start] if from_start else value[end - 1]
        run = 1
        if from_start:
            while start + run < end and value[start + run] == boundary:
                run += 1
        else:
            while end - run - 1 >= start and value[end - run - 1] == boundary:
                run += 1
        if run < 8:
            break
        if from_start:
            start += run
            while start < end and value[start].isspace():
                start += 1
        else:
            end -= run
            while start < end and value[end - 1].isspace():
                end -= 1
    return value[start:end]


def _sequence_join_variants(
    fragments: list[str], *, deadline: float | None = None
) -> tuple[str, ...]:
    prefix = fragments[:-1]
    spaced = _bounded_utf8_suffix(" ".join(prefix).encode())
    compact = _bounded_utf8_suffix("".join(prefix).encode())
    variants = list(_junction_variants(spaced, compact, fragments[-1]))
    spaced = _bounded_append(spaced, fragments[-1])
    compact = _bounded_utf8_suffix(f"{compact}{fragments[-1]}".encode())
    variants.extend(_join_variants(fragments, spaced=spaced, compact=compact))
    if len(fragments) >= 2:
        trimmed = [
            _trim_boundary_padding(fragment, from_start=index > 0)
            for index, fragment in enumerate(fragments)
        ]
        trimmed[:-1] = [
            _trim_boundary_padding(fragment, from_start=False) for fragment in trimmed[:-1]
        ]
        variants.extend(_join_variants(trimmed))
        if len(fragments) == 2:
            variants.extend(_rule_edge_matches(fragments[0], fragments[1], deadline=deadline))
    return tuple(dict.fromkeys(variants))


def _bounded_utf8_prefix(data: bytes) -> str:
    if len(data) <= MAX_SPLIT_WINDOW_BYTES:
        return data.decode("utf-8")
    prefix = data[:MAX_SPLIT_WINDOW_BYTES]
    while prefix:
        try:
            return prefix.decode("utf-8")
        except UnicodeDecodeError as exc:
            prefix = prefix[: exc.start]
    return ""


def _bounded_utf8_suffix(data: bytes) -> str:
    if len(data) <= MAX_SPLIT_WINDOW_BYTES:
        return data.decode("utf-8")
    suffix = data[-MAX_SPLIT_WINDOW_BYTES:]
    while suffix:
        try:
            return suffix.decode("utf-8")
        except UnicodeDecodeError as exc:
            suffix = suffix[exc.start + 1 :]
    return ""
