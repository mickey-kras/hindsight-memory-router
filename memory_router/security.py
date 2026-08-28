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
                index = after  # optional group: