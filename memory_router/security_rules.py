from __future__ import annotations

import re
import time
from collections.abc import Iterable

from agent_memory_guard.detectors import (
    ExcessiveAutonomyDetector,
    PrivilegeEscalationDetector,
    PromptInjectionDetector,
    SensitiveDataDetector,
    ToolAbuseDetector,
)

from .security_models import SafetyFinding, SafetyResult
from .unicode_security import (
    UnicodeScanDeadlineExceeded,
    confusable_rule_variant_set,
    official_confusable_variant,
    preferred_confusable_variant,
)

MAX_SCAN_FIELD_BYTES = 1024 * 1024
MAX_NON_ASCII_CODEPOINTS = 65_536

_IN_WORD_DIGIT = re.compile(r"(?<=[A-Za-z])\d(?=[A-Za-z])")


_RULE_PUNCTUATION = re.compile(r"(?!\s)[\W_]")


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


_IGNORE_PREVIOUS_INSTRUCTIONS = "ignore previous instructions"
_DISCLOSURE_RULE_REASON = "reveal secret"
_API_KEY = "api key"

_RULE_EDGE_SPECS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("ignore", "previous", "instructions"), _IGNORE_PREVIOUS_INSTRUCTIONS),
    (("ignore", "all", "previous", "instructions"), _IGNORE_PREVIOUS_INSTRUCTIONS),
    (("you", "are", "now"), "you are now"),
    (("write", "this", "to", "memory"), "write this to memory"),
    (("remember", "this", "as", "truth"), "remember this as truth"),
    (("store", "this", "as", "core", "memory"), "store this as core memory"),
    (("overwrite", "permissions"), "overwrite permissions"),
    (("reveal", "secret"), _DISCLOSURE_RULE_REASON),
    (("reveal", "the", "secret"), _DISCLOSURE_RULE_REASON),
    (("reveal", "token"), _DISCLOSURE_RULE_REASON),
    (("reveal", "the", "token"), _DISCLOSURE_RULE_REASON),
    (("reveal", "key"), _DISCLOSURE_RULE_REASON),
    (("reveal", "the", "key"), _DISCLOSURE_RULE_REASON),
    (("api", "key"), _API_KEY),
    (("private", "key"), "private key"),
    (("begin", "openssh", "private", "key"), "private key block"),
)


_RULE_FUSED_PADDING_CHARS = 4


_RULE_FUSED_SHORT_SIGNAL_CHARS = 3


_RULE_FUSED_SHORT_SIGNAL_PADDING = 8


_RULE_PADDING_BYTES = 64


_RULE_MAX_FILLER_SKIPS = 2


_RULE_FAIL_CLOSED_MATCHES = frozenset(
    {"ignore previous instructions", "overwrite permissions", "private key block"}
)


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
        "these",
        "those",
        "two",
        "few",
        "many",
        "several",
        "some",
        "any",
        "other",
        "another",
        "such",
        "own",
        "same",
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


def _append_rule_matches(
    findings: list[SafetyFinding],
    seen: set[tuple[str, str]],
    rules: Iterable[tuple[re.Pattern[str], str, str]],
    candidate: str,
) -> None:
    for pattern, matched, reason in rules:
        match = pattern.search(candidate)
        signature = matched, reason
        if match is not None and signature not in seen:
            seen.add(signature)
            findings.append(SafetyFinding(matched, reason, hits=(match.group(0),)))


def _rule_scan(
    value: str, *, deadline: float | None = None, strip_inword_digits: bool = False
) -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    seen: set[tuple[str, str]] = set()
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
        for candidate in dict.fromkeys((variant, _RULE_PUNCTUATION.sub(" ", variant))):
            _append_rule_matches(findings, seen, _RULES, candidate)
    if variants.exhausted:
        findings.append(SafetyFinding("confusable_variant_limit", "span_limit"))
    return findings


def _split_instruction_rule_scan(
    value: str, *, deadline: float | None = None, strip_inword_digits: bool = False
) -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    seen: set[tuple[str, str]] = set()
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
            (_SPLIT_RULES, _RULE_PUNCTUATION.sub(" ", variant)),
            (_COMPACT_SPLIT_RULES, re.sub(r"\s+", "", variant)),
        )
        for rules, candidate in scans:
            _append_rule_matches(findings, seen, rules, candidate)
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


def _has_bare_secret_word_sequence(  # NOSONAR
    fragments: list[str], matched_words: list[str]
) -> bool:
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


def _exceeds_non_ascii_budget(
    value: str, *, max_codepoints: int = MAX_NON_ASCII_CODEPOINTS
) -> bool:
    seen = 0
    for char in value:
        if not char.isascii():
            seen += 1
            if seen > max_codepoints:
                return True
    return False


def _add_unicode_findings(  # NOSONAR
    result: SafetyResult, transformations: set[str]
) -> None:
    if transformations & {"invisible", "display_modifier_evasion"}:
        result.add(SafetyFinding("invisible_unicode", "invisible_unicode"))
    if transformations & {"mixed_script", "unmapped_confusable"}:
        result.add(SafetyFinding("confusable_unicode", "confusable_unicode"))


def _amg_scan(  # NOSONAR
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


def _crosses_field_boundary(  # NOSONAR
    hit: str, fields: Iterable[str]
) -> bool:
    return bool(hit) and not any(hit in field for field in fields)


def _rule_edge_matches(  # NOSONAR
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
            if not _rule_gap_allowed(previous_gap, current_gap) and not (
                matched in _RULE_FAIL_CLOSED_MATCHES
                and _rule_gap_fail_closed(previous_gap, current_gap)
            ):
                # Distinctive hostile phrases fail closed on clearly padded
                # subsequences; common-word rules and lightly padded matches
                # stay silent to avoid flagging ordinary prose collisions
                # across field junctions.
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


def _rule_part_gap(  # NOSONAR
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


def _rule_gap_fail_closed(previous: _RuleGap, current: _RuleGap) -> bool:
    """Whether a budget-exceeded strong-rule match fails closed.

    Requires at least two non-filler junk words, or three or more skipped
    words overall, so ordinary ops prose ("the existing permissions doc")
    stays clean while nonce-word padding still fails closed.
    """
    arbitrary_count = previous[0] + current[0]
    signal_count = previous[2] + current[2]
    filler_words = (previous[1] | current[1]) & _RULE_FILLER_WORDS
    non_filler_count = arbitrary_count - len(filler_words)
    skipped_count = arbitrary_count + signal_count
    return non_filler_count >= 2 or skipped_count >= 3


def _trim_boundary_padding(value: str, *, from_start: bool) -> str:  # NOSONAR
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
