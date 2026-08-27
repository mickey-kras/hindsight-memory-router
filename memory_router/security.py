from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
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
MIN_BASE64_OVERFLOW_PLAUSIBLE_PARTS = MAX_SPLIT_BASE64_SKIPS + 2
FACADE_SCAN_BATCH_FIELDS = 32
FACADE_SCAN_CARRY_VALUES = MAX_SPLIT_BASE64_SKIPS + 2
MAX_FACADE_SCAN_FIELDS = 8_192
MAX_FACADE_SCAN_SECONDS = 30.0
MAX_RETAIN_SCAN_FIELDS = MAX_FACADE_SCAN_FIELDS
MAX_QUERY_SCAN_FIELDS = 256
MAX_SCAN_FIELD_BYTES = 1024 * 1024
MAX_NON_ASCII_CODEPOINTS = 65_536
MAX_CORE_SCAN_SECONDS = 5.0
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{8,}(?![A-Za-z0-9+/=])")
_BASE64_CHARS = re.compile(r"^[A-Za-z0-9+/=]+$")
_BASE64_PARTS = re.compile(r"[A-Za-z0-9+/=]+")
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


def scan_query_values(query: Iterable[tuple[str, str]]) -> SafetyResult:
    """Scan bounded query keys and values."""

    result = SafetyResult()
    canonical_values: list[str] = []
    canonical_keys: list[str] = []
    canonical_traversal: list[str] = []
    canonical_fields: list[tuple[str, str, bool]] = []
    keycap_values: set[str] = set()
    encoded_state = _EncodedState()
    rolling_windows = 0
    skip_windows = 0
    deadline = time.monotonic() + MAX_CORE_SCAN_SECONDS
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
    for canonical_fragments in (canonical_values, canonical_keys, canonical_traversal):
        if len(canonical_fragments) < 2:
            continue
        skip_windows = 0
        spaced = ""
        compact = ""
        for end, value in enumerate(canonical_fragments, start=1):
            if _deadline_reached(result, deadline):
                return result
            prefix = canonical_fragments[:end]
            junctions = _junction_variants(spaced, compact, value) if end >= 2 else ()
            spaced = _bounded_append(spaced, value)
            compact = _bounded_utf8_suffix(f"{compact}{value}".encode())
            if end < 2:
                continue
            windows = (*junctions, *_join_variants(prefix, spaced=spaced, compact=compact))
            for combined in dict.fromkeys(windows):
                rolling_windows += 1
                if rolling_windows > MAX_ROLLING_WINDOWS:
                    result.add(SafetyFinding("window_limit", "span_limit"))
                    return result
                if _scan_query_window(
                    result,
                    combined,
                    prefix,
                    canonical_fields,
                    keycap_values,
                    deadline,
                ):
                    return result
        for fragments in bounded_skip_fragments(canonical_fragments):
            for combined in _sequence_join_variants(fragments):
                skip_windows += 1
                if skip_windows > MAX_SKIP_WINDOWS:
                    result.add(SafetyFinding("window_limit", "span_limit"))
                    return result
                if _scan_query_window(
                    result,
                    combined,
                    fragments,
                    canonical_fields,
                    keycap_values,
                    deadline,
                ):
                    return result
                if _deadline_reached(result, deadline):
                    return result
    if not _deadline_reached(result, deadline):
        _scan_split_base64(result, canonical_fields, "read", deadline=deadline)
        _deadline_reached(result, deadline)
    return result


def _scan_query_window(
    result: SafetyResult,
    window: str,
    fragments: list[str],
    canonical_fields: list[tuple[str, str, bool]],
    keycap_values: set[str],
    deadline: float,
) -> bool:
    try:
        findings = _split_instruction_rule_scan(
            window,
            deadline=deadline,
            strip_inword_digits=any(fragment in keycap_values for fragment in fragments),
        )
    except UnicodeScanDeadlineExceeded:
        result.add(SafetyFinding("time_limit", "span_limit"))
        return True
    for finding in findings:
        if finding.reason == "span_limit":
            result.add(finding)
            return True
        if not _bare_secret_name_fragments(finding.matched, fragments, canonical_fields) and any(
            _crosses_field_boundary(hit, fragments) for hit in finding.hits
        ):
            result.add(SafetyFinding(finding.matched, "split_instruction"))
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
    keycap_values: set[str]
    operation: str
    deadline: float | None
    time_limit_match: str | None
    rolling_windows: int = 0
    skip_windows: int = 0
    limit_reached: bool = False
    scan_cache: dict[tuple[str, bool], tuple[list[SafetyFinding], list[SafetyFinding]]] = field(
        default_factory=dict
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
    result, canonical_fields, direct_rule_matches, keycap_values = _scan_direct_fields(
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
) -> tuple[SafetyResult, list[tuple[str, str, bool]], set[str], set[str]]:
    result = SafetyResult()
    canonical_fields: list[tuple[str, str, bool]] = []
    direct_rule_matches: set[str] = set()
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
                key, canonical, operation=options.operation, deadline=options.deadline
            ):
                result.add(finding)
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
    return result, canonical_fields, direct_rule_matches, keycap_values


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
    cache_key = window, strip_inword_digits
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
        if any(_crosses_field_boundary(hit, fragments) for hit in finding.hits):
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
            for window in _sequence_join_variants(fragments):
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
            if skipped >= MAX_SPLIT_BASE64_SKIPS and (
                _credible_base64_prefix(candidate)
                or (
                    _decode_base64_fragment(candidate) is not None
                    and _decode_base64_fragment(fragment) is not None
                )
            ):
                soft_exhausted = True
            if "=" not in candidate:
                combined = candidate + fragment
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
    candidates: list[tuple[str, str, int, int, bool]] = []
    work_bytes = 0
    exhausted = False
    soft_exhausted = False

    def add(
        target: list[tuple[str, str, int, int, bool]],
        compact: str,
        spaced: str,
        parts: int,
        skipped: int,
        terminated: bool,
    ) -> bool:
        nonlocal exhausted, work_bytes
        size = len(compact.encode("utf-8")) + len(spaced.encode("utf-8"))
        if size > MAX_SPLIT_BASE64_WORK_BYTES:
            exhausted = True
            return True
        if work_bytes + size > MAX_SPLIT_BASE64_WORK_BYTES:
            exhausted = True
            return False
        work_bytes += size
        target.append((compact, spaced, parts, skipped, terminated))
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
        fragment_fields += 1
        if fragment_fields > MAX_SPLIT_BASE64_FIELDS:
            exhausted = True
            break
        next_candidates: list[tuple[str, str, int, int, bool]] = []
        if not add(next_candidates, decoded, decoded, 1, 0, True):
            break
        for compact, spaced, parts, skipped, terminated in candidates:
            if deadline is not None and time.monotonic() >= deadline:
                exhausted = True
                break
            if not add(
                next_candidates,
                _bounded_utf8_suffix(f"{compact}{decoded}".encode()),
                _bounded_append(spaced, decoded),
                parts + 1,
                skipped,
                terminated,
            ):
                exhausted = True
                break
            if skipped < MAX_SPLIT_BASE64_SKIPS and not add(
                next_candidates, compact, spaced, parts, skipped + 1, terminated
            ):
                exhausted = True
                break
            if skipped >= MAX_SPLIT_BASE64_SKIPS:
                soft_exhausted = True
        unique = dict.fromkeys(next_candidates)
        if len(unique) > MAX_SPLIT_BASE64_CANDIDATES:
            soft_exhausted = True
        candidates = sorted(unique, key=lambda value: (-len(value[0]), value[3]))[
            :MAX_SPLIT_BASE64_CANDIDATES
        ]
        if exhausted:
            break
    return (
        [
            (compact, spaced)
            for compact, spaced, parts, _, terminated in candidates
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
    return text if text and all(char.isprintable() or char.isspace() for char in text) else None


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
    plausible_parts = 0
    for match_index, match in enumerate(_BASE64_PARTS.finditer(stripped), start=1):
        if match_index % 1_024 == 0 and deadline is not None and time.monotonic() >= deadline:
            return None, True
        if _base64_part_is_label(stripped, match):
            continue
        part_count += 1
        part = match.group(0)
        plausible_parts += int(_plausible_base64_fragment(part))
        if len(parts) < MAX_SPLIT_BASE64_FIELDS:
            parts.append(part)
    if part_count > MAX_SPLIT_BASE64_FIELDS:
        return None, plausible_parts >= MIN_BASE64_OVERFLOW_PLAUSIBLE_PARTS
    if not parts:
        return None, False
    return "".join(parts), False


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
    return bool(decoded and any(char.isspace() for char in decoded))


def _viable_base64_prefix(fragment: str) -> bool:
    """Return whether future Base64 bytes can still form printable UTF-8."""
    complete_length = len(fragment) - (len(fragment) % 4)
    if complete_length == 0:
        return True
    prefix = fragment[:complete_length]
    try:
        decoded = base64.b64decode(prefix, validate=True)
        text = codecs.getincrementaldecoder("utf-8")().decode(decoded, final=False)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return all(char.isprintable() or char.isspace() for char in text)


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
    for match in _BASE64_RUN.finditer(canonical):
        if deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        candidate = match.group(0)
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
        try:
            decoded_text = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            if hard_signal and fail_closed_invalid:
                result.add(SafetyFinding("invalid_utf8", "encoded_payload"))
            continue
        decoded_canonical, decoded_transformations = canonicalize_content(
            decoded_text, deadline=deadline
        )
        result.transformations.update(decoded_transformations)
        _add_unicode_findings(result, decoded_transformations)
        decoded_hits = _rule_scan(
            decoded_canonical,
            deadline=deadline,
            strip_inword_digits="keycap" in decoded_transformations,
        ) + _amg_scan(f"{key}.base64", decoded_canonical, operation=operation, deadline=deadline)
        if decoded_hits:
            result.add(SafetyFinding("unsafe_base64", "encoded_payload"))
            for finding in decoded_hits:
                result.add(finding)
        if depth == 0:
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
            hits = tuple(str(hit) for hit in raw_hits if isinstance(hit, str))
            if name == "sensitive_data" and not _keep_sensitive_detection(candidate, hits):
                continue
            finding = SafetyFinding(
                hits[0] if hits else name,
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
    try:
        decoded = base64.b64decode(padded, validate=True)
        text = decoded.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return bool(text and all(char.isprintable() or char.isspace() for char in text))


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


def _sequence_join_variants(fragments: list[str]) -> tuple[str, ...]:
    prefix = fragments[:-1]
    spaced = _bounded_utf8_suffix(" ".join(prefix).encode())
    compact = _bounded_utf8_suffix("".join(prefix).encode())
    variants = list(_junction_variants(spaced, compact, fragments[-1]))
    spaced = _bounded_append(spaced, fragments[-1])
    compact = _bounded_utf8_suffix(f"{compact}{fragments[-1]}".encode())
    variants.extend(_join_variants(fragments, spaced=spaced, compact=compact))
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
