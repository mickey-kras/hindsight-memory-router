from __future__ import annotations

import json
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from . import security_base64, security_rules, security_screen, security_windows
from .scan_windows import bounded_skip_fragments
from .security_base64 import MAX_BASE64_DECODED_BYTES as MAX_BASE64_DECODED_BYTES
from .security_base64 import MAX_BASE64_SPANS as MAX_BASE64_SPANS
from .security_base64 import MAX_SPLIT_BASE64_CANDIDATE_BYTES as MAX_SPLIT_BASE64_CANDIDATE_BYTES
from .security_base64 import MAX_SPLIT_BASE64_CANDIDATES as MAX_SPLIT_BASE64_CANDIDATES
from .security_base64 import MAX_SPLIT_BASE64_FIELDS as MAX_SPLIT_BASE64_FIELDS
from .security_base64 import (
    MAX_SPLIT_BASE64_RECOVERY_ATTEMPTS as MAX_SPLIT_BASE64_RECOVERY_ATTEMPTS,
)
from .security_base64 import (
    MAX_SPLIT_BASE64_RECOVERY_MIN_PARTS as MAX_SPLIT_BASE64_RECOVERY_MIN_PARTS,
)
from .security_base64 import (
    MAX_SPLIT_BASE64_RECOVERY_PAIR_PARTS as MAX_SPLIT_BASE64_RECOVERY_PAIR_PARTS,
)
from .security_base64 import (
    MAX_SPLIT_BASE64_RECOVERY_TRIPLE_PARTS as MAX_SPLIT_BASE64_RECOVERY_TRIPLE_PARTS,
)
from .security_base64 import (
    MAX_SPLIT_BASE64_RECOVERY_WORK_BYTES as MAX_SPLIT_BASE64_RECOVERY_WORK_BYTES,
)
from .security_base64 import MAX_SPLIT_BASE64_SKIPS as MAX_SPLIT_BASE64_SKIPS
from .security_base64 import MAX_SPLIT_BASE64_WORK_BYTES as MAX_SPLIT_BASE64_WORK_BYTES
from .security_models import SafetyFinding as SafetyFinding
from .security_models import SafetyResult as SafetyResult
from .security_models import _EncodedState
from .security_rules import MAX_NON_ASCII_CODEPOINTS as MAX_NON_ASCII_CODEPOINTS
from .security_rules import MAX_SCAN_FIELD_BYTES as MAX_SCAN_FIELD_BYTES
from .security_windows import MAX_SPLIT_WINDOW_BYTES as MAX_SPLIT_WINDOW_BYTES
from .unicode_security import (
    UnicodeScanDeadlineExceeded,
    canonicalize_content,
)

MAX_SCAN_FIELDS = 128
MAX_ROLLING_WINDOWS = 8_192
MAX_SKIP_WINDOWS = 8_192
FACADE_SCAN_BATCH_FIELDS = 32
FACADE_SCAN_CARRY_VALUES = MAX_SPLIT_BASE64_SKIPS + 2
MAX_FACADE_SCAN_FIELDS = 8_192
MAX_FACADE_SCAN_SECONDS = 30.0
MAX_RETAIN_SCAN_FIELDS = MAX_FACADE_SCAN_FIELDS
MAX_QUERY_SCAN_FIELDS = 256
MAX_QUERY_ROLLING_WINDOWS = 32_768
MAX_QUERY_SKIP_WINDOWS = 32_768
MAX_CORE_SCAN_SECONDS = 5.0
MAX_QUERY_SCAN_SECONDS = 10.0


def _query_window_scan_skippable(window: str, strip_inword_digits: bool) -> bool:
    """True only when every rule/detector scan of this window must be empty."""
    if security_screen._QUERY_WINDOW_SCREEN is None or strip_inword_digits or not window.isascii():
        return False
    (
        literals,
        refinements,
        unscreened,
        compact_literals,
        compact_refinements,
        compact_unscreened,
    ) = security_screen._QUERY_WINDOW_SCREEN
    if security_screen._window_form_scan_needed(
        literals, refinements, unscreened, window, window.lower()
    ):
        return False
    compact = security_screen._WINDOW_WHITESPACE.sub("", window)
    if compact == window and not compact_literals and not compact_unscreened:
        return True
    return not security_screen._window_form_scan_needed(
        compact_literals, compact_refinements, compact_unscreened, compact, compact.lower()
    )


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


def _scan_batched_fields(  # NOSONAR
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
        if security_rules._deadline_reached(combined, deadline, time_limit_match):
            return combined
        _scan_split_base64(
            combined,
            split_fields,
            operation,
            deadline=deadline,
            time_limit_match=time_limit_match,
        )
        security_rules._deadline_reached(combined, deadline, time_limit_match)
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


def scan_query_values(query: Iterable[tuple[str, str]]) -> SafetyResult:  # NOSONAR
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
        if security_rules._deadline_reached(result, deadline):
            break
        if security_rules._string_exceeds_scan_limit(
            key
        ) or security_rules._string_exceeds_scan_limit(raw):
            result.add(SafetyFinding("field_size_limit", "span_limit"))
            break
        if security_rules._exceeds_non_ascii_budget(
            key, max_codepoints=security_rules.MAX_NON_ASCII_CODEPOINTS
        ) or security_rules._exceeds_non_ascii_budget(
            raw, max_codepoints=security_rules.MAX_NON_ASCII_CODEPOINTS
        ):
            result.add(SafetyFinding("unicode_size_limit", "span_limit"))
            break
        try:
            canonical_key, key_transformations = canonicalize_content(key, deadline=deadline)
        except UnicodeScanDeadlineExceeded:
            result.add(SafetyFinding("time_limit", "span_limit"))
            break
        security_rules._add_unicode_findings(result, key_transformations)
        if "keycap" in key_transformations:
            keycap_values.add(canonical_key)
        canonical_keys.append(canonical_key)
        canonical_traversal.append(canonical_key)
        canonical_fields.append((f"query.{key}.key", canonical_key, True))
        try:
            for finding in security_rules._rule_scan(
                canonical_key,
                deadline=deadline,
                strip_inword_digits="keycap" in key_transformations,
            ):
                result.add(finding)
            for finding in security_rules._amg_scan(
                f"query.{key}.key", canonical_key, operation="read", deadline=deadline
            ):
                result.add(finding)
                direct_detector_matches.add(finding.detector or finding.matched)
            security_base64._scan_encoded(
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
        security_rules._add_unicode_findings(result, transformations)
        if "keycap" in transformations:
            keycap_values.add(canonical)
        canonical_values.append(canonical)
        canonical_traversal.append(canonical)
        canonical_fields.append((f"query.{key}", canonical, False))
        try:
            for finding in security_rules._rule_scan(
                canonical,
                deadline=deadline,
                strip_inword_digits="keycap" in transformations,
            ):
                result.add(finding)
            for finding in security_rules._amg_scan(
                f"query.{key}", canonical, operation="read", deadline=deadline
            ):
                result.add(finding)
                direct_detector_matches.add(finding.detector or finding.matched)
            security_base64._scan_encoded(
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
        if security_rules._deadline_reached(result, deadline):
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
            if security_rules._deadline_reached(result, deadline):
                return result
            windows: list[str] = []
            if prefix:
                windows.extend(security_windows._junction_variants(spaced, compact, value))
                windows.extend(
                    security_windows._trim_evasion_variants(prefix[-1], value, deadline=deadline)
                )
            spaced = security_windows._bounded_append(spaced, value)
            compact = security_windows._bounded_utf8_suffix(f"{compact}{value}".encode())
            if prefix:
                compact_tail = security_windows._bounded_utf8_suffix(
                    f"{compact_tail}{value}".encode()
                )
            prefix.append(value)
            if len(prefix) < 2:
                continue
            mixed = f"{security_windows._bounded_utf8_prefix(prefix[0].encode())} {compact_tail}"
            windows.extend((spaced, compact, mixed))
            for combined in dict.fromkeys(windows):
                rolling_windows += 1
                if rolling_windows > MAX_QUERY_ROLLING_WINDOWS:
                    result.add(SafetyFinding("window_limit", "span_limit"))
                    return result
                if _scan_query_window(window_context, combined, prefix):
                    return result
        for fragments in bounded_skip_fragments(canonical_fragments):
            for combined in security_windows._sequence_join_variants(fragments, deadline=deadline):
                skip_windows += 1
                if skip_windows > MAX_QUERY_SKIP_WINDOWS:
                    result.add(SafetyFinding("window_limit", "span_limit"))
                    return result
                if _scan_query_window(window_context, combined, fragments):
                    return result
                if security_rules._deadline_reached(result, deadline):
                    return result
    if not security_rules._deadline_reached(result, deadline):
        _scan_split_base64(result, canonical_fields, "read", deadline=deadline)
        security_rules._deadline_reached(result, deadline)
    return result


def _scan_query_window(  # NOSONAR
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
                    security_rules._split_instruction_rule_scan(
                        window,
                        deadline=context.deadline,
                        strip_inword_digits=strip_inword_digits,
                    ),
                    security_rules._amg_scan(
                        "query.rolling", window, operation="read", deadline=context.deadline
                    ),
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
        if not security_rules._bare_secret_name_fragments(
            finding.matched, fragments, context.canonical_fields
        ) and any(security_rules._crosses_field_boundary(hit, fragments) for hit in finding.hits):
            context.result.add(SafetyFinding(finding.matched, "split_instruction"))
    for finding in detector_findings:
        detector = finding.detector or finding.matched
        if (
            any(security_rules._crosses_field_boundary(hit, fragments) for hit in finding.hits)
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
        and not security_rules._deadline_reached(result, deadline, time_limit_match)
    ):
        _scan_split_base64(
            result,
            canonical_fields,
            operation,
            deadline=deadline,
            time_limit_match=time_limit_match,
        )
        security_rules._deadline_reached(result, deadline, time_limit_match)
    return result


def _scan_direct_fields(  # NOSONAR
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
        if security_rules._string_exceeds_scan_limit(raw):
            result.add(SafetyFinding("field_size_limit", "span_limit"))
            break
        if security_rules._exceeds_non_ascii_budget(
            raw, max_codepoints=security_rules.MAX_NON_ASCII_CODEPOINTS
        ):
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
            security_rules._add_unicode_findings(result, transformations)
            if "keycap" in transformations:
                keycap_values.add(canonical)
            signature = canonical, is_key
            if signature in scanned_values:
                continue
            scanned_values.add(signature)
            for finding in security_rules._rule_scan(
                canonical,
                deadline=options.deadline,
                strip_inword_digits="keycap" in transformations,
            ):
                result.add(finding)
                direct_rule_matches.add(finding.matched)
            for finding in security_rules._amg_scan(
                key,
                canonical,
                operation=options.operation,
                deadline=options.deadline,
            ):
                result.add(finding)
                direct_detector_matches.add(finding.detector or finding.matched)
            state = _EncodedState() if options.isolated_encoded_fields else direct_encoded_state
            security_base64._scan_encoded(
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
        if security_rules._deadline_reached(result, options.deadline, options.time_limit_match):
            break
    return (
        result,
        canonical_fields,
        direct_rule_matches,
        direct_detector_matches,
        keycap_values,
    )


def _scan_window(  # NOSONAR
    context: _WindowScanContext,
    key: str,
    window: str,
    fragments: list[str],
    *,
    skip: bool = False,
) -> None:
    if context.limit_reached:
        return
    if skip:
        context.skip_windows += 1
        count, limit = context.skip_windows, MAX_SKIP_WINDOWS
    else:
        context.rolling_windows += 1
        count, limit = context.rolling_windows, MAX_ROLLING_WINDOWS
    if count > limit:
        context.result.add(SafetyFinding("window_limit", "span_limit"))
        context.limit_reached = True
        return
    strip_inword_digits = any(fragment in context.keycap_values for fragment in fragments)
    cache_key = key, window, strip_inword_digits
    cached = context.scan_cache.get(cache_key)
    if cached is None:
        try:
            split_findings = security_rules._split_instruction_rule_scan(
                window,
                deadline=context.deadline,
                strip_inword_digits=strip_inword_digits,
            )
            detector_findings = security_rules._amg_scan(
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
        if (
            finding.matched not in context.direct_rule_matches
            and not security_rules._bare_secret_name_fragments(
                finding.matched, fragments, context.canonical_fields
            )
        ):
            context.result.add(SafetyFinding(finding.matched, "split_instruction"))
    for finding in detector_findings:
        detector = finding.detector or finding.matched
        if (
            any(security_rules._crosses_field_boundary(hit, fragments) for hit in finding.hits)
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
    if security_rules._deadline_reached(context.result, context.deadline, context.time_limit_match):
        context.limit_reached = True


def _scan_rolling_group(  # NOSONAR
    context: _WindowScanContext, group: list[tuple[str, str]]
) -> None:
    spaced = ""
    compact = ""
    compact_tail = ""
    fragments: list[str] = []
    for key, value in group:
        if fragments:
            for window in security_windows._junction_variants(spaced, compact, value):
                _scan_window(context, key, window, [*fragments, value])
            for window in security_windows._trim_evasion_variants(
                fragments[-1], value, deadline=context.deadline
            ):
                _scan_window(context, key, window, [fragments[-1], value])
        spaced = security_windows._bounded_append(spaced, value)
        compact = security_windows._bounded_utf8_suffix(f"{compact}{value}".encode())
        if fragments:
            compact_tail = security_windows._bounded_utf8_suffix(f"{compact_tail}{value}".encode())
        fragments.append(value)
        if len(fragments) >= 2:
            mixed = f"{security_windows._bounded_utf8_prefix(fragments[0].encode())} {compact_tail}"
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
            for window in security_windows._sequence_join_variants(
                fragments, deadline=context.deadline
            ):
                _scan_window(context, group[-1][0], window, fragments, skip=True)
            if context.limit_reached:
                return


def _scan_split_base64(  # NOSONAR
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
        if security_rules._deadline_reached(result, deadline, time_limit_match):
            return
        encoded_candidates, encoded_exhausted = security_base64._split_base64_candidates(
            group,
            deadline=deadline,
            normalized_fragments=normalized_fragments,
            max_work_bytes=security_base64.MAX_SPLIT_BASE64_WORK_BYTES,
        )
        if security_rules._deadline_reached(result, deadline, time_limit_match):
            return
        exhausted |= encoded_exhausted
        for candidate in encoded_candidates:
            if security_rules._deadline_reached(result, deadline, time_limit_match):
                return
            try:
                security_base64._scan_encoded(
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
        decoded_candidates, decoded_exhausted = security_base64._split_decoded_base64_candidates(
            group,
            deadline=deadline,
            normalized_fragments=normalized_fragments,
            max_work_bytes=security_base64.MAX_SPLIT_BASE64_WORK_BYTES,
        )
        if security_rules._deadline_reached(result, deadline, time_limit_match):
            return
        exhausted |= decoded_exhausted
        for compact, spaced in decoded_candidates:
            for candidate in dict.fromkeys((compact, spaced)):
                if security_rules._deadline_reached(result, deadline, time_limit_match):
                    return
                try:
                    canonical, transformations = canonicalize_content(candidate, deadline=deadline)
                except UnicodeScanDeadlineExceeded:
                    result.add(SafetyFinding(time_limit_match or "time_limit", "span_limit"))
                    return
                result.transformations.update(transformations)
                security_rules._add_unicode_findings(result, transformations)
                try:
                    findings = security_rules._rule_scan(
                        canonical,
                        deadline=deadline,
                        strip_inword_digits="keycap" in transformations,
                    ) + security_rules._amg_scan(
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
