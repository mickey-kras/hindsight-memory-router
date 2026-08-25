from __future__ import annotations

import base64
import binascii
import re
import time
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from agent_memory_guard.detectors import (
    ExcessiveAutonomyDetector,
    PrivilegeEscalationDetector,
    PromptInjectionDetector,
    SensitiveDataDetector,
    ToolAbuseDetector,
)
from confusables import normalize as normalize_confusables  # type: ignore[import-untyped]

MAX_SCAN_FIELDS = 128
MAX_ROLLING_WINDOWS = 128
MAX_SPLIT_WINDOW_BYTES = 512
MAX_BASE64_SPANS = 8
MAX_BASE64_DECODED_BYTES = 16 * 1024
MAX_SPLIT_BASE64_CANDIDATES = 64
MAX_SPLIT_BASE64_FIELDS = 256
MAX_SPLIT_BASE64_SKIPS = 2
MAX_SPLIT_BASE64_CANDIDATE_BYTES = ((MAX_BASE64_DECODED_BYTES + 2) // 3) * 4
MAX_SPLIT_BASE64_WORK_BYTES = 512 * 1024
FACADE_SCAN_BATCH_FIELDS = 32
FACADE_SCAN_CARRY_FIELDS = 2
MAX_FACADE_SCAN_FIELDS = 8_192
MAX_FACADE_SCAN_SECONDS = 30.0
MAX_RETAIN_SCAN_FIELDS = MAX_FACADE_SCAN_FIELDS
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{8,}(?![A-Za-z0-9+/=])")
_BASE64_CHARS = re.compile(r"^[A-Za-z0-9+/=]+$")
_BASE64_PARTS = re.compile(r"[A-Za-z0-9+/=]+")
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
_SPLIT_INSTRUCTION_RULES = tuple(
    rule
    for rule in _RULES
    if rule[2] in {"prompt_injection", "permission_rewrite"}
    and rule[1] not in _NON_IMPERATIVE_SPLIT_MATCHES
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


@lru_cache(maxsize=1_024)
def _fold_confusable_char(char: str) -> str:
    if char.isascii():
        return char
    folded = normalize_confusables(char, prioritize_alpha=True)
    return folded[0] if folded else char


def canonicalize_content(content: str) -> tuple[str, set[str]]:
    normalized = unicodedata.normalize("NFKC", content)
    transformations: set[str] = set()
    if normalized != content:
        transformations.add("nfkc")
    chars: list[str] = []
    removed = False
    display_modifier_removed = False
    for char in normalized:
        cp = ord(char)
        display_modifier = cp in {0x200C, 0x200D} or 0xFE00 <= cp <= 0xFE0F
        invisible = (
            cp in {0x200B, 0x2060}
            or 0x202A <= cp <= 0x202E
            or 0x2066 <= cp <= 0x2069
            or 0xE0000 <= cp <= 0xE007F
        )
        if display_modifier:
            display_modifier_removed = True
        elif invisible:
            removed = True
        else:
            chars.append(char)
    canonical = "".join(chars)
    if removed:
        transformations.add("invisible")
    if display_modifier_removed:
        transformations.add("display_modifier")
    if not canonical.isascii():
        skeleton = "".join(_fold_confusable_char(char) for char in canonical)
        if skeleton != canonical:
            canonical = skeleton
            transformations.add("confusable")
    return canonical, transformations


def scan_content(content: str, *, operation: str = "read", key: str = "content") -> SafetyResult:
    return _scan_fields([(key, content, False)], operation=operation)


def scan_retain_body(body: dict[str, Any]) -> SafetyResult:
    return _scan_batched_fields(
        _walk_strings(body, "retain"),
        operation="write",
        max_fields=MAX_RETAIN_SCAN_FIELDS,
        field_limit_match="field_limit",
    )


def scan_recall_body(body: dict[str, Any]) -> SafetyResult:
    return _scan_fields(_walk_strings(body, "recall"), operation="read")


def scan_recall_result(result: dict[str, Any]) -> SafetyResult:
    return _scan_fields(_walk_strings(result, "recalled_memory"), operation="read")


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
        _scan_split_base64(combined, split_fields, operation)
        return combined

    while True:
        batch: list[tuple[str, str, bool]] = []
        for _ in range(FACADE_SCAN_BATCH_FIELDS):
            if scanned_fields and deadline is not None and time.monotonic() >= deadline:
                combined.add(SafetyFinding(time_limit_match or "time_limit", "span_limit"))
                return finish()
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
            key, raw, is_key = field
            canonical, _ = canonicalize_content(raw)
            split_fields.append((key, canonical, is_key))
        if not batch:
            return finish()
        combined.extend(
            _scan_fields(
                [*carry, *batch],
                operation=operation,
                isolated_encoded_fields=True,
                scan_split_base64=False,
            )
        )
        carry = [*carry, *batch][-FACADE_SCAN_CARRY_FIELDS:]


def scan_query_values(query: Iterable[tuple[str, str]]) -> SafetyResult:
    """Scan free-text query values without payload/base64 heuristics."""

    result = SafetyResult()
    canonical_values: list[str] = []
    for key, raw in query:
        canonical, _ = canonicalize_content(raw)
        canonical_values.append(canonical)
        for finding in _rule_scan(canonical):
            result.add(finding)
        for finding in _amg_scan(f"query.{key}", canonical, operation="read"):
            result.add(finding)
    if len(canonical_values) >= 2:
        spaced = ""
        compact = ""
        for value in canonical_values:
            spaced = _bounded_append(spaced, value)
            compact = _bounded_utf8_suffix(f"{compact}{value}".encode())
        for combined in dict.fromkeys((spaced, compact)):
            for finding in _split_instruction_rule_scan(combined):
                if any(_crosses_field_boundary(hit, canonical_values) for hit in finding.hits):
                    result.add(SafetyFinding(finding.matched, "split_instruction"))
    return result


def _walk_strings(
    value: Any, path: str, *, is_key: bool = False
) -> Iterator[tuple[str, str, bool]]:
    if isinstance(value, str):
        yield path, value, is_key
        return
    if isinstance(value, list):
        for index, entry in enumerate(value):
            yield from _walk_strings(entry, f"{path}.{index}")
        return
    if isinstance(value, dict):
        for key, entry in value.items():
            if isinstance(key, str):
                yield f"{path}.{key}", key, True
                child = f"{path}.{key}"
            else:
                child = path
            yield from _walk_strings(entry, child)


def _scan_fields(
    fields: Iterable[tuple[str, str, bool]],
    *,
    operation: str,
    isolated_encoded_fields: bool = False,
    scan_split_base64: bool = True,
) -> SafetyResult:
    result = SafetyResult()
    canonical_fields: list[tuple[str, str, bool]] = []
    direct_rule_matches: set[str] = set()
    direct_encoded_state = _EncodedState()
    for index, (key, raw, is_key) in enumerate(fields):
        if index >= MAX_SCAN_FIELDS:
            result.add(SafetyFinding("field_limit", "span_limit"))
            break
        canonical, transformations = canonicalize_content(raw)
        result.transformations.update(transformations)
        canonical_fields.append((key, canonical, is_key))
        if "invisible" in transformations:
            result.add(SafetyFinding("invisible_unicode", "invisible_unicode"))
        for finding in _rule_scan(canonical):
            result.add(finding)
            direct_rule_matches.add(finding.matched)
        for finding in _amg_scan(key, canonical, operation=operation):
            result.add(finding)
        state = _EncodedState() if isolated_encoded_fields else direct_encoded_state
        _scan_encoded(result, key, canonical, operation, state)

    rolling_windows = 0
    limit_reached = False

    def scan_window(key: str, window: str, fragments: list[str]) -> None:
        nonlocal rolling_windows, limit_reached
        if limit_reached:
            return
        rolling_windows += 1
        if rolling_windows > MAX_ROLLING_WINDOWS:
            result.add(SafetyFinding("window_limit", "span_limit"))
            limit_reached = True
            return
        for finding in _rule_scan(window):
            if finding.matched not in direct_rule_matches:
                result.add(SafetyFinding(finding.matched, "split_instruction"))
        for finding in _amg_scan(f"rolling.{key}", window, operation=operation):
            if any(_crosses_field_boundary(hit, fragments) for hit in finding.hits):
                result.add(
                    SafetyFinding(
                        finding.matched,
                        "split_instruction",
                        finding.detector,
                        finding.severity,
                        finding.hits,
                    )
                )

    value_window = ""
    value_fields: list[str] = []
    for key, canonical, is_key in canonical_fields:
        if is_key:
            continue
        value_window = _bounded_append(value_window, canonical)
        value_fields.append(canonical)
        if len(value_fields) >= 2:
            scan_window(key, value_window, value_fields)
        if limit_reached:
            break

    if not limit_reached:
        for index in range(len(canonical_fields) - 1):
            key, canonical, is_key = canonical_fields[index]
            next_key, next_canonical, next_is_key = canonical_fields[index + 1]
            if is_key == next_is_key:
                continue
            scan_window(
                next_key, _bounded_append(canonical, next_canonical), [canonical, next_canonical]
            )
            if limit_reached:
                break

    if scan_split_base64:
        _scan_split_base64(result, canonical_fields, operation)
    return result


def _scan_split_base64(
    result: SafetyResult, fields: Iterable[tuple[str, str, bool]], operation: str
) -> None:
    materialized = list(fields)
    for candidate in _split_base64_candidates(materialized):
        _scan_encoded(result, "split-base64", candidate, operation, _EncodedState())
    for compact, spaced in _split_decoded_base64_candidates(materialized):
        for candidate in dict.fromkeys((compact, spaced)):
            findings = _rule_scan(candidate) + _amg_scan(
                "split-base64.decoded", candidate, operation=operation
            )
            if findings:
                result.add(SafetyFinding("unsafe_base64", "encoded_payload"))
                for finding in findings:
                    result.add(finding)


def _split_base64_candidates(fields: Iterable[tuple[str, str, bool]]) -> list[str]:
    candidates: list[tuple[str, int]] = []
    fragment_fields = 0
    work_bytes = 0
    exhausted = False

    def add(next_candidates: list[tuple[str, int]], value: str, skipped: int) -> bool:
        nonlocal work_bytes
        size = len(value)
        if size > MAX_SPLIT_BASE64_CANDIDATE_BYTES:
            return True
        if work_bytes + size > MAX_SPLIT_BASE64_WORK_BYTES:
            return False
        work_bytes += size
        next_candidates.append((value, skipped))
        return True

    for _, canonical, is_key in fields:
        fragment = _normalized_base64_fragment(canonical)
        if fragment is None:
            continue
        if is_key and not _looks_like_base64(fragment):
            continue
        fragment_fields += 1
        if fragment_fields > MAX_SPLIT_BASE64_FIELDS:
            break
        if len(fragment) > MAX_SPLIT_BASE64_CANDIDATE_BYTES:
            continue
        next_candidates: list[tuple[str, int]] = []
        if not add(next_candidates, fragment, 0):
            break
        for candidate, skipped in candidates:
            if "=" not in candidate:
                combined = candidate + fragment
                if len(combined) <= MAX_SPLIT_BASE64_CANDIDATE_BYTES and not add(
                    next_candidates, combined, skipped
                ):
                    exhausted = True
                    break
            if skipped < MAX_SPLIT_BASE64_SKIPS and not add(
                next_candidates, candidate, skipped + 1
            ):
                exhausted = True
                break
        candidates = _dedupe_split_candidates(next_candidates)
        if exhausted:
            break
    return [candidate for candidate, _ in candidates if len(candidate) >= 8]


def _split_decoded_base64_candidates(
    fields: Iterable[tuple[str, str, bool]],
) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str, int, int, bool]] = []
    work_bytes = 0

    def add(
        target: list[tuple[str, str, int, int, bool]],
        compact: str,
        spaced: str,
        parts: int,
        skipped: int,
        terminated: bool,
    ) -> bool:
        nonlocal work_bytes
        size = len(compact.encode("utf-8")) + len(spaced.encode("utf-8"))
        if size > MAX_SPLIT_BASE64_WORK_BYTES:
            return True
        if work_bytes + size > MAX_SPLIT_BASE64_WORK_BYTES:
            return False
        work_bytes += size
        target.append((compact, spaced, parts, skipped, terminated))
        return True

    fragment_fields = 0
    for _, canonical, is_key in fields:
        fragment = _normalized_base64_fragment(canonical)
        if fragment is None:
            continue
        if is_key and not _looks_like_base64(fragment):
            continue
        decoded = _decode_base64_fragment(fragment)
        if decoded is None:
            continue
        fragment_fields += 1
        if fragment_fields > MAX_SPLIT_BASE64_FIELDS:
            break
        next_candidates: list[tuple[str, str, int, int, bool]] = []
        if not add(next_candidates, decoded, decoded, 1, 0, "=" in fragment):
            break
        exhausted = False
        for compact, spaced, parts, skipped, terminated in candidates:
            if not add(
                next_candidates,
                _bounded_utf8_suffix(f"{compact}{decoded}".encode()),
                _bounded_append(spaced, decoded),
                parts + 1,
                skipped,
                terminated or "=" in fragment,
            ):
                exhausted = True
                break
            if skipped < MAX_SPLIT_BASE64_SKIPS and not add(
                next_candidates, compact, spaced, parts, skipped + 1, terminated
            ):
                exhausted = True
                break
        unique = dict.fromkeys(next_candidates)
        candidates = sorted(unique, key=lambda value: (-len(value[0]), value[3]))[
            :MAX_SPLIT_BASE64_CANDIDATES
        ]
        if exhausted:
            break
    return [
        (compact, spaced)
        for compact, spaced, parts, _, terminated in candidates
        if parts >= 2 and terminated
    ]


def _decode_base64_fragment(fragment: str) -> str | None:
    if len(fragment) % 4 or not _CANONICAL_BASE64.fullmatch(fragment):
        return None
    try:
        decoded = base64.b64decode(fragment, validate=True)
        if len(decoded) > MAX_BASE64_DECODED_BYTES:
            return None
        text = decoded.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return text if text and all(char.isprintable() or char.isspace() for char in text) else None


def _normalized_base64_fragment(value: str) -> str | None:
    stripped = value.strip()
    if not stripped:
        return None
    if _BASE64_CHARS.fullmatch(stripped):
        return stripped
    parts = _BASE64_PARTS.findall(stripped)
    if len(parts) < 2:
        return None
    joined = "".join(parts)
    separators = _BASE64_PARTS.sub("", stripped)
    if not joined or not separators or any(char.isalnum() for char in separators):
        return None
    if any(char.isspace() for char in separators) and (
        max(len(part) for part in parts) > 7 or not _looks_like_base64(joined)
    ):
        return None
    return joined


def _dedupe_split_candidates(values: list[tuple[str, int]]) -> list[tuple[str, int]]:
    unique: dict[tuple[str, int], None] = {}
    for value in values:
        unique[value] = None
    candidates = list(unique)
    candidates.sort(key=lambda value: (-len(value[0]), value[1]))
    return candidates[:MAX_SPLIT_BASE64_CANDIDATES]


def _scan_encoded(
    result: SafetyResult, key: str, canonical: str, operation: str, state: _EncodedState
) -> None:
    for match in _BASE64_RUN.finditer(canonical):
        candidate = match.group(0)
        if candidate in state.seen or not _looks_like_base64(candidate):
            continue
        state.seen.add(candidate)
        state.spans += 1
        if state.spans > MAX_BASE64_SPANS:
            result.add(SafetyFinding("span_limit", "encoded_payload"))
            return
        hard_signal = _hard_base64_signal(candidate)
        if len(candidate) % 4 or not _CANONICAL_BASE64.fullmatch(candidate):
            if hard_signal:
                result.add(SafetyFinding("invalid_base64", "encoded_payload"))
            continue
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            if hard_signal:
                result.add(SafetyFinding("invalid_base64", "encoded_payload"))
            continue
        if (
            len(decoded) > MAX_BASE64_DECODED_BYTES
            or state.decoded_bytes + len(decoded) > MAX_BASE64_DECODED_BYTES
        ):
            result.add(SafetyFinding("decoded_size_limit", "encoded_payload"))
            continue
        state.decoded_bytes += len(decoded)
        try:
            decoded_text = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            if hard_signal:
                result.add(SafetyFinding("invalid_utf8", "encoded_payload"))
            continue
        decoded_canonical, decoded_transformations = canonicalize_content(decoded_text)
        result.transformations.update(decoded_transformations)
        decoded_hits = _rule_scan(decoded_canonical) + _amg_scan(
            f"{key}.base64", decoded_canonical, operation=operation
        )
        if decoded_hits:
            result.add(SafetyFinding("unsafe_base64", "encoded_payload"))
            for finding in decoded_hits:
                result.add(finding)


def _rule_scan(value: str) -> list[SafetyFinding]:
    return [
        SafetyFinding(matched, reason, hits=(match.group(0),))
        for pattern, matched, reason in _RULES
        if (match := pattern.search(value)) is not None
    ]


def _split_instruction_rule_scan(value: str) -> list[SafetyFinding]:
    return [
        SafetyFinding(matched, reason, hits=(match.group(0),))
        for pattern, matched, reason in _SPLIT_INSTRUCTION_RULES
        if (match := pattern.search(value)) is not None
    ]


def _amg_scan(key: str, value: str, *, operation: str) -> list[SafetyFinding]:
    if not value:
        return []
    findings: list[SafetyFinding] = []
    for detector in _DETECTORS:
        detection = detector.inspect(key, value, operation=operation)
        if not detection.matched:
            continue
        name = str(detection.detector)
        severity = getattr(detection.severity, "value", detection.severity)
        metadata = detection.metadata if isinstance(detection.metadata, dict) else {}
        raw_hits = metadata.get("hits", [])
        hits = tuple(str(hit) for hit in raw_hits if isinstance(hit, str))
        if name == "sensitive_data" and not _keep_sensitive_detection(value, hits):
            continue
        findings.append(
            SafetyFinding(
                hits[0] if hits else name,
                _REASON_MAP.get(name, name),
                name,
                str(severity) if severity is not None else None,
                hits,
            )
        )
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
    if _hard_base64_signal(candidate) or _weak_base64_signal(candidate):
        return True
    if len(candidate) % 4:
        return False
    try:
        decoded = base64.b64decode(candidate, validate=True)
        text = decoded.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return bool(text and all(char.isprintable() or char.isspace() for char in text))


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
