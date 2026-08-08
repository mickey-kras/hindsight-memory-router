from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agent_memory_guard.detectors import (
    ExcessiveAutonomyDetector,
    PrivilegeEscalationDetector,
    PromptInjectionDetector,
    SensitiveDataDetector,
    ToolAbuseDetector,
)

MAX_CANONICAL_BYTES = 64 * 1024
MAX_BASE64_SPANS = 8
MAX_BASE64_DECODED_BYTES = 16 * 1024
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]{16,}")
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
_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), "ignore previous instructions", "prompt_injection"),
    (re.compile(r"system\s+prompt", re.I), "system prompt", "prompt_injection"),
    (re.compile(r"developer\s+message", re.I), "developer message", "prompt_injection"),
    (re.compile(r"new\s+instructions", re.I), "new instructions", "prompt_injection"),
    (re.compile(r"you\s+are\s+now", re.I), "you are now", "prompt_injection"),
    (re.compile(r"write\s+this\s+to\s+memory", re.I), "write this to memory", "prompt_injection"),
    (re.compile(r"remember\s+this\s+as\s+truth", re.I), "remember this as truth", "prompt_injection"),
    (re.compile(r"store\s+this\s+as\s+core\s+memory", re.I), "store this as core memory", "prompt_injection"),
    (re.compile(r"overwrite\s+permissions", re.I), "overwrite permissions", "permission_rewrite"),
    (re.compile(r"reveal\s+(the\s+)?(secret|token|key)", re.I), "reveal secret", "secret_like"),
    (re.compile(r"\bapi[_ -]?key\b", re.I), "api key", "secret_like"),
    (re.compile(r"private\s+key", re.I), "private key", "secret_like"),
    (re.compile(r"BEGIN\s+OPENSSH\s+PRIVATE\s+KEY", re.I), "private key block", "secret_like"),
    (re.compile(r"exfiltrate", re.I), "exfiltrate", "secret_like"),
)


@dataclass(frozen=True, slots=True)
class SafetyFinding:
    matched: str
    reason: str
    detector: str | None = None
    severity: str | None = None
    hits: tuple[str, ...] = field(default=(), compare=False, repr=False)

    def public(self) -> dict[str, str]:
        result = {"matched": self.matched, "reason": self.reason}
        if self.detector is not None:
            result["detector"] = self.detector
        if self.severity is not None:
            result["severity"] = self.severity
        return result


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


def canonicalize_content(content: str) -> tuple[str, set[str]]:
    normalized = unicodedata.normalize("NFKC", content)
    transformations: set[str] = set()
    if normalized != content:
        transformations.add("nfkc")
    chars: list[str] = []
    removed = False
    for char in normalized:
        cp = ord(char)
        invisible = (
            cp in {0x200B, 0x200C, 0x200D, 0x2060}
            or 0xFE00 <= cp <= 0xFE0F
            or 0xE0000 <= cp <= 0xE007F
        )
        if invisible:
            removed = True
        else:
            chars.append(char)
    if removed:
        transformations.add("invisible")
    return "".join(chars), transformations


def scan_content(content: str, *, operation: str = "read", key: str = "content") -> SafetyResult:
    return _scan_fields([(key, content)], operation=operation)


def scan_retain_body(body: dict[str, Any]) -> SafetyResult:
    fields: list[tuple[str, str]] = []
    for index, item in enumerate(body.get("items", [])):
        if not isinstance(item, dict):
            continue
        values: list[tuple[str, Any]] = [
            (f"items.{index}.content", item.get("content")),
            (f"items.{index}.context", item.get("context")),
            (f"items.{index}.document_id", item.get("document_id")),
        ]
        values.extend((f"items.{index}.tags.{i}", value) for i, value in enumerate(item.get("tags") or []))
        values.extend((f"items.{index}.metadata.{name}", value) for name, value in (item.get("metadata") or {}).items())
        fields.extend((name, value) for name, value in values if isinstance(value, str))
    return _scan_fields(fields, operation="write")


def scan_recall_result(result: dict[str, Any]) -> SafetyResult:
    return _scan_fields([("recalled_memory.text", str(result.get("text", "")))], operation="read")


def _scan_fields(fields: Iterable[tuple[str, str]], *, operation: str) -> SafetyResult:
    result = SafetyResult()
    canonical_fields: list[tuple[str, str]] = []
    direct_rule_matches: set[str] = set()
    decoded_total = 0
    span_count = 0
    for key, raw in fields:
        canonical, transformations = canonicalize_content(raw)
        result.transformations.update(transformations)
        canonical_fields.append((key, canonical))
        if "invisible" in transformations:
            result.add(SafetyFinding("invisible_unicode", "invisible_unicode"))
        for finding in _rule_scan(canonical):
            result.add(finding)
            direct_rule_matches.add(finding.matched)
        for finding in _amg_scan(key, canonical, operation=operation):
            result.add(finding)
        for match in _BASE64_RUN.finditer(canonical):
            candidate = match.group(0)
            if not _looks_like_base64(candidate):
                continue
            span_count += 1
            if span_count > MAX_BASE64_SPANS:
                result.add(SafetyFinding("span_limit", "encoded_payload"))
                break
            if len(candidate) % 4 or not _CANONICAL_BASE64.fullmatch(candidate):
                result.add(SafetyFinding("invalid_base64", "encoded_payload"))
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True)
            except (binascii.Error, ValueError):
                result.add(SafetyFinding("invalid_base64", "encoded_payload"))
                continue
            if len(decoded) > MAX_BASE64_DECODED_BYTES or decoded_total + len(decoded) > MAX_BASE64_DECODED_BYTES:
                result.add(SafetyFinding("decoded_size_limit", "encoded_payload"))
                continue
            decoded_total += len(decoded)
            try:
                decoded_text = decoded.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                result.add(SafetyFinding("invalid_utf8", "encoded_payload"))
                continue
            decoded_canonical, decoded_transformations = canonicalize_content(decoded_text)
            result.transformations.update(decoded_transformations)
            decoded_hits = _rule_scan(decoded_canonical) + _amg_scan(f"{key}.base64", decoded_canonical, operation=operation)
            if decoded_hits:
                result.add(SafetyFinding("unsafe_base64", "encoded_payload"))
                for finding in decoded_hits:
                    result.add(finding)
    window = ""
    window_fields: list[str] = []
    for key, canonical in canonical_fields:
        window = _bounded_append(window, canonical)
        window_fields.append(canonical)
        if len(window_fields) < 2:
            continue
        for finding in _rule_scan(window):
            if finding.matched not in direct_rule_matches:
                result.add(SafetyFinding(finding.matched, "split_instruction"))
        for finding in _amg_scan(f"rolling.{key}", window, operation=operation):
            if any(_crosses_field_boundary(hit, window_fields) for hit in finding.hits):
                result.add(SafetyFinding(finding.matched, "split_instruction", finding.detector, finding.severity, finding.hits))
    return result


def _rule_scan(value: str) -> list[SafetyFinding]:
    return [SafetyFinding(matched, reason, hits=(match.group(0),)) for pattern, matched, reason in _RULES if (match := pattern.search(value)) is not None]


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
        findings.append(SafetyFinding(hits[0] if hits else name, _REASON_MAP.get(name, name), name, str(severity) if severity is not None else None, hits))
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
    mixed_case = bool(re.search(r"[a-z]", candidate) and re.search(r"[A-Z]", candidate))
    return bool(re.search(r"[=+/]", candidate) or (mixed_case and re.search(r"\d", candidate)))


def _bounded_append(window: str, field: str) -> str:
    data = (f"{window} {field}" if window else field).encode("utf-8")
    if len(data) <= MAX_CANONICAL_BYTES:
        return data.decode("utf-8")
    suffix = data[-MAX_CANONICAL_BYTES:]
    while suffix:
        try:
            return suffix.decode("utf-8")
        except UnicodeDecodeError as exc:
            suffix = suffix[exc.start + 1 :]
    return ""
