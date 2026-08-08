from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable

from agent_memory_guard.detectors import (
    ExcessiveAutonomyDetector,
    PrivilegeEscalationDetector,
    PromptInjectionDetector,
    SensitiveDataDetector,
    ToolAbuseDetector,
)

from .models import MemoryItem, RecallResult, RetainBody

MAX_CANONICAL_BYTES = 64 * 1024
MAX_BASE64_SPANS = 8
MAX_BASE64_DECODED_BYTES = 16 * 1024
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/=]{16,}")
_CANONICAL_BASE64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")

# These remain because AMG 0.3.0 does not own the same exact classification semantics.
# Direct overlaps (notably "ignore previous instructions") are intentionally left to AMG.
_FALLBACK_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"system\s+prompt", re.I), "system prompt", "prompt_injection"),
    (re.compile(r"developer\s+message", re.I), "developer message", "prompt_injection"),
    (re.compile(r"new\s+instructions", re.I), "new instructions", "prompt_injection"),
    (re.compile(r"you\s+are\s+now", re.I), "you are now", "prompt_injection"),
    (re.compile(r"write\s+this\s+to\s+memory", re.I), "write this to memory", "prompt_injection"),
    (re.compile(r"remember\s+this\s+as\s+truth", re.I), "remember this as truth", "prompt_injection"),
    (re.compile(r"store\s+this\s+as\s+core\s+memory", re.I), "store this as core memory", "prompt_injection"),
    (re.compile(r"overwrite\s+permissions", re.I), "overwrite permissions", "permission_rewrite"),
    (re.compile(r"reveal\s+(?:the\s+)?(?:secret|token|key)", re.I), "reveal secret", "secret_like"),
    (re.compile(r"\bapi[_ -]?key\b", re.I), "api key", "secret_like"),
    (re.compile(r"private\s+key", re.I), "private key", "secret_like"),
    (re.compile(r"BEGIN\s+OPENSSH\s+PRIVATE\s+KEY", re.I), "private key block", "secret_like"),
    (re.compile(r"exfiltrate", re.I), "exfiltrate", "secret_like"),
)

_AMG_REASON = {
    "prompt_injection": "prompt_injection",
    "sensitive_data": "secret_like",
    "tool_abuse": "prompt_injection",
    "privilege_escalation": "permission_rewrite",
    "excessive_autonomy": "permission_rewrite",
}


@dataclass(frozen=True, slots=True)
class SafetyFinding:
    matched: str
    reason: str


@dataclass(frozen=True, slots=True)
class SafetyResult:
    safe: bool
    findings: tuple[SafetyFinding, ...]
    transformations: tuple[str, ...]


class ThreatDetector:
    """Stateless in-process OWASP AMG detector composition."""

    def __init__(self) -> None:
        self._detectors = (
            PromptInjectionDetector(),
            SensitiveDataDetector(),
            ToolAbuseDetector(),
            PrivilegeEscalationDetector(),
            ExcessiveAutonomyDetector(),
        )

    @property
    def enabled_names(self) -> tuple[str, ...]:
        return tuple(str(detector.name) for detector in self._detectors)

    def inspect(self, key: str, value: str, *, operation: str) -> list[SafetyFinding]:
        findings: list[SafetyFinding] = []
        for detector in self._detectors:
            result = detector.inspect(key, value, operation=operation)
            if not bool(getattr(result, "matched", False)):
                continue
            name = str(getattr(result, "detector", getattr(detector, "name", "unknown")))
            reason = _AMG_REASON.get(name, "prompt_injection")
            _add_finding(findings, SafetyFinding(f"amg:{name}", reason))
        return findings


DEFAULT_THREAT_DETECTOR = ThreatDetector()


def scan_content(
    content: str,
    *,
    operation: str = "write",
    detector: ThreatDetector = DEFAULT_THREAT_DETECTOR,
) -> SafetyResult:
    return _scan_fields([content], operation=operation, detector=detector)


def scan_retain_body(
    body: RetainBody, *, detector: ThreatDetector = DEFAULT_THREAT_DETECTOR
) -> SafetyResult:
    fields: list[str] = []
    for item in body.items:
        fields.extend(memory_item_content_fields(item))
    return _scan_fields(fields, operation="write", detector=detector)


def scan_recall_result(
    result: RecallResult, *, detector: ThreatDetector = DEFAULT_THREAT_DETECTOR
) -> SafetyResult:
    return _scan_fields([result.text], operation="read", detector=detector)


def memory_item_content_fields(item: MemoryItem) -> list[str]:
    values: list[object] = [
        item.content,
        item.context or "",
        item.document_id or "",
        *(item.tags or []),
        *(item.metadata or {}).values(),
    ]
    return [value for value in values if isinstance(value, str)]


def canonicalize_content(content: str) -> tuple[str, tuple[str, ...]]:
    normalized = unicodedata.normalize("NFKC", content)
    transformations: list[str] = []
    if normalized != content:
        transformations.append("nfkc")
    stripped = "".join(ch for ch in normalized if not _is_invisible(ch))
    if stripped != normalized:
        transformations.append("invisible")
    return stripped, tuple(transformations)


def _scan_fields(
    fields: Iterable[str], *, operation: str, detector: ThreatDetector
) -> SafetyResult:
    findings: list[SafetyFinding] = []
    transformations: list[str] = []
    canonical_fields: list[str] = []
    direct_matches: set[str] = set()
    decoded_bytes = 0
    base64_spans = 0

    for index, field in enumerate(fields):
        canonical, changed = canonicalize_content(field)
        canonical_fields.append(canonical)
        for transformation in changed:
            if transformation not in transformations:
                transformations.append(transformation)
        if "invisible" in changed:
            _add_finding(findings, SafetyFinding("invisible_unicode", "invisible_unicode"))

        direct = _detect(canonical, f"field.{index}", operation, detector)
        for finding in direct:
            _add_finding(findings, finding)
            direct_matches.add(finding.matched)

        for candidate in _base64_candidates(canonical):
            base64_spans += 1
            if base64_spans > MAX_BASE64_SPANS:
                _add_finding(findings, SafetyFinding("span_limit", "encoded_payload"))
                break
            if len(candidate) % 4 != 0 or not _CANONICAL_BASE64.fullmatch(candidate):
                _add_finding(findings, SafetyFinding("invalid_base64", "encoded_payload"))
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True)
            except binascii.Error:
                _add_finding(findings, SafetyFinding("invalid_base64", "encoded_payload"))
                continue
            if base64.b64encode(decoded).decode("ascii") != candidate:
                continue
            if len(decoded) > MAX_BASE64_DECODED_BYTES or decoded_bytes + len(decoded) > MAX_BASE64_DECODED_BYTES:
                _add_finding(findings, SafetyFinding("decoded_size_limit", "encoded_payload"))
                continue
            decoded_bytes += len(decoded)
            try:
                decoded_text = decoded.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                _add_finding(findings, SafetyFinding("invalid_utf8", "encoded_payload"))
                continue
            decoded_canonical, decoded_changes = canonicalize_content(decoded_text)
            for transformation in decoded_changes:
                if transformation not in transformations:
                    transformations.append(transformation)
            decoded_findings = _detect(
                decoded_canonical, f"field.{index}.base64", operation, detector
            )
            if decoded_findings:
                _add_finding(findings, SafetyFinding("unsafe_base64", "encoded_payload"))
                for finding in decoded_findings:
                    _add_finding(findings, finding)

    window = ""
    for index, field in enumerate(canonical_fields):
        window = _bounded_append(window, field)
        for finding in _detect(window, f"combined.{index}", operation, detector):
            if finding.matched not in direct_matches:
                _add_finding(findings, SafetyFinding(finding.matched, "split_instruction"))

    return SafetyResult(not findings, tuple(findings), tuple(transformations))


def _detect(
    content: str, key: str, operation: str, detector: ThreatDetector
) -> list[SafetyFinding]:
    findings = detector.inspect(key, content, operation=operation)
    for pattern, matched, reason in _FALLBACK_RULES:
        if pattern.search(content):
            _add_finding(findings, SafetyFinding(matched, reason))
    return findings


def _base64_candidates(content: str) -> list[str]:
    candidates: list[str] = []
    for match in _BASE64_TOKEN.finditer(content):
        candidate = match.group(0)
        mixed_case = any(ch.islower() for ch in candidate) and any(ch.isupper() for ch in candidate)
        if any(ch in candidate for ch in "=+/") or (mixed_case and any(ch.isdigit() for ch in candidate)):
            candidates.append(candidate)
    return candidates


def _bounded_append(window: str, field: str) -> str:
    combined = f"{window} {field}" if window else field
    encoded = combined.encode("utf-8")
    if len(encoded) <= MAX_CANONICAL_BYTES:
        return combined
    tail = encoded[-MAX_CANONICAL_BYTES:]
    while tail and (tail[0] & 0xC0) == 0x80:
        tail = tail[1:]
    return tail.decode("utf-8", errors="strict")


def _is_invisible(character: str) -> bool:
    code = ord(character)
    return (
        code in {0x200B, 0x200C, 0x200D, 0x2060}
        or 0xFE00 <= code <= 0xFE0F
        or 0xE0000 <= code <= 0xE007F
    )


def _add_finding(findings: list[SafetyFinding], finding: SafetyFinding) -> None:
    if not any(
        candidate.reason == finding.reason and candidate.matched == finding.matched
        for candidate in findings
    ):
        findings.append(finding)
