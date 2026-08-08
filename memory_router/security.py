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


@dataclass(frozen=True, slots=True)
class SafetyFinding:
    matched: str
    reason: str
    detector: str | None = None
    severity: str | None = None

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
        values.extend(
            (f"items.{index}.tags.{i}", value) for i, value in enumerate(item.get("tags") or [])
        )
        values.extend(
            (f"items.{index}.metadata.{name}", value)
            for name, value in (item.get("metadata") or {}).items()
        )
        fields.extend((name, value) for name, value in values if isinstance(value, str))
    return _scan_fields(fields, operation="write")


def scan_recall_result(result: dict[str, Any]) -> SafetyResult:
    return _scan_fields([("recalled_memory.text", str(result.get("text", "")))], operation="read")


def _scan_fields(fields: Iterable[tuple[str, str]], *, operation: str) -> SafetyResult:
    result = SafetyResult()
    canonical_fields: list[tuple[str, str]] = []
    decoded_total = 0
    span_count = 0
    direct_hits: set[str] = set()
    for key, raw in fields:
        canonical, transformations = canonicalize_content(raw)
        result.transformations.update(transformations)
        canonical_fields.append((key, canonical))
        if "invisible" in transformations:
            result.add(SafetyFinding("invisible_unicode", "invisible_unicode"))
        for finding in _amg_scan(key, canonical, operation=operation):
            direct_hits.add(finding.detector or finding.matched)
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
            if (
                len(decoded) > MAX_BASE64_DECODED_BYTES
                or decoded_total + len(decoded) > MAX_BASE64_DECODED_BYTES
            ):
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
            decoded_hits = _amg_scan(f"{key}.base64", decoded_canonical, operation=operation)
            if decoded_hits:
                result.add(SafetyFinding("unsafe_base64", "encoded_payload"))
                for finding in decoded_hits:
                    result.add(finding)
    window = ""
    for key, canonical in canonical_fields:
        window = _bounded_append(window, canonical)
        for finding in _amg_scan(f"rolling.{key}", window, operation=operation):
            detector = finding.detector or finding.matched
            if detector not in direct_hits:
                result.add(
                    SafetyFinding(
                        finding.matched, "split_instruction", finding.detector, finding.severity
                    )
                )
    return result


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
        findings.append(
            SafetyFinding(
                name,
                _REASON_MAP.get(name, name),
                name,
                str(severity) if severity is not None else None,
            )
        )
    return findings


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
