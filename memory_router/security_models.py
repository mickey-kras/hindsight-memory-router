from __future__ import annotations

from dataclasses import dataclass, field


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
    reviewed_fields: frozenset[str]
