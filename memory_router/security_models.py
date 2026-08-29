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
