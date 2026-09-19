from __future__ import annotations

import threading

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

AUTH_FAILURES_TOTAL = "memory_router_auth_failures_total"
RATE_LIMITED_TOTAL = "memory_router_rate_limited_responses_total"
CAPACITY_REJECTIONS_TOTAL = "memory_router_quarantine_capacity_rejections_total"
RECALL_DEGRADED_BANKS_TOTAL = "memory_router_recall_degraded_banks_total"
SWEEPER_FAILURES_TOTAL = "memory_router_sweeper_failures_total"
REVIEW_SIDE_EFFECT_STARTED_ITEMS = "memory_router_review_side_effect_started_items"

_DEFINITIONS = (
    (AUTH_FAILURES_TOTAL, "counter", "Authentication failures by route class."),
    (RATE_LIMITED_TOTAL, "counter", "HTTP 429 rate-limit responses by route class."),
    (
        CAPACITY_REJECTIONS_TOTAL,
        "counter",
        "Quarantine admissions rejected with HTTP 507 by route class.",
    ),
    (
        RECALL_DEGRADED_BANKS_TOTAL,
        "counter",
        "Hindsight recall bank calls that degraded to partial results.",
    ),
    (SWEEPER_FAILURES_TOTAL, "counter", "Quarantine sweeper iterations that failed."),
    (
        REVIEW_SIDE_EFFECT_STARTED_ITEMS,
        "gauge",
        "Quarantine items waiting for review side-effect reconciliation.",
    ),
)

_lock = threading.Lock()
_values: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}


def record_auth_failure(route_class: str) -> None:
    _increment(AUTH_FAILURES_TOTAL, (("route_class", route_class),))


def record_rate_limited(route_class: str) -> None:
    _increment(RATE_LIMITED_TOTAL, (("route_class", route_class),))


def record_capacity_rejection(route_class: str) -> None:
    _increment(CAPACITY_REJECTIONS_TOTAL, (("route_class", route_class),))


def record_recall_degraded_bank() -> None:
    _increment(RECALL_DEGRADED_BANKS_TOTAL, ())


def record_sweeper_failure() -> None:
    _increment(SWEEPER_FAILURES_TOTAL, ())


def set_review_side_effect_started(count: int) -> None:
    with _lock:
        _values[(REVIEW_SIDE_EFFECT_STARTED_ITEMS, ())] = count


def render() -> str:
    with _lock:
        snapshot = sorted(_values.items())
    lines: list[str] = []
    for name, kind, help_text in _DEFINITIONS:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for (metric, labels), value in snapshot:
            if metric == name:
                lines.append(f"{name}{_label_text(labels)} {value}")
    return "\n".join(lines) + "\n"


def reset() -> None:
    with _lock:
        _values.clear()


def _increment(name: str, labels: tuple[tuple[str, str], ...]) -> None:
    with _lock:
        key = (name, labels)
        _values[key] = _values.get(key, 0) + 1


def _label_text(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    rendered = ",".join(f'{key}="{_escape(value)}"' for key, value in labels)
    return "{" + rendered + "}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
