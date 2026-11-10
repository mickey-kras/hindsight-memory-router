from __future__ import annotations

from typing import Any

import pytest

from memory_router.audit_summary import security_audit_summary


@pytest.mark.parametrize(
    ("reason", "payload", "expected"),
    [
        ("auth_failed", {"route_group": "router"}, "Authentication failed: router"),
        ("auth_failed", {"route_group": "admin"}, "Authentication failed: admin"),
        ("auth_failed", {"route_group": "secret\nvalue"}, "Authentication failed: unmatched"),
        (
            "denied_endpoint",
            {
                "method": "delete",
                "path": "/v1/default/banks/private/documents/private-id?key=secret",
            },
            "Denied: DELETE /v1/default/banks/{bank_id}/documents/{document_id}",
        ),
        (
            "denied_endpoint",
            {"method": "GET\nsecret", "path": "/secret/" + "x" * 5000},
            "Denied: OTHER /unmatched",
        ),
        (
            "denied_endpoint",
            {"method": "get", "path": "/admin/private-token?secret=value"},
            "Denied: GET /admin/{unmatched}",
        ),
        (
            "denied_endpoint",
            {"method": "get", "path": "/v1/default/banks/private/private-token"},
            "Denied: GET /v1/default/banks/{bank_id}/{unmatched}",
        ),
        ("denied_endpoint", {"method": "get", "path": "/metrics"}, "Denied: GET /metrics"),
        (
            "openclaw_unknown_writer",
            {"method": "post", "resource": "reflect", "body": "secret"},
            "Unknown writer: writer; POST reflect",
        ),
        (
            "openclaw_unknown_writer",
            {"method": "get", "resource": "private-token"},
            "Unknown writer: writer; GET unmatched",
        ),
    ],
)
def test_audit_summaries_only_show_bounded_route_metadata(
    reason: str, payload: dict[str, Any], expected: str
) -> None:
    assert (
        security_audit_summary(
            {"kind": "security_event", "reason": reason, "writerId": "writer", "payload": payload}
        )
        == expected
    )


def test_unsafe_writer_labels_use_a_digest() -> None:
    summary = security_audit_summary(
        {
            "kind": "security_event",
            "reason": "openclaw_unknown_writer",
            "writerId": "secret\n" * 1000,
            "payload": {"method": "GET", "resource": ""},
        }
    )
    assert summary is not None
    assert summary.startswith("Unknown writer: sha256:")
    assert "secret" not in summary
    assert len(summary) < 100


@pytest.mark.parametrize(
    "reason",
    [
        "recalled_memory_too_large",
        "recall_request_too_large",
        "recalled_suspicious_aggregate",
        "openclaw_suspicious_provider_response",
    ],
)
def test_content_audit_reasons_do_not_expose_payload_summaries(reason: str) -> None:
    assert (
        security_audit_summary(
            {"kind": "security_event", "reason": reason, "payload": {"content": "secret"}}
        )
        is None
    )


def test_review_payload_cannot_supply_a_plaintext_summary() -> None:
    assert (
        security_audit_summary(
            {
                "kind": "blocked_content",
                "reason": "auth_failed",
                "payload": {"route_group": "router"},
            }
        )
        is None
    )
    assert (
        security_audit_summary(
            {"kind": "security_event", "reason": "auth_failed", "payload": "secret"}
        )
        is None
    )
