import pytest

from memory_router.envelope import parse_decrypted


def test_parse_decrypted_uses_strict_pydantic_boundary_and_preserves_extras() -> None:
    value = {
        "quarantine_id": "q_20260808_0123456789abcdef",
        "created_at": "2026-08-08T12:00:00.000Z",
        "reason": "suspicious_content",
        "payload": {"content": "x"},
        "extra": {"preserved": True},
    }
    assert parse_decrypted(value) == value

    with pytest.raises(ValueError, match="writer_id must be a non-empty string"):
        parse_decrypted({**value, "writer_id": None})

    with pytest.raises(ValueError, match="invalid quarantine reason"):
        parse_decrypted({**value, "reason": "other"})
