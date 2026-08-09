from memory_router.dedupe import request_family_identity


def test_request_family_identity_uses_unicode_casefolding() -> None:
    sharp_s = request_family_identity(
        "retain_request", "suspicious_content", "writer", {"content": "Straße"}
    )
    ascii_equivalent = request_family_identity(
        "retain_request", "suspicious_content", "writer", {"content": "STRASSE"}
    )
    assert sharp_s == ascii_equivalent
