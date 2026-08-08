from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from memory_router.envelope import decrypt_envelope


def extract_envelope(value: Any) -> Any:
    if isinstance(value, dict) and "encrypted" in value:
        return value["encrypted"]
    return value


def escaped_review_value(value: Any) -> tuple[bool, Any]:
    changed = False

    def visit(candidate: Any) -> Any:
        nonlocal changed
        if isinstance(candidate, str):
            escaped = _escape_string(candidate)
            changed = changed or escaped != candidate
            return escaped
        if isinstance(candidate, list):
            return [visit(item) for item in candidate]
        if isinstance(candidate, dict):
            result: dict[str, Any] = {}
            for key, child in candidate.items():
                escaped_key = _escape_string(str(key))
                changed = changed or escaped_key != key
                result[escaped_key] = visit(child)
            return result
        return candidate

    return changed, visit(value)


def _escape_string(value: str) -> str:
    result: list[str] = []
    for character in value:
        codepoint = ord(character)
        if not _is_invisible_or_control(codepoint):
            result.append(character)
        elif character == "\n":
            result.append("\\n")
        elif character == "\r":
            result.append("\\r")
        elif character == "\t":
            result.append("\\t")
        elif codepoint <= 0xFFFF:
            result.append(f"\\u{codepoint:04X}")
        else:
            result.append(f"\\u{{{codepoint:X}}}")
    return "".join(result)


def _is_invisible_or_control(codepoint: int) -> bool:
    return (
        codepoint <= 0x1F
        or 0x7F <= codepoint <= 0x9F
        or codepoint in {0x200B, 0x200C, 0x200D, 0x2060}
        or 0xFE00 <= codepoint <= 0xFE0F
        or 0xE0000 <= codepoint <= 0xE007F
    )


def run(path: str) -> int:
    try:
        key_text = sys.stdin.read().strip()
        if not key_text:
            raise ValueError("decryption key is required on stdin")
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        decrypted = decrypt_envelope(extract_envelope(value), key_text)
        changed, visible = escaped_review_value(decrypted)
        if changed:
            print(
                "warning: decrypted evidence contains invisible or control characters; "
                "stdout preserves the original evidence unchanged.",
                file=sys.stderr,
            )
            print("escaped visible representation:", file=sys.stderr)
            print(json.dumps(visible, indent=2, ensure_ascii=False), file=sys.stderr)
        print(json.dumps(decrypted, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"decrypt-quarantine failed: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: memory-router-decrypt-quarantine <encrypted-response.json>", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(run(sys.argv[1]))


if __name__ == "__main__":
    main()
