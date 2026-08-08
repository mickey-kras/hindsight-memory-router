from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ..quarantine.crypto import decrypt_envelope, parse_envelope


def extract_envelope(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and "encrypted" in value:
        return parse_envelope(value["encrypted"])
    return parse_envelope(value)


def escaped_review_value(value: Any) -> tuple[bool, Any]:
    changed = False

    def visit(candidate: Any) -> Any:
        nonlocal changed
        if isinstance(candidate, str):
            escaped = _escape_controls(candidate)
            changed = changed or escaped != candidate
            return escaped
        if isinstance(candidate, list):
            return [visit(entry) for entry in candidate]
        if isinstance(candidate, dict):
            result: dict[str, Any] = {}
            for key, child in candidate.items():
                escaped_key = _escape_controls(key)
                changed = changed or escaped_key != key
                result[escaped_key] = visit(child)
            return result
        return candidate

    visible = visit(value)
    return changed, visible


def _escape_controls(content: str) -> str:
    visible = []
    for character in content:
        code = ord(character)
        if not _is_invisible_or_control(code):
            visible.append(character)
        elif character == "\n":
            visible.append("\\n")
        elif character == "\r":
            visible.append("\\r")
        elif character == "\t":
            visible.append("\\t")
        elif code <= 0xFFFF:
            visible.append(f"\\u{code:04X}")
        else:
            visible.append(f"\\u{{{code:X}}}")
    return "".join(visible)


def _is_invisible_or_control(code: int) -> bool:
    return (
        code <= 0x1F
        or 0x7F <= code <= 0x9F
        or code in {0x200B, 0x200C, 0x200D, 0x2060}
        or 0xFE00 <= code <= 0xFE0F
        or 0xE0000 <= code <= 0xE007F
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(argv) != 1:
            raise ValueError(
                "usage: <private-key-command> | decrypt-quarantine <encrypted-response.json>"
            )
        private_key = sys.stdin.read().strip()
        if not private_key:
            raise ValueError("private key is required on stdin")
        response = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        decrypted = decrypt_envelope(extract_envelope(response), private_key).to_dict()
        changed, visible = escaped_review_value(decrypted)
        if changed:
            print(
                "warning: decrypted evidence contains invisible or control characters; stdout preserves the original evidence unchanged.",
                file=sys.stderr,
            )
            print("escaped visible representation:", file=sys.stderr)
            print(json.dumps(visible, indent=2, ensure_ascii=False), file=sys.stderr)
        print(json.dumps(decrypted, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"decrypt-quarantine failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
