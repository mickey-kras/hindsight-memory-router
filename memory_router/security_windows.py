from __future__ import annotations

from .security_rules import _rule_edge_matches, _trim_boundary_padding

MAX_SPLIT_WINDOW_BYTES = 512


def _join_variants(
    fragments: list[str], *, spaced: str | None = None, compact: str | None = None
) -> tuple[str, ...]:
    """Return bounded joins; split rules also scan without whitespace."""
    if len(fragments) < 2:
        return tuple(fragments)
    variants = [
        _bounded_utf8_suffix(" ".join(fragments).encode()),
        _bounded_utf8_suffix("".join(fragments).encode()),
        _bounded_utf8_suffix(f"{fragments[0]} {''.join(fragments[1:])}".encode()),
    ]
    if spaced is not None:
        variants.append(spaced)
    if compact is not None:
        variants.append(compact)
    return tuple(dict.fromkeys(variants))


def _bounded_append(window: str, field: str) -> str:
    return _bounded_utf8_suffix((f"{window} {field}" if window else field).encode("utf-8"))


def _junction_variants(spaced: str, compact: str, field: str) -> tuple[str, ...]:
    """Keep both sides of a junction before either rolling side is truncated."""
    encoded = field.encode("utf-8")
    if (
        len(spaced.encode("utf-8")) + 1 + len(encoded) <= MAX_SPLIT_WINDOW_BYTES
        and len(compact.encode("utf-8")) + len(encoded) <= MAX_SPLIT_WINDOW_BYTES
    ):
        return ()
    prefix = _bounded_utf8_prefix(encoded)
    return tuple(
        dict.fromkeys(
            (
                f"{spaced} {prefix}" if spaced else prefix,
                f"{compact}{prefix}" if compact else prefix,
            )
        )
    )


def _trim_evasion_variants(
    previous: str, current: str, *, deadline: float | None = None
) -> tuple[str, ...]:
    """Remove low-entropy boundary padding in bounded linear time."""
    trimmed_previous = _trim_boundary_padding(previous, from_start=False)
    trimmed_current = _trim_boundary_padding(current, from_start=True)
    variants: list[str] = []
    if trimmed_previous != previous or trimmed_current != current:
        left = _bounded_utf8_suffix(trimmed_previous.encode("utf-8"))
        right = _bounded_utf8_prefix(trimmed_current.encode("utf-8"))
        variants.extend((f"{left} {right}", f"{left}{right}"))
    variants.extend(_rule_edge_matches(previous, current, deadline=deadline))
    return tuple(dict.fromkeys(variants))


def _sequence_join_variants(
    fragments: list[str], *, deadline: float | None = None
) -> tuple[str, ...]:
    prefix = fragments[:-1]
    spaced = _bounded_utf8_suffix(" ".join(prefix).encode())
    compact = _bounded_utf8_suffix("".join(prefix).encode())
    variants = list(_junction_variants(spaced, compact, fragments[-1]))
    spaced = _bounded_append(spaced, fragments[-1])
    compact = _bounded_utf8_suffix(f"{compact}{fragments[-1]}".encode())
    variants.extend(_join_variants(fragments, spaced=spaced, compact=compact))
    if len(fragments) >= 2:
        trimmed = [
            _trim_boundary_padding(fragment, from_start=index > 0)
            for index, fragment in enumerate(fragments)
        ]
        trimmed[:-1] = [
            _trim_boundary_padding(fragment, from_start=False) for fragment in trimmed[:-1]
        ]
        variants.extend(_join_variants(trimmed))
        if len(fragments) == 2:
            variants.extend(_rule_edge_matches(fragments[0], fragments[1], deadline=deadline))
    return tuple(dict.fromkeys(variants))


def _bounded_utf8_prefix(data: bytes) -> str:
    if len(data) <= MAX_SPLIT_WINDOW_BYTES:
        return data.decode("utf-8")
    prefix = data[:MAX_SPLIT_WINDOW_BYTES]
    while prefix:
        try:
            return prefix.decode("utf-8")
        except UnicodeDecodeError as exc:
            prefix = prefix[: exc.start]
    return ""


def _bounded_utf8_suffix(data: bytes) -> str:
    if len(data) <= MAX_SPLIT_WINDOW_BYTES:
        return data.decode("utf-8")
    suffix = data[-MAX_SPLIT_WINDOW_BYTES:]
    while suffix:
        try:
            return suffix.decode("utf-8")
        except UnicodeDecodeError as exc:
            suffix = suffix[exc.start + 1 :]
    return ""
