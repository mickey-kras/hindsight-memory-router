from __future__ import annotations

import base64
import binascii
import codecs
import re
import time
import unicodedata
from collections.abc import Iterable

from .security_models import SafetyFinding, SafetyResult, _EncodedState
from .security_rules import _add_unicode_findings, _amg_scan, _rule_scan
from .security_windows import _bounded_append, _bounded_utf8_suffix
from .unicode_security import (
    UnicodeScanDeadlineExceeded,
    canonicalize_content,
)

MAX_BASE64_SPANS = 8
MAX_BASE64_DECODED_BYTES = 16 * 1024
MAX_SPLIT_BASE64_CANDIDATES = 64
MAX_SPLIT_BASE64_FIELDS = 256
MAX_SPLIT_BASE64_SKIPS = 2
MAX_SPLIT_BASE64_CANDIDATE_BYTES = ((MAX_BASE64_DECODED_BYTES + 2) // 3) * 4
MAX_SPLIT_BASE64_WORK_BYTES = 512 * 1024
MAX_SPLIT_BASE64_RECOVERY_MIN_PARTS = 3
MAX_SPLIT_BASE64_RECOVERY_PAIR_PARTS = 64
MAX_SPLIT_BASE64_RECOVERY_TRIPLE_PARTS = 32
MAX_SPLIT_BASE64_RECOVERY_ATTEMPTS = 40_000
MAX_SPLIT_BASE64_RECOVERY_WORK_BYTES = 16 * 1024 * 1024
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{8,}(?![A-Za-z0-9+/=])")
_BASE64_CHARS = re.compile(r"^[A-Za-z0-9+/=]+$")
_BASE64_PARTS = re.compile(r"[A-Za-z0-9+/=]+")
_BASE64_IN_ALPHABET_SEPARATOR = re.compile(r"[+/]+")
_BASE64_LABEL_AFTER = re.compile(r"\s*:\s+")
_BASE64_COLON_AFTER = re.compile(r"\s*:")
_BASE64_JSON_LABEL_AFTER = re.compile(r"[\"']\s*:\s*")
_BASE64_NUMBERED_LABEL = re.compile(r"(?:part|chunk|fragment)\d*", re.I)
_CANONICAL_BASE64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_DecodedBase64Candidate = tuple[str, str, int, int, bool, bool]


def _split_base64_candidates(  # NOSONAR
    fields: Iterable[tuple[str, str, bool]],
    *,
    deadline: float | None = None,
    normalized_fragments: dict[str, tuple[str | None, bool]] | None = None,
    max_work_bytes: int = MAX_SPLIT_BASE64_WORK_BYTES,
) -> tuple[list[str], bool]:
    candidates: list[tuple[str, int]] = []
    completed: dict[str, None] = {}
    fragment_fields = 0
    work_bytes = 0
    exhausted = False
    unconditional_exhausted = False
    soft_exhausted = False

    def preserve_completed(value: str) -> None:
        if (
            len(value) >= 8
            and _padded_base64(value) is not None
            and _looks_like_base64(value)
            and (_decode_base64_fragment(value) is not None or _lossy_decodable_base64(value))
        ):
            completed[value] = None

    def add(next_candidates: list[tuple[str, int]], value: str, skipped: int) -> bool:
        nonlocal exhausted, unconditional_exhausted, work_bytes
        size = len(value)
        if size > MAX_SPLIT_BASE64_CANDIDATE_BYTES:
            unconditional_exhausted = True
            return True
        if work_bytes + size > max_work_bytes:
            exhausted = True
            return False
        work_bytes += size
        next_candidates.append((value, skipped))
        preserve_completed(value)
        return True

    for _, canonical, _ in fields:
        if deadline is not None and time.monotonic() >= deadline:
            unconditional_exhausted = True
            break
        if normalized_fragments is None:
            fragment, fragment_exhausted = _normalized_base64_fragment(canonical, deadline=deadline)
        elif canonical in normalized_fragments:
            fragment, fragment_exhausted = normalized_fragments[canonical]
        else:
            fragment, fragment_exhausted = _normalized_base64_fragment(canonical, deadline=deadline)
            normalized_fragments[canonical] = fragment, fragment_exhausted
        unconditional_exhausted |= fragment_exhausted
        if fragment is None:
            continue
        plausible_fragment = _plausible_base64_fragment(fragment)
        if _alphabet_separator_split_is_suspicious(fragment):
            # Base64-alphabet characters ("/" or "+") used as separators between
            # several plausible parts never decode as-is; fail closed instead of
            # silently dropping the split payload.
            unconditional_exhausted = True
        if len(fragment) > MAX_SPLIT_BASE64_CANDIDATE_BYTES:
            if plausible_fragment or any(_credible_base64_prefix(value) for value, _ in candidates):
                unconditional_exhausted = True
            continue
        next_candidates: list[tuple[str, int]] = []
        if not add(next_candidates, fragment, 0):
            break
        for candidate, skipped in candidates:
            if deadline is not None and time.monotonic() >= deadline:
                unconditional_exhausted = True
                break
            preserved = False
            if skipped >= MAX_SPLIT_BASE64_SKIPS and _credible_base64_prefix(candidate):
                soft_exhausted = True
            if "=" not in candidate:
                combined = candidate + fragment
                if _alphabet_separator_split_is_suspicious(combined):
                    unconditional_exhausted = True
                if len(combined) <= MAX_SPLIT_BASE64_CANDIDATE_BYTES and not add(
                    next_candidates, combined, skipped
                ):
                    break
                preserved = len(combined) <= MAX_SPLIT_BASE64_CANDIDATE_BYTES
            if skipped < MAX_SPLIT_BASE64_SKIPS and not add(
                next_candidates, candidate, skipped + 1
            ):
                break
            if skipped < MAX_SPLIT_BASE64_SKIPS:
                preserved = True
            if not preserved and candidate not in completed and _looks_like_base64(candidate):
                soft_exhausted = True
        next_candidates = [
            candidate
            for candidate in next_candidates
            if _viable_base64_prefix(candidate[0]) or _lossy_viable_base64_prefix(candidate[0])
        ]
        if plausible_fragment or any(
            _credible_base64_prefix(value) for value, _ in next_candidates
        ):
            fragment_fields += 1
            if fragment_fields > MAX_SPLIT_BASE64_FIELDS:
                unconditional_exhausted = True
                break
        if len(set(next_candidates)) > MAX_SPLIT_BASE64_CANDIDATES:
            soft_exhausted = True
        candidates = _dedupe_split_candidates(next_candidates)
        if exhausted:
            break
    return (
        list(completed),
        unconditional_exhausted or soft_exhausted or exhausted,
    )


def _split_decoded_base64_candidates(  # NOSONAR
    fields: Iterable[tuple[str, str, bool]],
    *,
    deadline: float | None = None,
    normalized_fragments: dict[str, tuple[str | None, bool]] | None = None,
    max_work_bytes: int = MAX_SPLIT_BASE64_WORK_BYTES,
) -> tuple[list[tuple[str, str]], bool]:
    candidates: list[_DecodedBase64Candidate] = []
    work_bytes = 0
    exhausted = False
    soft_exhausted = False

    def add(
        target: list[_DecodedBase64Candidate],
        candidate: _DecodedBase64Candidate,
    ) -> bool:
        nonlocal exhausted, work_bytes
        compact, spaced, _, _, _, _ = candidate
        size = len(compact.encode("utf-8")) + len(spaced.encode("utf-8"))
        if size > max_work_bytes:
            exhausted = True
            return True
        if work_bytes + size > max_work_bytes:
            exhausted = True
            return False
        work_bytes += size
        target.append(candidate)
        return True

    fragment_fields = 0
    for _, canonical, _ in fields:
        if deadline is not None and time.monotonic() >= deadline:
            exhausted = True
            break
        if normalized_fragments is None:
            fragment, fragment_exhausted = _normalized_base64_fragment(canonical, deadline=deadline)
        elif canonical in normalized_fragments:
            fragment, fragment_exhausted = normalized_fragments[canonical]
        else:
            fragment, fragment_exhausted = _normalized_base64_fragment(canonical, deadline=deadline)
            normalized_fragments[canonical] = fragment, fragment_exhausted
        exhausted |= fragment_exhausted
        if fragment is None:
            continue
        decoded = _decode_base64_fragment(fragment)
        if decoded is None:
            continue
        fragment_credible = _credible_base64_prefix(fragment)
        fragment_fields += 1
        if fragment_fields > MAX_SPLIT_BASE64_FIELDS:
            exhausted = True
            break
        next_candidates: list[_DecodedBase64Candidate] = []
        if not add(next_candidates, (decoded, decoded, 1, 0, True, fragment_credible)):
            break
        for compact, spaced, parts, skipped, terminated, credible in candidates:
            if deadline is not None and time.monotonic() >= deadline:
                exhausted = True
                break
            if not add(
                next_candidates,
                (
                    _bounded_utf8_suffix(f"{compact}{decoded}".encode()),
                    _bounded_append(spaced, decoded),
                    parts + 1,
                    skipped,
                    terminated,
                    credible or fragment_credible,
                ),
            ):
                exhausted = True
                break
            if skipped < MAX_SPLIT_BASE64_SKIPS and not add(
                next_candidates,
                (compact, spaced, parts, skipped + 1, terminated, credible),
            ):
                exhausted = True
                break
            if skipped >= MAX_SPLIT_BASE64_SKIPS and (credible or fragment_credible):
                soft_exhausted = True
        unique = dict.fromkeys(next_candidates)
        if len(unique) > MAX_SPLIT_BASE64_CANDIDATES and any(candidate[-1] for candidate in unique):
            soft_exhausted = True
        candidates = sorted(unique, key=lambda value: (-len(value[0]), value[3]))[
            :MAX_SPLIT_BASE64_CANDIDATES
        ]
        if exhausted:
            break
    return (
        [
            (compact, spaced)
            for compact, spaced, parts, _, terminated, _ in candidates
            if parts >= 2 and terminated
        ],
        exhausted or soft_exhausted,
    )


def _decode_base64_fragment(fragment: str) -> str | None:
    padded = _padded_base64(fragment)
    if padded is None:
        return None
    try:
        decoded = base64.b64decode(padded, validate=True)
        if len(decoded) > MAX_BASE64_DECODED_BYTES:
            return None
        text = decoded.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError):
        return None
    variants = _decoded_text_variants(text)
    return variants[0] if variants else None


def _lossy_ascii_decoded_text(decoded: bytes) -> str | None:
    """Fold undecodable bytes into sentinel controls so weak-signal payloads stay scannable.

    Only printable ASCII (plus tab/newline/return) survives; every other character
    becomes a NUL sentinel that ``_decoded_text_variants`` treats like any other
    control byte. The resulting variants are pure printable ASCII, so canonicalization
    cannot invent Unicode findings for random weak-signal tokens.
    """
    replaced = decoded.decode("utf-8", errors="replace")
    folded = "".join(
        char if char.isascii() and (char.isprintable() or char in "\t\n\r") else "\x00"
        for char in replaced
    )
    return folded if folded.strip("\x00").strip() else None


def _lossy_scannable_ascii(decoded: bytes) -> bool:
    """Whether lossy folding keeps enough ASCII text to be worth scanning.

    Split-join garbage decodes to mostly non-printable bytes (~37% printable
    on average), while a real payload with a few invalid bytes stays mostly
    printable ASCII. Requiring a printable majority keeps random joins out of
    the candidate pool so budgets behave like the strict path.
    """
    if not decoded:
        return False
    printable = sum(1 for byte in decoded if 0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D))
    return printable >= 8 and printable / len(decoded) >= 0.6


def _lossy_decodable_base64(candidate: str) -> bool:
    """Whether decoded bytes fail strict UTF-8 but keep scannable ASCII.

    Complements the strict decode paths so weak-signal split payloads with
    invalid UTF-8 survive to the lossy scan in ``_scan_encoded`` instead of
    being dropped before scanning. Strictly decodable candidates stay on the
    strict paths.
    """
    if _hard_base64_signal(candidate):
        # Hard-signal candidates already fail closed on invalid UTF-8 in
        # _scan_encoded; accepting them here would re-route random "+"/"/"
        # tokens into that fail-closed path and false-positive.
        return False
    padded = _padded_base64(candidate)
    if padded is None:
        return False
    try:
        decoded = base64.b64decode(padded, validate=True)
    except binascii.Error:
        return False
    if len(decoded) > MAX_BASE64_DECODED_BYTES:
        return False
    try:
        decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _lossy_scannable_ascii(decoded)
    return False


def _lossy_viable_base64_prefix(fragment: str) -> bool:
    """Fallback viability for joins dropped only due to invalid UTF-8.

    ``_viable_base64_prefix`` judges strictly decodable text; a weak-signal
    join whose decoded bytes are invalid UTF-8 but whose lossy folding keeps
    scannable ASCII stays in the candidate pool so ``_scan_encoded`` can
    lossy-scan it. Strictly decodable prefixes remain ``_viable_base64_prefix``
    territory, and undecodable garbage still drops out of the pool.
    """
    if _hard_base64_signal(fragment):
        # See _lossy_decodable_base64: hard-signal garbage must keep dropping
        # out of the pool instead of reaching the fail-closed invalid-UTF-8
        # path in _scan_encoded.
        return False
    complete_length = len(fragment) - (len(fragment) % 4)
    if complete_length == 0:
        return False
    prefix = fragment[:complete_length]
    try:
        decoded = base64.b64decode(prefix, validate=True)
    except binascii.Error:
        return False
    try:
        decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _lossy_scannable_ascii(decoded)
    return False


def _decoded_text_variants(value: str) -> tuple[str, ...]:
    """Keep both intra-word and between-word control-byte payloads scannable."""
    removed: list[str] = []
    separated: list[str] = []
    for char in value:
        if char.isprintable() or char in "\t\n\r":
            removed.append(char)
            separated.append(char)
        else:
            separated.append(" ")
    return tuple(
        dict.fromkeys(
            candidate for candidate in ("".join(removed), "".join(separated)) if candidate.strip()
        )
    )


def _joined_base64_decodes_cleanly(joined: str) -> bool:
    """Return whether the joined run decodes to fully printable text.

    Alignment-preserving poison parts keep the joined run structurally
    decodable while garbling the plaintext with control bytes; such a decode
    is not a clean Base64 payload and must not suppress recovery.
    """
    padded = _padded_base64(joined)
    if padded is None:
        return False
    try:
        decoded = base64.b64decode(padded, validate=True)
    except binascii.Error:
        return False
    if len(decoded) > MAX_BASE64_DECODED_BYTES:
        return False
    try:
        text = decoded.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    return all(char.isprintable() or char in "\t\n\r" for char in text)


def _recover_base64_edge_fragments(  # NOSONAR
    value: str, *, deadline: float | None
) -> tuple[tuple[str, ...], bool]:
    """Recover viable encoded fragments from a poisoned short-part join.

    Fast path trims a contiguous prefix or suffix. Bounded elimination then
    retries the join while dropping each single part, each pair of parts (when
    the part count allows pairwise work), and each contiguous window of parts.
    A near-decodable join whose elimination budget is exhausted fails closed
    instead of passing silently.
    """
    parts: list[str] = []
    for index, match in enumerate(_BASE64_PARTS.finditer(value)):
        if index % 1_024 == 0 and deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        if _base64_part_is_label(value, match):
            continue
        parts.append(match.group(0))
        if len(parts) > MAX_SPLIT_BASE64_FIELDS:
            return (), False
    count = len(parts)
    if count < MAX_SPLIT_BASE64_RECOVERY_MIN_PARTS:
        return (), False
    joined = "".join(parts)
    if not 8 <= len(joined) <= MAX_SPLIT_BASE64_CANDIDATE_BYTES:
        return (), False
    clean_join = False
    garbled_decode = False
    if _decode_base64_fragment(joined) is not None:
        if _joined_base64_decodes_cleanly(joined):
            # The join itself is scanned elsewhere, but a consumer that drops
            # junk parts sees a different message: recover clean alternates so
            # alignment-preserving poison parts cannot hide the real payload.
            clean_join = True
        else:
            # The joined run decodes only to control-byte/non-printable garble:
            # an alignment-preserving poisoned join, not a clean decode.
            garbled_decode = True
    offsets = [0]
    for part in parts:
        offsets.append(offsets[-1] + len(part))
    attempts = 0
    work_bytes = 0
    cut_short = False
    near_decodable = garbled_decode and (_hard_base64_signal(joined) or _weak_base64_signal(joined))
    found: dict[str, None] = {}

    def probe(candidate: str) -> bool:
        """Return whether candidate is a plausible payload; track budget/evidence."""
        nonlocal attempts, work_bytes, cut_short, near_decodable
        size = len(candidate)
        if size < 8 or size % 4 == 1:
            return False
        if deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        if (
            attempts >= MAX_SPLIT_BASE64_RECOVERY_ATTEMPTS
            or work_bytes + size > MAX_SPLIT_BASE64_RECOVERY_WORK_BYTES
        ):
            cut_short = True
            return False
        attempts += 1
        work_bytes += size
        signaled = _hard_base64_signal(candidate) or _weak_base64_signal(candidate)
        if clean_join:
            return bool(signaled and _joined_base64_decodes_cleanly(candidate))
        if _decode_base64_fragment(candidate) is not None:
            if signaled:
                near_decodable = True
                return True
            return False
        if not near_decodable and signaled:
            near_decodable = _viable_base64_prefix(candidate)
        return False

    def keep(candidate: str) -> None:
        # Never evict the true payload by ranking: excess candidates trip the
        # encoded span limit in _scan_encoded, which fails closed.
        if len(found) < MAX_BASE64_SPANS + 1:
            found[candidate] = None

    # Linear evidence pass: any cleanly decodable prefix across the part stream
    # marks this join as near-decodable even when elimination never recovers it.
    if not clean_join:
        prefix_tracker = ""
        for part in parts:
            if deadline is not None and time.monotonic() >= deadline:
                raise UnicodeScanDeadlineExceeded
            prefix_tracker, prefix_decoded = _advance_base64_prefix(prefix_tracker, part)
            if prefix_decoded and (
                _hard_base64_signal(prefix_tracker) or _weak_base64_signal(prefix_tracker)
            ):
                near_decodable = True

    # Fast path: contiguous suffix and prefix trims.
    for stop in range(count - 1, 0, -1):
        candidate = joined[: offsets[stop]]
        if probe(candidate):
            keep(candidate)
            break
    for start in range(1, count):
        candidate = joined[offsets[start] :]
        if probe(candidate):
            keep(candidate)
            break
    # Bounded elimination: drop each single part.
    for drop in range(count):
        if cut_short:  # NOSONAR
            break
        candidate = joined[: offsets[drop]] + joined[offsets[drop + 1] :]
        if probe(candidate):
            keep(candidate)

    # Bounded elimination: drop each pair of parts where the part count keeps
    # the quadratic work bounded.
    pairs_skipped = count > MAX_SPLIT_BASE64_RECOVERY_PAIR_PARTS
    if not pairs_skipped:
        for first in range(count):
            if cut_short:  # NOSONAR
                break
            for second in range(first + 1, count):
                if cut_short:  # NOSONAR
                    break
                candidate = (
                    joined[: offsets[first]]
                    + joined[offsets[first + 1] : offsets[second]]
                    + joined[offsets[second + 1] :]
                )
                if probe(candidate):
                    keep(candidate)

    # Bounded elimination: drop each triple of parts where the part count keeps
    # the cubic work bounded (multi-part alignment-preserving poison).
    if count <= MAX_SPLIT_BASE64_RECOVERY_TRIPLE_PARTS:
        for first in range(count):
            if cut_short:  # NOSONAR
                break
            for second in range(first + 1, count):
                if cut_short:  # NOSONAR
                    break
                for third in range(second + 1, count):
                    if cut_short:  # NOSONAR
                        break
                    candidate = (
                        joined[: offsets[first]]
                        + joined[offsets[first + 1] : offsets[second]]
                        + joined[offsets[second + 1] : offsets[third]]
                        + joined[offsets[third + 1] :]
                    )
                    if probe(candidate):
                        keep(candidate)

    # Bounded elimination: contiguous windows (drop a prefix and a suffix at
    # once), longest window per start position wins.
    for start in range(count):
        if cut_short:  # NOSONAR
            break
        for stop in range(count, start + 1, -1):
            if start == 0 and stop == count:
                continue
            candidate = joined[offsets[start] : offsets[stop]]
            if probe(candidate):
                keep(candidate)
                break

    if clean_join:
        return tuple(dict.fromkeys(found)), False
    fail_closed = not found and count >= 8 and near_decodable and (cut_short or pairs_skipped)
    return tuple(dict.fromkeys(found)), fail_closed


def _normalized_base64_fragment(
    value: str, *, deadline: float | None = None
) -> tuple[str | None, bool]:
    stripped = value.strip()
    if not stripped:
        return None, False
    if _BASE64_CHARS.fullmatch(stripped):
        return stripped, False
    parts: list[str] = []
    part_count = 0
    overflow_candidate = ""
    decodable_prefix = False
    equals_part = False
    for match_index, match in enumerate(_BASE64_PARTS.finditer(stripped), start=1):
        if match_index % 1_024 == 0 and deadline is not None and time.monotonic() >= deadline:
            return None, True
        if _base64_part_is_label(stripped, match):
            continue
        part_count += 1
        part = match.group(0)
        equals_part |= "=" in part
        overflow_candidate, found = _advance_base64_prefix(overflow_candidate, part)
        decodable_prefix |= found
        if len(parts) < MAX_SPLIT_BASE64_FIELDS:
            parts.append(part)
    if part_count > MAX_SPLIT_BASE64_FIELDS:
        return None, decodable_prefix or equals_part
    if not parts:
        return None, False
    joined = "".join(parts)
    if part_count >= 16 and _padded_base64(joined) is None and decodable_prefix:
        return None, True
    return joined, False


def _base64_part_is_label(value: str, match: re.Match[str]) -> bool:
    if _BASE64_LABEL_AFTER.match(value, match.end()):
        return True
    if _BASE64_NUMBERED_LABEL.fullmatch(match.group(0)) and _BASE64_COLON_AFTER.match(
        value, match.end()
    ):
        return True
    return bool(
        match.start() > 0
        and value[match.start() - 1] in {'"', "'"}
        and _BASE64_JSON_LABEL_AFTER.match(value, match.end())
    )


def _plausible_base64_fragment(fragment: str) -> bool:
    return bool(
        _hard_base64_signal(fragment)
        or _weak_base64_signal(fragment)
        or _decode_base64_fragment(fragment) is not None
    )


def _credible_base64_prefix(fragment: str) -> bool:
    if _hard_base64_signal(fragment) or _weak_base64_signal(fragment):
        return True
    decoded = _decode_base64_fragment(fragment)
    return bool(
        decoded
        and len(decoded) >= 2
        and re.search(r"[a-z]", fragment)
        and re.search(r"[A-Z]", fragment)
        and all(char.isalnum() or char.isspace() for char in decoded)
    )


def _advance_base64_prefix(candidate: str, part: str) -> tuple[str, bool]:
    """Track a viable decoded prefix in linear bounded space across all parts."""
    if "=" in part:
        return candidate, False
    combined = candidate + part
    if len(combined) >= 8 and _decode_base64_fragment(combined) is not None:
        return combined, True
    if len(combined) > 256:
        return "", True
    if _viable_base64_prefix(combined):
        return combined, False
    if part != combined and _viable_base64_prefix(part):
        return part, False
    return "", False


def _is_decoded_removable_character(char: str) -> bool:
    """Match characters _decoded_text_variants removes from decoded text.

    Covers control bytes (Cc) and format characters (Cf: zero-width space,
    joiner/non-joiner, soft hyphen, bidi controls), which _decoded_text_variants
    strips or separates. Unassigned (Cn), private-use (Co), and surrogate (Cs)
    codepoints stay non-removable.
    """
    codepoint = ord(char)
    return codepoint < 0x20 or 0x7F <= codepoint <= 0x9F or unicodedata.category(char) == "Cf"


def _viable_base64_prefix(fragment: str) -> bool:
    """Return whether future Base64 bytes can still form scannable UTF-8.

    Viability is judged on the control-and-format-removed variant, consistent
    with _decoded_text_variants: decoded control bytes (Cc) and format
    characters (Cf) never kill viability because the removed/separated
    variants are scanned downstream in _scan_encoded. Other non-printable,
    non-whitespace characters (unassigned, private-use) and invalid UTF-8
    still mark the prefix as non-viable garbage.
    """
    complete_length = len(fragment) - (len(fragment) % 4)
    if complete_length == 0:
        return True
    prefix = fragment[:complete_length]
    try:
        decoded = base64.b64decode(prefix, validate=True)
        text = codecs.getincrementaldecoder("utf-8")().decode(decoded, final=False)
    except (binascii.Error, UnicodeDecodeError):
        return False
    if all(char.isprintable() or char.isspace() for char in text):
        return True
    # Consistent with _decoded_text_variants: control bytes and format
    # characters mixed into otherwise-scannable text never kill viability,
    # because the removed and separated variants are scanned downstream in
    # _scan_encoded. Prefixes decoding to nothing but control or format
    # characters carry no scannable signal and stay non-viable, as do
    # unassigned and private-use characters.
    return any(char.isprintable() or char.isspace() for char in text) and all(
        char.isprintable() or char.isspace() or _is_decoded_removable_character(char)
        for char in text
    )


def _alphabet_separator_split_is_suspicious(fragment: str) -> bool:
    """Return whether in-alphabet separators ("/"/"+") split plausible Base64 parts.

    A fragment that decodes cleanly is legitimate Base64 and never suspicious. An
    undecodable fragment whose in-alphabet characters separate four or more viable
    parts (sixteen or more viable characters overall) is a poisoned split payload,
    not prose: URL/path segments are dictionary words that are not viable prefixes.
    """
    if len(fragment) > MAX_SPLIT_BASE64_CANDIDATE_BYTES:
        return False
    if _BASE64_IN_ALPHABET_SEPARATOR.search(fragment) is None:
        return False
    if _decode_base64_fragment(fragment) is not None:
        return False
    viable_parts = [
        head
        for part in _BASE64_IN_ALPHABET_SEPARATOR.split(fragment)
        for head in (part.split("=", 1)[0],)
        if len(head) >= 2 and _viable_base64_prefix(head)
    ]
    if len(viable_parts) >= 4 and sum(len(part) for part in viable_parts) >= 16:
        return True
    # A single in-alphabet separator already breaks alignment; if simply removing
    # the separator characters yields a decodable printable payload, the fragment
    # is a split payload with separator poisoning rather than prose. Trailing
    # junk appended after the padding marker must not hide the payload either.
    stripped = _BASE64_IN_ALPHABET_SEPARATOR.sub("", fragment)
    if len(stripped) >= 8 and _decode_base64_fragment(stripped) is not None:
        return True
    head = stripped.split("=", 1)[0]
    return head != stripped and len(head) >= 8 and _decode_base64_fragment(head) is not None


def _dedupe_split_candidates(values: list[tuple[str, int]]) -> list[tuple[str, int]]:
    unique: dict[tuple[str, int], None] = {}
    for value in values:
        unique[value] = None
    candidates = list(unique)
    candidates.sort(key=lambda value: (-len(value[0]), value[1]))
    return candidates[:MAX_SPLIT_BASE64_CANDIDATES]


def _scan_encoded(  # NOSONAR
    result: SafetyResult,
    key: str,
    canonical: str,
    operation: str,
    state: _EncodedState,
    *,
    depth: int = 0,
    fail_closed_invalid: bool = True,
    deadline: float | None = None,
) -> None:
    recovered, recovery_fail_closed = _recover_base64_edge_fragments(canonical, deadline=deadline)
    if recovery_fail_closed:
        result.add(SafetyFinding("split_base64_limit", "span_limit"))
    candidates = dict.fromkeys(
        (*recovered, *(match.group(0) for match in _BASE64_RUN.finditer(canonical)))
    )
    for candidate in candidates:
        if deadline is not None and time.monotonic() >= deadline:
            raise UnicodeScanDeadlineExceeded
        if candidate in state.seen or (
            not _hard_base64_signal(candidate) and not _looks_like_base64(candidate)
        ):
            continue
        state.seen.add(candidate)
        state.spans += 1
        if state.spans > MAX_BASE64_SPANS:
            result.add(SafetyFinding("span_limit", "encoded_payload"))
            return
        hard_signal = _hard_base64_signal(candidate)
        padded = _padded_base64(candidate)
        if padded is None:
            if hard_signal and fail_closed_invalid:
                result.add(SafetyFinding("invalid_base64", "encoded_payload"))
            continue
        try:
            decoded = base64.b64decode(padded, validate=True)
        except binascii.Error:
            if hard_signal and fail_closed_invalid:
                result.add(SafetyFinding("invalid_base64", "encoded_payload"))
            continue
        if (
            len(decoded) > MAX_BASE64_DECODED_BYTES
            or state.decoded_bytes + len(decoded) > MAX_BASE64_DECODED_BYTES
        ):
            if fail_closed_invalid:
                result.add(SafetyFinding("decoded_size_limit", "encoded_payload"))
            continue
        state.decoded_bytes += len(decoded)
        lossy_decoded = False
        try:
            decoded_text = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            if hard_signal and fail_closed_invalid:
                result.add(SafetyFinding("invalid_utf8", "encoded_payload"))
                continue
            lossy_text = _lossy_ascii_decoded_text(decoded)
            if lossy_text is None:
                continue
            decoded_text = lossy_text
            lossy_decoded = True
        sanitized_variants = _decoded_text_variants(decoded_text)
        if not sanitized_variants:
            continue
        scan_variants = (
            tuple(dict.fromkeys((decoded_text, *sanitized_variants)))
            if hard_signal and not lossy_decoded
            else sanitized_variants
        )
        for decoded_variant in scan_variants:
            decoded_canonical, decoded_transformations = canonicalize_content(
                decoded_variant, deadline=deadline
            )
            result.transformations.update(decoded_transformations)
            if len(decoded_variant) >= 8:
                # Decoded fragments shorter than a rule phrase cannot carry a
                # unicode-smuggling attack; flagging their canonicalization
                # noise false-positives on benign text like "C++ / C-- notes".
                # Control/format characters are stripped by
                # _decoded_text_variants before the rule/detector scans below.
                _add_unicode_findings(result, decoded_transformations)
            decoded_hits = _rule_scan(
                decoded_canonical,
                deadline=deadline,
                strip_inword_digits="keycap" in decoded_transformations,
            ) + _amg_scan(
                f"{key}.base64", decoded_canonical, operation=operation, deadline=deadline
            )
            if decoded_hits:
                result.add(SafetyFinding("unsafe_base64", "encoded_payload"))
                for finding in decoded_hits:
                    result.add(finding)
            if depth == 0 and not lossy_decoded:
                _scan_encoded(
                    result,
                    f"{key}.base64",
                    decoded_canonical,
                    operation,
                    state,
                    depth=1,
                    fail_closed_invalid=fail_closed_invalid,
                    deadline=deadline,
                )


def _looks_like_base64(candidate: str) -> bool:
    if len(candidate) < 8:
        return False
    padded = _padded_base64(candidate)
    if padded is None:
        return False
    if _hard_base64_signal(candidate) or _weak_base64_signal(candidate):
        return True
    return _decode_base64_fragment(candidate) is not None


def _padded_base64(candidate: str) -> str | None:
    if not candidate or len(candidate) % 4 == 1:
        return None
    if "=" in candidate and not candidate.endswith(("=", "==")):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    return padded if _CANONICAL_BASE64.fullmatch(padded) else None


def _hard_base64_signal(candidate: str) -> bool:
    return bool(re.search(r"[=+/]", candidate))


def _weak_base64_signal(candidate: str) -> bool:
    return bool(
        re.search(r"[a-z]", candidate)
        and re.search(r"[A-Z]", candidate)
        and re.search(r"\d", candidate)
    )
