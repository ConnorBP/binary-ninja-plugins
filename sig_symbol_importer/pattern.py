"""IDA-style hex pattern → masked byte search across a BinaryView section.

Pattern syntax matches stb::simple_conversion in fvc/cs2-sdk:
    - whitespace-separated tokens
    - each token is either a 2-hex-digit byte ("8B", "ff") or a wildcard
      ("?" or "??") which matches any single byte
    - case-insensitive

`find_matches(bv, pattern, section_name)` returns a list of absolute
addresses where the pattern matches. The search is scoped to the named
section if provided and present in the BinaryView; otherwise it falls
back to every executable segment.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional


_HEX_BYTE = re.compile(r"^[0-9a-fA-F]{2}$")


class PatternError(ValueError):
    pass


def _tokenize(pattern: str) -> List[str]:
    return [t for t in pattern.replace(",", " ").split() if t]


def compile_pattern(pattern: str) -> "re.Pattern[bytes]":
    """Compile an IDA-style hex pattern into a `bytes` regex object.

    Wildcards (`?` or `??`) become `.` (any single byte). Concrete bytes
    are escaped as their literal byte values via `re.escape`.
    """
    parts: List[bytes] = []
    for tok in _tokenize(pattern):
        if tok == "?" or tok == "??":
            parts.append(b".")
            continue
        if not _HEX_BYTE.match(tok):
            raise PatternError(f"invalid pattern token {tok!r}")
        parts.append(re.escape(bytes([int(tok, 16)])))
    if not parts:
        raise PatternError("empty pattern")
    return re.compile(b"".join(parts), re.DOTALL)


def _section_range(bv, section_name: Optional[str]):
    """Return (start, end) for the requested section, or None."""
    if not section_name:
        return None
    sec = None
    getter = getattr(bv, "get_section_by_name", None)
    if getter is not None:
        try:
            sec = getter(section_name)
        except Exception:
            sec = None
    if sec is None:
        # Some BV variants expose sections as a dict
        try:
            sec = bv.sections[section_name]  # type: ignore[index]
        except Exception:
            sec = None
    if sec is None:
        return None
    return (int(sec.start), int(sec.end))


def _executable_segment_ranges(bv) -> Iterable:
    for seg in bv.segments:
        if seg.executable:
            yield (int(seg.start), int(seg.end))


def find_matches(
    bv,
    pattern: str,
    section_name: Optional[str] = None,
    *,
    limit: int = 16,
) -> List[int]:
    """Scan the named section (or every executable segment) for `pattern`.

    Returns up to `limit` absolute match addresses. The caller decides
    how to interpret zero / one / multiple hits — this function reports
    them all so the loader can warn on ambiguity.
    """
    rx = compile_pattern(pattern)

    ranges: List = []
    sr = _section_range(bv, section_name)
    if sr is not None:
        ranges.append(sr)
    else:
        ranges.extend(_executable_segment_ranges(bv))

    out: List[int] = []
    for start, end in ranges:
        size = end - start
        if size <= 0:
            continue
        data = bv.read(start, size)
        if not data:
            continue
        for m in rx.finditer(data):
            out.append(start + m.start())
            if len(out) >= limit:
                return out
    return out
