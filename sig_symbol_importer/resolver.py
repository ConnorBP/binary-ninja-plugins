"""Resolution-op chain that mirrors CPointer (fvc winningapi/pointer).

A resolve chain is a list of ops applied left-to-right to a base address
(the byte offset of a pattern match). Supported ops match the C++ side:

    {"op": "offset",      "value": N}            ptr += N
    {"op": "absolute",    "pre": N, "post": M}   ptr += N
                                                  disp = *(int32*)ptr
                                                  ptr  = ptr + 4 + disp
                                                  ptr += M
    {"op": "dereference", "count": N}            for _ in range(N):
                                                      ptr = *(uint64*)ptr

`apply(bv, addr, ops)` returns the final address, or None if any read
goes out of the mapped range.
"""

from __future__ import annotations

import struct
from typing import List, Optional


class ResolveError(ValueError):
    pass


def _read_int32(bv, addr: int) -> Optional[int]:
    data = bv.read(addr, 4)
    if not data or len(data) != 4:
        return None
    return struct.unpack("<i", data)[0]


def _read_uint64(bv, addr: int) -> Optional[int]:
    data = bv.read(addr, 8)
    if not data or len(data) != 8:
        return None
    return struct.unpack("<Q", data)[0]


def apply(bv, addr: int, ops: List[dict]) -> Optional[int]:
    cur = int(addr) & 0xFFFFFFFFFFFFFFFF
    for op in ops or []:
        name = op.get("op")
        if name == "offset":
            cur = (cur + int(op.get("value", 0))) & 0xFFFFFFFFFFFFFFFF
        elif name == "absolute":
            pre = int(op.get("pre", 0))
            post = int(op.get("post", 0))
            cur = (cur + pre) & 0xFFFFFFFFFFFFFFFF
            disp = _read_int32(bv, cur)
            if disp is None:
                return None
            cur = (cur + 4 + disp) & 0xFFFFFFFFFFFFFFFF
            cur = (cur + post) & 0xFFFFFFFFFFFFFFFF
        elif name == "dereference":
            for _ in range(int(op.get("count", 1))):
                v = _read_uint64(bv, cur)
                if v is None:
                    return None
                cur = v & 0xFFFFFFFFFFFFFFFF
        else:
            raise ResolveError(f"unknown resolve op {name!r}")
    return cur


def describe(ops: List[dict]) -> str:
    """Render an op chain like `Absolute(3,0).Dereference(1)` for logging."""
    if not ops:
        return "(direct)"
    parts = []
    for op in ops:
        name = op.get("op")
        if name == "offset":
            parts.append(f"Offset({op.get('value', 0)})")
        elif name == "absolute":
            parts.append(f"Absolute({op.get('pre', 0)},{op.get('post', 0)})")
        elif name == "dereference":
            parts.append(f"Dereference({op.get('count', 1)})")
        else:
            parts.append(f"?{name}?")
    return ".".join(parts)
