"""Export the current BinaryView's `sig_symbol`-tagged addresses to JSON.

This is a write-back of the live state, NOT a source-of-truth dump. The
exported file records:
  - the current symbol name at each tagged address
  - the module (basename of the loaded BV)
  - a "captured_address" so the user can re-locate it on the same build
The exported file omits patterns/resolve chains — those belong in the
authored source file (e.g. generated from signatures.cpp).

The main use case: round-tripping renames you made manually after a
prior import, so the next import-with-same-build doesn't clobber them.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .importer import TAG_TYPE_NAME, _binary_basename


def export_symbols(bv) -> Dict[str, Any]:
    module = _binary_basename(bv)
    symbols: List[Dict[str, Any]] = []

    tag_type = bv.get_tag_type(TAG_TYPE_NAME)
    if tag_type is None:
        return {"version": 1, "module": module, "symbols": []}

    # BinaryView.tags_by_type(tag_type) returns List[Tuple[int, Tag]]
    # of every tag of the given type across ALL scopes (function tags,
    # function address-tags, and data tags) so we pick up both the
    # function-scoped tags the importer creates inside functions AND
    # the data-scoped tags it creates on .data slots.
    seen = set()
    for addr, tag in bv.tags_by_type(tag_type):
        if addr in seen:
            continue
        seen.add(addr)

        sym = bv.get_symbol_at(addr)
        func = bv.get_function_at(addr)
        if func is not None:
            kind = "function"
            name = sym.name if sym is not None else func.name
        elif sym is not None:
            kind = "data"
            name = sym.name
        else:
            kind = "raw"
            name = tag.data or f"sub_{addr:x}"

        symbols.append({
            "name": name,
            "module": module,
            "kind": kind,
            "captured_address": f"{addr:#x}",
            "tag_label": tag.data or "",
        })

    return {"version": 1, "module": module, "symbols": symbols}


def write_export(bv, out_path: str) -> int:
    doc = export_symbols(bv)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    return len(doc.get("symbols", []))
