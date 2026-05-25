"""
Parser for cs2-dumper schema headers.

We prefer the .hpp because it preserves the per-field type_name as a trailing
comment (cs2-dumper drops that information from the .json). When .hpp is
absent we fall back to the .json with type_name == None.

Output:

    SchemaModule(
        module_name="client.dll",
        classes=[SchemaClass(name, parent, fields=[SchemaField(name, offset, type_name)], metadata=[...]), ...],
        enums=[SchemaEnum(name, alignment, members=[(name, value), ...]), ...],
    )
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SchemaField:
    name: str
    offset: int
    type_name: Optional[str]


@dataclass
class SchemaClass:
    name: str
    parent: Optional[str]
    fields: list[SchemaField] = field(default_factory=list)
    metadata: list[str] = field(default_factory=list)


@dataclass
class SchemaEnum:
    name: str
    alignment: int
    members: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class SchemaModule:
    module_name: str
    classes: list[SchemaClass] = field(default_factory=list)
    enums: list[SchemaEnum] = field(default_factory=list)


_FIELD_RE = re.compile(
    r"constexpr\s+std::ptrdiff_t\s+(?P<name>\w+)\s*=\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*;\s*//\s*(?P<type>.+?)\s*$"
)
_ENUM_HEADER_RE = re.compile(
    r"enum\s+class\s+(?P<name>[\w:]+)\s*:\s*(?P<base>uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t)"
)
_ENUM_MEMBER_RE = re.compile(
    r"^\s*(?P<name>\w+)\s*=\s*(?P<value>-?0x[0-9a-fA-F]+|-?\d+)\s*,?\s*$"
)
_NAMESPACE_RE = re.compile(r"\bnamespace\s+(?P<name>[\w:]+)\s*\{")
_MODULE_RE = re.compile(r"//\s*Module:\s*(?P<mod>\S+)")
_PARENT_RE = re.compile(r"//\s*Parent:\s*(?P<parent>\S+)")
_ALIGNMENT_RE = re.compile(r"//\s*Alignment:\s*(?P<a>\d+)")
_FIELDCOUNT_RE = re.compile(r"//\s*Field count:\s*(?P<n>\d+)")


_BASE_INT_TO_ALIGN = {
    "uint8_t": 1, "int8_t": 1,
    "uint16_t": 2, "int16_t": 2,
    "uint32_t": 4, "int32_t": 4,
    "uint64_t": 8, "int64_t": 8,
}


def _parse_int(raw: str) -> int:
    s = raw.strip()
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    val = int(s, 16) if s.lower().startswith("0x") else int(s)
    return -val if neg else val


def _parse_hpp_module(text: str) -> Optional[SchemaModule]:
    """Streaming parser. Maintains a namespace stack; only INNERMOST namespaces
    that immediately contain `constexpr std::ptrdiff_t` lines are classes."""

    lines = text.splitlines()
    n = len(lines)

    module_name: Optional[str] = None
    for line in lines[:50]:
        m = _MODULE_RE.search(line)
        if m:
            module_name = m.group("mod")
            break

    out = SchemaModule(module_name=module_name or "")

    # Stack of (kind, name, fields, parent, metadata, alignment) — kind in {'ns','enum'}
    # Brace depth tracked separately; we push on namespace/enum openings only.
    stack: list[dict] = []
    brace_depth = 0  # absolute brace depth across the whole file

    pending_parent: Optional[str] = None
    pending_meta: list[str] = []
    pending_alignment: Optional[int] = None
    pending_is_class = False  # set by `// Parent:` or `// Field count:` immediately before a namespace
    in_metadata_block = False

    for raw_line in lines:
        line = raw_line
        stripped = line.strip()

        # --- Pre-scan annotation comments ---
        m = _MODULE_RE.search(stripped)
        if m and not module_name:
            module_name = m.group("mod")
            out.module_name = module_name

        m = _PARENT_RE.search(stripped)
        if m:
            pending_parent = m.group("parent") if m.group("parent") != "None" else None
            pending_is_class = True
            in_metadata_block = False
            continue

        m = _FIELDCOUNT_RE.search(stripped)
        if m:
            pending_is_class = True
            in_metadata_block = False
            continue

        m = _ALIGNMENT_RE.search(stripped)
        if m:
            pending_alignment = int(m.group("a"))
            in_metadata_block = False
            continue

        if stripped.startswith("// Metadata:"):
            in_metadata_block = True
            continue
        if in_metadata_block and stripped.startswith("//"):
            txt = stripped.lstrip("/").strip()
            if txt:
                pending_meta.append(txt)
            continue
        else:
            in_metadata_block = False

        # --- Detect openings (must come before brace-depth bookkeeping for the same line) ---
        nm = _NAMESPACE_RE.search(stripped)
        em = _ENUM_HEADER_RE.search(stripped)

        opened_ns_or_enum = False
        if nm and "{" in stripped and not stripped.lstrip().startswith("//"):
            stack.append({
                "kind": "ns",
                "name": nm.group("name"),
                "depth_at_open": brace_depth,
                "fields": [],
                "parent": pending_parent,
                "metadata": list(pending_meta),
                "alignment": pending_alignment,
                "is_class": pending_is_class,
            })
            pending_parent = None
            pending_meta = []
            pending_alignment = None
            pending_is_class = False
            opened_ns_or_enum = True
        elif em:
            # enum class can span multiple lines before `{`. Push a synthetic frame
            # that finalizes when we see the matching `}`. Capture name + base now.
            stack.append({
                "kind": "enum",
                "name": em.group("name"),
                "base": em.group("base"),
                "depth_at_open": brace_depth,  # set after we observe the `{`
                "members": [],
                "alignment": pending_alignment if pending_alignment is not None else _BASE_INT_TO_ALIGN.get(em.group("base"), 4),
                "awaiting_open_brace": "{" not in stripped,
            })
            pending_alignment = None
            opened_ns_or_enum = True

        # --- Parse field / enum-member lines INSIDE a class/enum frame ---
        if not opened_ns_or_enum and stack:
            top = stack[-1]
            if top["kind"] == "ns":
                fm = _FIELD_RE.search(stripped)
                if fm:
                    top["fields"].append(SchemaField(
                        name=fm.group("name"),
                        offset=_parse_int(fm.group("offset")),
                        type_name=fm.group("type").strip(),
                    ))
            elif top["kind"] == "enum":
                if top.get("awaiting_open_brace") and "{" in stripped:
                    top["awaiting_open_brace"] = False
                else:
                    mm = _ENUM_MEMBER_RE.match(stripped)
                    if mm:
                        top["members"].append((mm.group("name"), _parse_int(mm.group("value"))))

        # --- Brace depth bookkeeping ---
        # Count braces on this line, ignoring those inside line comments after `//`.
        scan = stripped.split("//", 1)[0]
        brace_depth += scan.count("{") - scan.count("}")

        # --- Pop frames whose closing brace we just consumed ---
        while stack and brace_depth <= stack[-1]["depth_at_open"]:
            top = stack.pop()
            if top["kind"] == "ns":
                # Class namespaces are flagged via the `// Parent:` / `// Field count:`
                # comment that always precedes them. Outer wrapping namespaces
                # (cs2_dumper, schemas, <module>_dll) lack that flag.
                if top.get("is_class"):
                    out.classes.append(SchemaClass(
                        name=top["name"],
                        parent=top["parent"],
                        fields=top["fields"],
                        metadata=top["metadata"],
                    ))
            else:
                if top["members"]:
                    out.enums.append(SchemaEnum(
                        name=top["name"],
                        alignment=top["alignment"],
                        members=top["members"],
                    ))

    if not out.module_name:
        return None
    return out


def parse_hpp(path: str) -> SchemaModule:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    mod = _parse_hpp_module(text)
    if mod is None:
        raise ValueError(f"could not detect module name in {path}")
    return mod


def parse_json(path: str) -> SchemaModule:
    """Fallback when .hpp isn't available — produces fields without type_name."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not data:
        raise ValueError(f"empty json: {path}")
    module_name, body = next(iter(data.items()))
    out = SchemaModule(module_name=module_name)

    for class_name, cls in body.get("classes", {}).items():
        fields = []
        for fname, foff in cls.get("fields", {}).items():
            fields.append(SchemaField(name=fname, offset=int(foff), type_name=None))
        fields.sort(key=lambda f: f.offset)
        out.classes.append(SchemaClass(
            name=class_name,
            parent=cls.get("parent"),
            fields=fields,
            metadata=[m.get("type", "") for m in cls.get("metadata", [])],
        ))

    for enum_name, en in body.get("enums", {}).items():
        members = [(k, int(v)) for k, v in en.get("members", {}).items()]
        out.enums.append(SchemaEnum(
            name=enum_name,
            alignment=int(en.get("alignment", 4)),
            members=members,
        ))

    return out


def load_module(output_dir: str, module_name: str) -> SchemaModule:
    """Load cs2-dumper data for a module (e.g. 'client.dll').
    Tries `<stem>_dll.hpp` first, then `<stem>_dll.json`."""
    stem = module_name.lower().replace(".dll", "")
    hpp_path = os.path.join(output_dir, f"{stem}_dll.hpp")
    json_path = os.path.join(output_dir, f"{stem}_dll.json")

    if os.path.isfile(hpp_path):
        return parse_hpp(hpp_path)
    if os.path.isfile(json_path):
        return parse_json(json_path)

    raise FileNotFoundError(f"no schema dump for {module_name} in {output_dir}")
