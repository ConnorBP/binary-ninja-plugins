"""
Static schema extractor — pulls the CS2 schema graph straight out of the
loaded module's static data, with no live process required.

Pipeline (verified against client.dll build 14160 in Binary Ninja):

  1. Find every `CSchemaRegistration::VFunc0` function. Each one is the
     class registration handler for a single batch of bindings (one per
     translation-unit-template-instantiation).

  2. In each VFunc0, locate the call to `vtable[0x110]` — the phase-2
     bindings-registration call. Its 5th arg is the class count, its 6th
     arg is a pointer to an array of `SchemaClassBinding*`.

  3. For every binding pointer in those arrays, read the static fields:

       struct SchemaClassBinding {                        // verified offsets
           void*  pServerClass;        // +0x00 (runtime, null statically)
           const char* m_Name;         // +0x08
           const char* m_BinaryName;   // +0x10 (often null)
           const char* m_Module;       // +0x18 (often null)
           uint32_t m_nSizeOf;         // +0x20  ← ground truth class size
           int16_t  m_nFieldsCount;    // +0x24
           int16_t  m_nStaticMetadataCount; // +0x26
           ...
           SchemaClassFieldData_t* m_Fields;       // +0x30
           SchemaBaseClassInfo_t*  m_BaseClasses;  // +0x38
           SchemaStaticMetadata_t* m_pStaticMetadata; // +0x40
       };

       struct SchemaClassFieldData_t {  // 0x20 bytes total
           const char* m_Name;          // +0x00
           void*       m_pType;         // +0x08 (runtime, null statically)
           uint32_t    m_nSingleInheritanceOffset;  // +0x10
           ...
       };

       struct SchemaBaseClassInfo_t {   // 16 bytes
           uint32_t offset;             // +0x00
           SchemaClassBinding* m_pParentBinding; // +0x08
       };

  4. Resolve parent names by following `m_BaseClasses[0].m_pParentBinding`
     and reading its `m_Name`.

What we DON'T get statically: per-field type strings. `m_pType` at +0x08
is populated at runtime when SchemaSystem walks each binding. The only
type info baked into the static image is a per-field metadata pointer
(field+0x18) which references a `CSchemaType` whose layout requires
runtime resolution. So fields come out with `type_name=None` — the same
state the JSON-fallback path produces, and the builder already handles
that by sizing fields with gap-to-next-field byte arrays.

What we DO get that cs2-dumper's JSON loses: the exact `m_nSizeOf` for
every class, plus the static metadata names per class.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Optional

try:
    from .parser import SchemaModule, SchemaClass, SchemaField, SchemaEnum
except ImportError:
    from parser import SchemaModule, SchemaClass, SchemaField, SchemaEnum  # type: ignore

try:
    import binaryninja as bn
    from binaryninja.enums import HighLevelILOperation
except ImportError:
    bn = None  # type: ignore


# Symbol name binja gives the schema registration handler. Sometimes prefixed
# (CSchemaRegistration_client::VFunc0 etc.); we match by suffix.
_VFUNC0_SUFFIX = "CSchemaRegistration::VFunc0"
_BINDING_VTABLE_CALL_OFFSET = 0x110

# Static-binding offsets (verified against client.dll, build 14160)
_BIND_OFF_NAME = 0x08
_BIND_OFF_SIZEOF = 0x20
_BIND_OFF_FIELDS_COUNT = 0x24
_BIND_OFF_METADATA_COUNT = 0x26
_BIND_OFF_FIELDS_PTR = 0x30
_BIND_OFF_BASE_CLASSES_PTR = 0x38
_BIND_OFF_METADATA_PTR = 0x40

_FIELD_RECORD_SIZE = 0x20
_FIELD_OFF_NAME = 0x00
_FIELD_OFF_OFFSET = 0x10

_BASE_CLASS_RECORD_SIZE = 0x10
_BASE_OFF_PARENT_BINDING = 0x08

_METADATA_RECORD_SIZE = 0x10  # per fvc::SchemaStaticMetadata_t-ish; entry at +0x00 = name ptr


def _read_ptr(bv, addr: int) -> int:
    raw = bv.read(addr, bv.address_size)
    if len(raw) != bv.address_size:
        return 0
    return int.from_bytes(raw, "little")


def _read_u32(bv, addr: int) -> int:
    raw = bv.read(addr, 4)
    if len(raw) != 4:
        return 0
    return int.from_bytes(raw, "little", signed=False)


def _read_i16(bv, addr: int) -> int:
    raw = bv.read(addr, 2)
    if len(raw) != 2:
        return 0
    return int.from_bytes(raw, "little", signed=True)


def _read_cstring(bv, addr: int, max_len: int = 256) -> str:
    if addr == 0:
        return ""
    raw = bv.read(addr, max_len)
    if not raw:
        return ""
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


# -------- VFunc0 → bindings-array discovery --------

def _vtable_indirect_call_offset(bv, hlil_call_dest) -> Optional[int]:
    """If `hlil_call_dest` looks like `*(*this + N)` for some constant N, return N.
    Otherwise None.

    Handles a few shapes binja produces for virtual calls:
       HLIL_DEREF(HLIL_ADD(HLIL_DEREF(x), CONST))
       HLIL_DEREF(HLIL_ADD(CONST, HLIL_DEREF(x)))
       HLIL_VAR(.) wrapping any of the above
    """
    if hlil_call_dest is None:
        return None

    expr = hlil_call_dest
    # Sometimes the dest is wrapped in HLIL_VAR or similar — try a couple of unwrap layers.
    for _ in range(3):
        op = getattr(expr, "operation", None)
        if op != HighLevelILOperation.HLIL_DEREF:
            break
        inner = expr.src
        in_op = getattr(inner, "operation", None)
        if in_op == HighLevelILOperation.HLIL_ADD:
            left, right = inner.left, inner.right
            l_op = getattr(left, "operation", None)
            r_op = getattr(right, "operation", None)
            if r_op in (HighLevelILOperation.HLIL_CONST, HighLevelILOperation.HLIL_CONST_PTR):
                return int(right.constant)
            if l_op in (HighLevelILOperation.HLIL_CONST, HighLevelILOperation.HLIL_CONST_PTR):
                return int(left.constant)
        # No add — direct deref of `(this + N)` rendered as e.g. struct member access
        break

    return None


def _looks_like_pointer_into_section(bv, addr: int) -> bool:
    if addr == 0:
        return False
    seg = bv.get_segment_at(addr)
    return seg is not None


def _const_int(expr) -> Optional[int]:
    """Best-effort: pull an integer constant out of an HLIL expression."""
    if expr is None:
        return None
    op = getattr(expr, "operation", None)
    if op == HighLevelILOperation.HLIL_CONST:
        return int(expr.constant)
    if op == HighLevelILOperation.HLIL_CONST_PTR:
        return int(expr.constant)
    if op == HighLevelILOperation.HLIL_IMPORT:
        return int(expr.constant)
    # constant-data variants
    val = getattr(expr, "value", None)
    if val is not None:
        try:
            from binaryninja.enums import RegisterValueType
            if val.type in (RegisterValueType.ConstantValue,
                            RegisterValueType.ConstantPointerValue,
                            RegisterValueType.ImportedAddressValue):
                return int(val.value)
        except Exception:
            pass
    return None


def _calls_with_offset(bv, func, want_offset: int):
    """Yield (insn, params_list) for HLIL calls in `func` whose dest matches
    `*(*this + want_offset)`. Permissive — uses _vtable_indirect_call_offset."""
    try:
        hlil = func.hlil
    except Exception:
        return
    if hlil is None:
        return
    for insn in hlil.instructions:
        op = getattr(insn, "operation", None)
        if op not in (HighLevelILOperation.HLIL_CALL, HighLevelILOperation.HLIL_TAILCALL):
            continue
        off = _vtable_indirect_call_offset(bv, insn.dest)
        if off == want_offset:
            yield insn, list(insn.params)


def _find_bindings_arrays_in_function(bv, func, log) -> list[tuple[int, int]]:
    """For a CSchemaRegistration::VFunc0, return [(count, bindings_ptr), ...]
    extracted from each call to vtable[0x110]."""
    out = []
    found = False
    for insn, params in _calls_with_offset(bv, func, _BINDING_VTABLE_CALL_OFFSET):
        if len(params) < 6:
            continue
        count = _const_int(params[4])
        bindings_ptr = _const_int(params[5])
        if count is None or bindings_ptr is None:
            continue
        if bindings_ptr == 0 or count <= 0 or count > 4096:
            continue
        if not _looks_like_pointer_into_section(bv, bindings_ptr):
            continue
        out.append((count, bindings_ptr))
        found = True

    if not found:
        # Permissive fallback: scan ALL HLIL calls, look for `(this, str, str, ptr, count, ptr_array, …)`
        # signature shape — count is a small positive int < 4096, ptr_array points into a section,
        # and there are at least 6 params.
        try:
            hlil = func.hlil
        except Exception:
            hlil = None
        if hlil is not None:
            for insn in hlil.instructions:
                op = getattr(insn, "operation", None)
                if op not in (HighLevelILOperation.HLIL_CALL, HighLevelILOperation.HLIL_TAILCALL):
                    continue
                params = list(insn.params)
                if len(params) < 6:
                    continue
                count = _const_int(params[4])
                bindings_ptr = _const_int(params[5])
                if count is None or bindings_ptr is None:
                    continue
                if not (0 < count < 4096):
                    continue
                if not _looks_like_pointer_into_section(bv, bindings_ptr):
                    continue
                # Heuristic: phase 1 (0x108) and phase 2 (0x110) calls have the same shape.
                # We want phase 2 (bindings). Phase 1's 6th arg is the enum array. Phase 0 (0x100)
                # has no count + ptr at the same position. We pick BOTH and disambiguate by
                # checking if the dereffed pointer-array entries themselves look like binding
                # structs (zero at +0, valid name string at +0x08).
                if _array_looks_like_class_bindings(bv, bindings_ptr, count):
                    out.append((count, bindings_ptr))

    return out


def _array_looks_like_class_bindings(bv, addr: int, count: int) -> bool:
    """Validate that `addr` points to an array of `count` SchemaClassBinding pointers,
    each pointing to a struct with a non-empty name string at +0x08."""
    if count <= 0 or count > 4096:
        return False
    sample = min(count, 4)
    ok = 0
    for i in range(sample):
        ptr = _read_ptr(bv, addr + i * bv.address_size)
        if ptr == 0:
            continue
        # binding[+0x00] should be 0 (pServerClass) statically
        head = _read_ptr(bv, ptr)
        if head != 0:
            continue
        # binding[+0x08] should point to a non-empty ASCII string starting with [A-Za-z_]
        name_ptr = _read_ptr(bv, ptr + _BIND_OFF_NAME)
        if name_ptr == 0:
            continue
        nm = _read_cstring(bv, name_ptr, 64)
        if not nm:
            continue
        first = nm[0]
        if not (first.isalpha() or first == "_"):
            continue
        ok += 1
    return ok > 0  # at least one entry validates


def _enumerate_vfunc0(bv) -> list:
    """All `CSchemaRegistration::VFunc0` instances. Multiple symbols share the
    same name (one per template instantiation per translation unit)."""
    funcs = []
    seen = set()

    # Fast path: lookup by exact name
    try:
        syms = bv.get_symbols_by_name(_VFUNC0_SUFFIX) or []
    except Exception:
        syms = []

    for sym in syms:
        f = bv.get_function_at(sym.address)
        if f is not None and f.start not in seen:
            seen.add(f.start)
            funcs.append(f)

    if funcs:
        return funcs

    # Fallback: scan all symbols for any name containing both "CSchemaRegistration"
    # and "VFunc0" (handles oddly-prefixed mangled names).
    for sym in bv.get_symbols():
        n = sym.name
        if "CSchemaRegistration" in n and "VFunc0" in n:
            f = bv.get_function_at(sym.address)
            if f is not None and f.start not in seen:
                seen.add(f.start)
                funcs.append(f)
    return funcs


# -------- per-binding parsing --------

def _read_class_binding(bv, binding_addr: int, log) -> Optional[SchemaClass]:
    if binding_addr == 0:
        return None

    name_ptr = _read_ptr(bv, binding_addr + _BIND_OFF_NAME)
    name = _read_cstring(bv, name_ptr)
    if not name:
        log(f"  binding @{binding_addr:#x}: missing name")
        return None

    field_count = _read_i16(bv, binding_addr + _BIND_OFF_FIELDS_COUNT)
    metadata_count = _read_i16(bv, binding_addr + _BIND_OFF_METADATA_COUNT)
    fields_ptr = _read_ptr(bv, binding_addr + _BIND_OFF_FIELDS_PTR)
    base_classes_ptr = _read_ptr(bv, binding_addr + _BIND_OFF_BASE_CLASSES_PTR)
    metadata_ptr = _read_ptr(bv, binding_addr + _BIND_OFF_METADATA_PTR)

    fields: list[SchemaField] = []
    if fields_ptr and field_count > 0:
        for i in range(field_count):
            entry_addr = fields_ptr + i * _FIELD_RECORD_SIZE
            fname_ptr = _read_ptr(bv, entry_addr + _FIELD_OFF_NAME)
            fname = _read_cstring(bv, fname_ptr)
            foff = _read_u32(bv, entry_addr + _FIELD_OFF_OFFSET)
            if not fname:
                continue
            fields.append(SchemaField(name=fname, offset=foff, type_name=None))

    parent: Optional[str] = None
    if base_classes_ptr:
        # Read first base class entry only (Source 2 schemas use single inheritance for these
        # — multiple inheritance is rare and uses a different layout).
        parent_binding_ptr = _read_ptr(bv, base_classes_ptr + _BASE_OFF_PARENT_BINDING)
        if parent_binding_ptr:
            parent_name_ptr = _read_ptr(bv, parent_binding_ptr + _BIND_OFF_NAME)
            parent_name = _read_cstring(bv, parent_name_ptr)
            if parent_name:
                parent = parent_name

    metadata: list[str] = []
    if metadata_ptr and metadata_count > 0:
        for i in range(metadata_count):
            entry_addr = metadata_ptr + i * _METADATA_RECORD_SIZE
            mname_ptr = _read_ptr(bv, entry_addr + 0x00)
            mname = _read_cstring(bv, mname_ptr)
            if mname:
                metadata.append(mname)

    return SchemaClass(name=name, parent=parent, fields=fields, metadata=metadata)


# -------- enum extraction (separate registration phase) --------

# Phase 1 calls (vtable[0x100] and 0x108) register class-name and enum lists. We
# can pull enums out by scanning calls to vtable[0x108].
_ENUM_VTABLE_CALL_OFFSET = 0x108


def _find_enum_arrays_in_function(bv, func, log) -> list[tuple[int, int]]:
    out = []
    for insn, params in _calls_with_offset(bv, func, _ENUM_VTABLE_CALL_OFFSET):
        if len(params) < 6:
            continue
        count = _const_int(params[4])
        ptr = _const_int(params[5])
        if count is None or ptr is None:
            continue
        if ptr == 0 or count <= 0 or count > 4096:
            continue
        if not _looks_like_pointer_into_section(bv, ptr):
            continue
        out.append((count, ptr))
    return out


# Enum binding layout (best-guess from cs2-dumper analysis source — we only need
# name + alignment + member list).
_ENUM_BIND_OFF_NAME = 0x08
_ENUM_BIND_OFF_ALIGNMENT = 0x10  # uint8
_ENUM_BIND_OFF_MEMBER_COUNT = 0x14  # uint16
_ENUM_BIND_OFF_MEMBERS_PTR = 0x18

_ENUM_MEMBER_RECORD_SIZE = 0x18
_ENUM_MEMBER_OFF_NAME = 0x00
_ENUM_MEMBER_OFF_VALUE = 0x10  # i64


def _read_enum_binding(bv, binding_addr: int, log) -> Optional[SchemaEnum]:
    if binding_addr == 0:
        return None
    name_ptr = _read_ptr(bv, binding_addr + _ENUM_BIND_OFF_NAME)
    name = _read_cstring(bv, name_ptr)
    if not name:
        return None

    raw_align = bv.read(binding_addr + _ENUM_BIND_OFF_ALIGNMENT, 1)
    alignment = raw_align[0] if raw_align else 4
    member_count = int.from_bytes(bv.read(binding_addr + _ENUM_BIND_OFF_MEMBER_COUNT, 2) or b"\x00\x00", "little", signed=False)
    members_ptr = _read_ptr(bv, binding_addr + _ENUM_BIND_OFF_MEMBERS_PTR)

    members: list[tuple[str, int]] = []
    if members_ptr and member_count > 0 and member_count < 4096:
        for i in range(member_count):
            entry_addr = members_ptr + i * _ENUM_MEMBER_RECORD_SIZE
            mname_ptr = _read_ptr(bv, entry_addr + _ENUM_MEMBER_OFF_NAME)
            mname = _read_cstring(bv, mname_ptr)
            mval_raw = bv.read(entry_addr + _ENUM_MEMBER_OFF_VALUE, 8)
            if not mname or len(mval_raw) != 8:
                continue
            mval = int.from_bytes(mval_raw, "little", signed=True)
            members.append((mname, mval))

    return SchemaEnum(name=name, alignment=alignment, members=members)


# -------- top-level entry --------

@dataclass
class _ExtractionResult:
    module: SchemaModule
    sizes: dict[str, int]


def _collect_binding_addrs(bv, log) -> tuple[list[int], list[int]]:
    """One-shot walk of every CSchemaRegistration::VFunc0; returns
    (class_binding_addrs, enum_binding_addrs)."""
    funcs = _enumerate_vfunc0(bv)
    log(f"[cs2_schema:static] found {len(funcs)} CSchemaRegistration::VFunc0 instances")

    class_addrs: list[int] = []
    enum_addrs: list[int] = []

    for f in funcs:
        for count, ptr in _find_bindings_arrays_in_function(bv, f, log):
            log(f"  vtable[0x110] @{f.start:#x}: count={count} bindings@{ptr:#x}")
            for i in range(count):
                slot = ptr + i * bv.address_size
                binding_ptr = _read_ptr(bv, slot)
                if binding_ptr:
                    class_addrs.append(binding_ptr)

        for count, ptr in _find_enum_arrays_in_function(bv, f, log):
            log(f"  vtable[0x108] @{f.start:#x}: count={count} enums@{ptr:#x}")
            for i in range(count):
                slot = ptr + i * bv.address_size
                enum_ptr = _read_ptr(bv, slot)
                if enum_ptr:
                    enum_addrs.append(enum_ptr)

    return class_addrs, enum_addrs


def extract_static(bv, log) -> _ExtractionResult:
    """Single-pass extraction. Returns the SchemaModule plus an authoritative
    {class_name: m_nSizeOf} map taken straight from each binding."""
    class_addrs, enum_addrs = _collect_binding_addrs(bv, log)

    # Module name — pull from binding's m_Module if set, else from filename
    module_name = ""
    for b_addr in class_addrs[:64]:
        mod_ptr = _read_ptr(bv, b_addr + 0x18)
        if mod_ptr:
            mod = _read_cstring(bv, mod_ptr)
            if mod:
                module_name = mod if mod.endswith(".dll") else mod + ".dll"
                break
    if not module_name:
        import os
        fn = getattr(bv.file, "original_filename", None) or bv.file.filename
        base = os.path.basename(fn).lower()
        if base.endswith(".bndb"):
            base = base[: -len(".bndb")]
        if not base.endswith(".dll"):
            base = base + ".dll"
        module_name = base

    out = SchemaModule(module_name=module_name)
    sizes: dict[str, int] = {}
    seen_names: set[str] = set()

    for addr in class_addrs:
        cls = _read_class_binding(bv, addr, log)
        if cls is None or cls.name in seen_names:
            continue
        seen_names.add(cls.name)
        out.classes.append(cls)

        sz = _read_u32(bv, addr + _BIND_OFF_SIZEOF)
        if sz > 0:
            sizes[cls.name] = sz

    seen_enum_names: set[str] = set()
    for addr in enum_addrs:
        en = _read_enum_binding(bv, addr, log)
        if en is None or en.name in seen_enum_names:
            continue
        seen_enum_names.add(en.name)
        out.enums.append(en)

    log(f"[cs2_schema:static] extracted {len(out.classes)} classes, {len(out.enums)} enums for {module_name}")
    return _ExtractionResult(module=out, sizes=sizes)


# Backwards-compat shims for the original two-call API
def extract_static_module(bv, log) -> SchemaModule:
    return extract_static(bv, log).module


def static_class_sizes(bv, module: SchemaModule) -> dict[str, int]:
    """Returns {class_name -> m_nSizeOf}. Walks bindings again — prefer
    `extract_static()` which returns both in one pass."""
    return extract_static(bv, lambda *_: None).sizes
