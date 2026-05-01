"""
vtable_rename.py - Binary Ninja plugin for filling in auto-generated VTables.

Walks every data variable typed as `*::VTable` and applies one or both passes:

  Pass 1: For each slot, rename the target function to `ClassName::VFuncN`.
  Pass 2: For each renamed function, retype `arg1` to `ClassName *` (creating
          an empty struct named `ClassName` if one doesn't already exist).

User-renamed functions (symbol.auto == False) and user-typed first arguments
(pointer-to-NamedTypeReference) are skipped. When the same function appears
in multiple vtables, the class with the shortest name wins.

Commands register under Plugins -> Vtable Rename.
"""

import re

from binaryninja import (
    PluginCommand,
    Type,
    StructureBuilder,
    QualifiedName,
    log_info,
    log_warn,
)
from binaryninja.enums import (
    TypeClass,
    NamedTypeReferenceClass,
)


AUTO_CREATE_FUNCTIONS = True


VTABLE_SUFFIX = "::VTable"


def _split_qualified(s):
    """Split a C++ qualified name on '::' while respecting template angle brackets.

    BN sometimes hands us a QualifiedName whose `list()` yields the full
    `'A::B::VTable'` as a single atomic part (no auto-split), so we split
    here ourselves. Templates like `Foo<Bar, Baz<Qux>>::Inner` must not split
    inside `<...>`.
    """
    parts = []
    depth = 0
    current = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "<":
            depth += 1
            current.append(c)
            i += 1
        elif c == ">":
            depth -= 1
            current.append(c)
            i += 1
        elif depth == 0 and c == ":" and i + 1 < len(s) and s[i + 1] == ":":
            parts.append("".join(current))
            current = []
            i += 2
        else:
            current.append(c)
            i += 1
    if current:
        parts.append("".join(current))
    return parts


def _is_vtable_qname(qname):
    """True if the qname's string form looks like a vtable type."""
    if qname is None:
        return False
    s = str(qname)
    if s.endswith(VTABLE_SUFFIX):
        return True
    sl = s.lower()
    return sl.endswith("vftable") or sl.endswith("vftable'") or "::vftable" in sl


def _vtable_class_name(qname):
    """Extract owning class name. 'A::B::VTable' -> 'B'. Template-aware."""
    if qname is None:
        return None
    s = str(qname)
    if s.endswith(VTABLE_SUFFIX):
        base = s[: -len(VTABLE_SUFFIX)]
        parts = _split_qualified(base)
    else:
        parts = _split_qualified(s)
        while parts and ("vftable" in parts[-1].lower() or "vtable" in parts[-1].lower()):
            parts.pop()
    if not parts:
        return None
    cls = str(parts[-1]).strip("`'\"")
    return cls if cls else None


def _ntr_qname(t):
    """Pull a QualifiedName out of a NamedTypeReferenceType, robust to API shape.

    Modern BN exposes `t.name` directly. Older versions had a `named_type_reference`
    instance property that returned a NamedTypeReference object with `.name`.
    On the user's BN, `Type.named_type_reference` is the static constructor, so
    accessing it on an instance returns the function itself - hence the callable
    guards below.
    """
    n = getattr(t, "name", None)
    if n is not None and not callable(n):
        return n
    legacy = getattr(t, "named_type_reference", None)
    if legacy is not None and not callable(legacy):
        n = getattr(legacy, "name", None)
        if n is not None and not callable(n):
            return n
    return None


def _resolve_ntr(bv, t, max_depth=8):
    """Follow NamedTypeReference links until we land on a concrete type.

    bv.types may contain `Foo::VTable` as another NTR (forward decl) that
    points elsewhere - keep dereferencing so we end up with the actual
    StructureType whose `.members` we can iterate.
    """
    seen = set()
    depth = 0
    while t is not None and t.type_class == TypeClass.NamedTypeReferenceClass and depth < max_depth:
        n = _ntr_qname(t)
        if n is None:
            return t
        key = str(n)
        if key in seen:
            return t
        seen.add(key)
        nxt = bv.get_type_by_name(n)
        if nxt is None or nxt is t:
            return t
        t = nxt
        depth += 1
    return t


VFTABLE_MARKER = "::`vftable'"
MAX_HEURISTIC_SLOTS = 512


def _is_code_pointer(bv, addr):
    """True if `addr` lives in an executable segment."""
    if addr == 0:
        return False
    seg = bv.get_segment_at(addr)
    if seg is None:
        return False
    return bool(getattr(seg, "executable", False))


_VFTABLE_FOR_RE = re.compile(r"^\{for `(.+)'\}")


def _vtable_symbol_class_name(sym_name):
    """Extract the canonical class for a vftable symbol's slot indexing.

    For `Foo::``vftable'{for `Bar'}`: the slot layout follows Bar's vtable
    (Bar is the base subobject this vtable serves), so return Bar - that's
    the only class whose VFuncN indices are consistent here.

    For a plain `Foo::``vftable'` (primary): return Foo.
    """
    if not sym_name:
        return None
    idx = sym_name.find(VFTABLE_MARKER)
    if idx <= 0:
        return None

    suffix = sym_name[idx + len(VFTABLE_MARKER):]
    m = _VFTABLE_FOR_RE.match(suffix)
    if m:
        path = m.group(1)
    else:
        path = sym_name[:idx]

    parts = _split_qualified(path)
    if not parts:
        return None
    cls = parts[-1].strip("`'\"")
    return cls if cls else None


def _iter_vtable_typed(bv):
    """Yield vtable instances for data vars whose type resolves to a `*::VTable` struct.

    Slot index comes from `member.offset // ptr_size`, not enumerate(), so any
    skipped/padded member doesn't shift everything. Class name prefers the data
    var's symbol (which encodes MSVC `{for `Base'}` correctly) over the struct
    type name.
    """
    ptr_size = bv.address_size
    for dv_addr, dv in bv.data_vars.items():
        t = dv.type
        qname = None

        if t.type_class == TypeClass.NamedTypeReferenceClass:
            qname = _ntr_qname(t)
        elif t.type_class == TypeClass.StructureTypeClass:
            reg = getattr(t, "registered_name", None)
            if reg is not None:
                rn = getattr(reg, "name", None)
                if rn is not None and not callable(rn):
                    qname = rn

        if not _is_vtable_qname(qname):
            continue

        cls = None
        sym = bv.get_symbol_at(dv_addr)
        if sym is not None and VFTABLE_MARKER in sym.name:
            cls = _vtable_symbol_class_name(sym.name)
        if cls is None:
            cls = _vtable_class_name(qname)
        if cls is None:
            continue

        struct_t = _resolve_ntr(bv, t)
        if struct_t is None or struct_t.type_class != TypeClass.StructureTypeClass:
            continue
        if not getattr(struct_t, "members", None):
            continue

        slots = []
        for member in struct_t.members:
            if member.offset % ptr_size != 0:
                continue
            slot_idx = member.offset // ptr_size
            raw = bv.read(dv_addr + member.offset, ptr_size)
            if len(raw) != ptr_size:
                continue
            func_addr = int.from_bytes(raw, "little")
            if func_addr == 0:
                continue
            slots.append((slot_idx, func_addr))

        if slots:
            yield dv_addr, cls, slots


def _iter_vtable_symbols(bv):
    """Yield vtable instances by walking every `vftable'` symbol.

    Slot count is heuristic - we read pointer-sized words starting at the
    symbol address and stop on the first slot that doesn't point into an
    executable segment. Capped at MAX_HEURISTIC_SLOTS.
    """
    ptr_size = bv.address_size
    for sym in bv.get_symbols():
        name = sym.name
        if VFTABLE_MARKER not in name:
            continue
        cls = _vtable_symbol_class_name(name)
        if cls is None:
            continue

        addr = sym.address
        slots = []
        for idx in range(MAX_HEURISTIC_SLOTS):
            slot_addr = addr + idx * ptr_size
            raw = bv.read(slot_addr, ptr_size)
            if len(raw) != ptr_size:
                break
            ptr_val = int.from_bytes(raw, "little")
            if not _is_code_pointer(bv, ptr_val):
                break
            slots.append((idx, ptr_val))

        if slots:
            yield addr, cls, slots


def _iter_vtable_instances(bv):
    """Combined discovery: typed vtables (precise slot count) then symbol-named
    vtables (heuristic). Deduped by address - typed wins if both find the same
    instance."""
    seen = set()
    for addr, cls, slots in _iter_vtable_typed(bv):
        if addr in seen:
            continue
        seen.add(addr)
        yield addr, cls, slots
    for addr, cls, slots in _iter_vtable_symbols(bv):
        if addr in seen:
            continue
        seen.add(addr)
        yield addr, cls, slots


def _collect_chosen(bv):
    """For each function address seen across all vtables, pick (class, slot_idx).

    When the same function appears in multiple vtables with DIFFERENT slot
    indices (shared thunks, _purecall stubs, etc.), the majority slot wins -
    avoids labeling a function with an index that's only valid in one obscure
    vtable. Then within that majority slot, shortest class name wins (most-
    parented heuristic), alphabetical tiebreak for determinism.
    """
    candidates = {}
    for _, cls, slots in _iter_vtable_instances(bv):
        for slot_idx, func_addr in slots:
            candidates.setdefault(func_addr, []).append((cls, slot_idx))

    chosen = {}
    for func_addr, opts in candidates.items():
        slot_counts = {}
        for _, slot_idx in opts:
            slot_counts[slot_idx] = slot_counts.get(slot_idx, 0) + 1
        majority_slot = max(slot_counts.keys(), key=lambda s: (slot_counts[s], -s))
        in_majority = [(c, s) for c, s in opts if s == majority_slot]
        in_majority.sort(key=lambda x: (len(x[0]), x[0]))
        chosen[func_addr] = in_majority[0]
    return chosen


def _function_has_user_name(func):
    """True if the function has any name other than BN's default auto-generated one.

    Belt-and-suspenders: any name not matching `sub_*` / `j_sub_*` is treated as
    user-set (or set by another plugin) and left alone, regardless of what
    `sym.auto` reports. This protects manual renames where BN's auto flag
    didn't get cleared - we'd rather miss renaming a few `sub_*` that the
    user happened to leave alone than ever clobber a real name.
    """
    name = func.name
    if not name:
        return False
    if name.startswith("sub_") or name.startswith("j_sub_"):
        sym = func.symbol
        if sym is not None and not sym.auto:
            return True
        return False
    return True


def _first_arg_is_struct_pointer(param_var):
    pt = param_var.type
    if pt is None:
        return False
    if pt.type_class != TypeClass.PointerTypeClass:
        return False
    target = pt.target
    if target is None:
        return False
    return target.type_class == TypeClass.NamedTypeReferenceClass


def _ensure_class_struct(bv, class_name):
    qname = QualifiedName([class_name])
    if bv.get_type_by_name(qname) is not None:
        return qname
    bv.define_user_type(qname, Type.structure_type(StructureBuilder.create()))
    return qname


def _rename_pass(bv, chosen):
    created = 0
    if AUTO_CREATE_FUNCTIONS:
        missing = [a for a in chosen.keys() if bv.get_function_at(a) is None]
        if missing:
            log_info(f"vtable_rename pass1: creating {len(missing)} functions, waiting for analysis...")
            for addr in missing:
                bv.add_function(addr)
            bv.update_analysis_and_wait()
            created = sum(1 for a in missing if bv.get_function_at(a) is not None)
            log_info(f"vtable_rename pass1: created {created}/{len(missing)} functions")

    renamed = 0
    skipped_user = 0
    skipped_no_func = 0
    for func_addr, (cls, slot_idx) in chosen.items():
        func = bv.get_function_at(func_addr)
        if func is None:
            skipped_no_func += 1
            continue
        if _function_has_user_name(func):
            skipped_user += 1
            continue
        func.name = f"{cls}::VFunc{slot_idx}"
        renamed += 1
    log_info(
        f"vtable_rename pass1: renamed={renamed} created={created} "
        f"skipped(user-named)={skipped_user} skipped(no-func)={skipped_no_func}"
    )


def _retype_pass(bv, chosen):
    typed = 0
    skipped_typed = 0
    skipped_no_params = 0
    skipped_no_func = 0

    type_cache = {}
    for func_addr, (cls, _) in chosen.items():
        func = bv.get_function_at(func_addr)
        if func is None:
            skipped_no_func += 1
            continue

        params = func.parameter_vars
        if len(params) == 0:
            skipped_no_params += 1
            continue

        first = params[0]
        if _first_arg_is_struct_pointer(first):
            skipped_typed += 1
            continue

        if cls not in type_cache:
            qname = _ensure_class_struct(bv, cls)
            ntr = Type.named_type_reference(
                NamedTypeReferenceClass.StructNamedTypeClass, qname
            )
            type_cache[cls] = Type.pointer(bv.arch, ntr)

        first.type = type_cache[cls]
        if first.name in ("", "arg1"):
            first.name = "this"
        typed += 1

    log_info(
        f"vtable_rename pass2: typed={typed} skipped(already-typed)={skipped_typed} "
        f"skipped(no-params)={skipped_no_params} skipped(no-func)={skipped_no_func}"
    )


def cmd_pass1(bv):
    chosen = _collect_chosen(bv)
    if not chosen:
        log_warn("vtable_rename: no `*::VTable` data vars found")
        return
    bv.begin_undo_actions()
    try:
        _rename_pass(bv, chosen)
    finally:
        bv.commit_undo_actions()


def cmd_pass2(bv):
    chosen = _collect_chosen(bv)
    if not chosen:
        log_warn("vtable_rename: no `*::VTable` data vars found")
        return
    bv.begin_undo_actions()
    try:
        _retype_pass(bv, chosen)
    finally:
        bv.commit_undo_actions()


def cmd_both(bv):
    chosen = _collect_chosen(bv)
    if not chosen:
        log_warn("vtable_rename: no `*::VTable` data vars found")
        return
    bv.begin_undo_actions()
    try:
        _rename_pass(bv, chosen)
        _retype_pass(bv, chosen)
    finally:
        bv.commit_undo_actions()


def _tc_name(tc):
    return tc.name if hasattr(tc, "name") else str(tc)


def cmd_diagnose(bv):
    """Dump what BN's type system actually exposes for vtables.

    If pass1 finds nothing, run this and share the log: it shows what shapes
    `bv.types` and `bv.data_vars` are using so the matcher can be adjusted.
    """
    log_info("=== vtable_rename diagnose ===")

    log_info("[1] bv.types entries that look vtable-ish:")
    type_hits = 0
    for qname, t in bv.types.items():
        if not _is_vtable_qname(qname):
            continue
        try:
            parts = list(qname)
        except Exception:
            parts = ["<unlistable>"]
        n_members = len(t.members) if hasattr(t, "members") and t.members is not None else 0
        log_info(
            f"  qname={str(qname)!r} parts={parts!r} "
            f"class={_vtable_class_name(qname)!r} "
            f"type_class={_tc_name(t.type_class)} members={n_members}"
        )
        type_hits += 1
        if type_hits >= 10:
            log_info("  (...truncated at 10)")
            break
    if type_hits == 0:
        log_info("  (none)")

    log_info("[2] bv.data_vars whose type str contains 'vtable'/'vftable':")
    dv_hits = 0
    type_class_counts = {}
    total = 0
    for addr, dv in bv.data_vars.items():
        total += 1
        t = dv.type
        tc = _tc_name(t.type_class)
        type_class_counts[tc] = type_class_counts.get(tc, 0) + 1
        ts = str(t)
        tsl = ts.lower()
        if "vtable" not in tsl and "vftable" not in tsl:
            continue
        sym = bv.get_symbol_at(addr)
        log_info(f"  @{addr:#x}: type_class={tc} sym={sym.name if sym else None!r}")
        log_info(f"    str(type) = {ts[:300]!r}")
        log_info(f"    registered_name = {getattr(t, 'registered_name', 'MISSING')!r}")
        log_info(f"    name           = {getattr(t, 'name', 'MISSING')!r}")
        log_info(f"    target         = {getattr(t, 'target', 'MISSING')!r}")
        dv_hits += 1
        if dv_hits >= 5:
            log_info("  (...truncated at 5)")
            break
    if dv_hits == 0:
        log_info("  (no matching data vars)")
    log_info(f"  data_vars total: {total}, type_class breakdown: {type_class_counts}")

    log_info("[3] symbols whose name contains `::`vftable'`:")
    sym_count = 0
    for sym in bv.get_symbols():
        if VFTABLE_MARKER in sym.name:
            sym_count += 1
    log_info(f"  total vftable symbols: {sym_count}")
    log_info("=== end diagnose ===")


PluginCommand.register(
    "Vtable Rename\\Pass 1: Rename vtable functions",
    "Rename auto-named vtable function targets to ClassName::VFuncN.",
    cmd_pass1,
)

PluginCommand.register(
    "Vtable Rename\\Pass 2: Type first argument as ClassName *",
    "Retype arg1 of each vtable function to a pointer to the owning class struct.",
    cmd_pass2,
)

PluginCommand.register(
    "Vtable Rename\\Run both passes",
    "Run pass 1 (rename) followed by pass 2 (retype).",
    cmd_both,
)

PluginCommand.register(
    "Vtable Rename\\Diagnose: show what BN exposes for vtables",
    "Log shape of bv.types and bv.data_vars entries that look vtable-ish.",
    cmd_diagnose,
)
