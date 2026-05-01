"""
cvar_rename.py - Auto-rename CVar (or other) globals via a register-style helper.

Right-click a registration function (e.g. RegisterCvar / ConVar_Register) and
pick:

  Plugins -> CVar Rename -> Rename globals from this register-fn

The plugin walks every call to that function via HLIL, extracts the constant
pointer passed as arg1 (the global) and the C-string passed as arg2 (the name),
and renames the data var at arg1's address to `cvar_<name>` (sanitized).
User-named symbols and calls whose args can't be resolved as constants are
skipped. Tweak CVAR_PREFIX / GLOBAL_ARG_INDEX / NAME_ARG_INDEX below to retarget.
"""

from binaryninja import (
    PluginCommand,
    Symbol,
    SymbolType,
    Type,
    log_info,
    log_warn,
)
from binaryninja.enums import HighLevelILOperation


CVAR_PREFIX = "cvar_"
GLOBAL_ARG_INDEX = 0   # zero-based index of the global-pointer parameter
NAME_ARG_INDEX = 1     # zero-based index of the name-string parameter


def _sanitize(s):
    return "".join(c if (c.isalnum() or c == "_") else "_" for c in s)


def _walk_hlil(expr):
    """Recursively yield expression and every sub-expression it contains."""
    yield expr
    for op in getattr(expr, "operands", None) or []:
        if hasattr(op, "operation"):
            yield from _walk_hlil(op)
        elif isinstance(op, (list, tuple)):
            for o in op:
                if hasattr(o, "operation"):
                    yield from _walk_hlil(o)


def _const_addr(expr):
    if expr is None:
        return None
    if expr.operation in (
        HighLevelILOperation.HLIL_CONST_PTR,
        HighLevelILOperation.HLIL_IMPORT,
        HighLevelILOperation.HLIL_EXTERN_PTR,
        HighLevelILOperation.HLIL_CONST,
    ):
        return expr.constant
    return None


def _read_cstring(bv, addr):
    s = bv.get_string_at(addr)
    if s is not None:
        return s.value
    s = bv.get_ascii_string_at(addr, min_length=1)
    if s is not None:
        return s.value
    return None


def cmd_rename_globals_via_register_fn(bv, func):
    callee_addr = func.start

    callers = set()
    for ref in bv.get_code_refs(callee_addr):
        if ref.function is not None:
            callers.add(ref.function)

    plan = {}
    conflicts = []
    skipped_extract = 0

    for caller in callers:
        hlil = caller.hlil
        if hlil is None:
            continue
        for instr in hlil.instructions:
            for expr in _walk_hlil(instr):
                if expr.operation not in (
                    HighLevelILOperation.HLIL_CALL,
                    HighLevelILOperation.HLIL_TAILCALL,
                ):
                    continue
                if _const_addr(expr.dest) != callee_addr:
                    continue

                params = list(expr.params)
                if len(params) <= max(GLOBAL_ARG_INDEX, NAME_ARG_INDEX):
                    skipped_extract += 1
                    continue

                global_addr = _const_addr(params[GLOBAL_ARG_INDEX])
                name_addr = _const_addr(params[NAME_ARG_INDEX])
                if global_addr is None or name_addr is None:
                    skipped_extract += 1
                    continue

                name = _read_cstring(bv, name_addr)
                if name is None:
                    skipped_extract += 1
                    continue

                sanitized = _sanitize(name)
                if not sanitized:
                    continue

                new_name = f"{CVAR_PREFIX}{sanitized}"
                if global_addr in plan and plan[global_addr] != new_name:
                    conflicts.append((global_addr, plan[global_addr], new_name))
                    continue
                plan[global_addr] = new_name

    if not plan:
        log_warn(
            f"cvar_rename: no usable call sites for {func.name} "
            f"(skipped(arg-extract)={skipped_extract}). "
            f"Check that args at indices {GLOBAL_ARG_INDEX}/{NAME_ARG_INDEX} are constants."
        )
        return

    log_info(f"cvar_rename: planned {len(plan)} renames; sample:")
    for i, (addr, new_name) in enumerate(plan.items()):
        if i >= 5:
            break
        log_info(f"  {addr:#x} -> {new_name}")

    bv.begin_undo_actions()
    try:
        renamed = 0
        skipped_user = 0
        created_dv = 0
        for addr, new_name in plan.items():
            existing = bv.get_symbol_at(addr)
            if existing is not None and not existing.auto:
                skipped_user += 1
                continue

            if bv.get_data_var_at(addr) is None:
                bv.define_user_data_var(addr, Type.pointer(bv.arch, Type.void()))
                created_dv += 1

            bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, new_name))
            renamed += 1

        log_info(
            f"cvar_rename: renamed={renamed} created_data_vars={created_dv} "
            f"skipped(user-named)={skipped_user} skipped(arg-extract)={skipped_extract} "
            f"conflicts={len(conflicts)}"
        )
        for addr, kept, also in conflicts[:10]:
            log_warn(f"  conflict @ {addr:#x}: kept '{kept}', also saw '{also}'")
    finally:
        bv.commit_undo_actions()


PluginCommand.register_for_function(
    "CVar Rename\\Rename globals from this register-fn",
    "Walk this function's call sites; rename the global passed as arg1 based on the string at arg2.",
    cmd_rename_globals_via_register_fn,
)
