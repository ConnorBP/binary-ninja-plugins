"""Import JSON-described symbols into a BinaryView.

Per symbol:
  1. Skip if `module` doesn't match the loaded binary.
  2. Try each pattern in order. First pattern that finds >=1 hit wins
     (first hit is used — same first-found-is-final semantics as
     CSigScan in fvc).
  3. Apply the resolve op chain on the match address.
  4. Depending on `kind`:
       - "function"  -> ensure a function exists at `addr`, then rename.
       - "data"      -> ensure a data var exists at `addr`, then rename.
       - "raw"       -> no rename; bookmark + comment only (e.g. a disp32
                        embedded in an instruction encoding a member offset).
  5. Tag the address with the `sig_symbol` tag type, and add a comment.

Returns a per-symbol status report the caller can log.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from binaryninja import Symbol, SymbolType, Type

from . import pattern as sig_pattern
from . import resolver as sig_resolver


TAG_TYPE_NAME = "sig_symbol"
TAG_TYPE_ICON = "\U0001F4CD"  # round pushpin


@dataclass
class SymbolStatus:
    name: str
    module: Optional[str]
    state: str            # "applied" | "skipped-module" | "no-match" | "resolve-failed" | "error"
    address: Optional[int] = None
    pattern_index: Optional[int] = None
    match_count: int = 0
    note: str = ""


@dataclass
class ImportReport:
    applied: int = 0
    skipped_module: int = 0
    no_match: int = 0
    resolve_failed: int = 0
    errors: int = 0
    statuses: List[SymbolStatus] = field(default_factory=list)


def _binary_basename(bv) -> str:
    fname = getattr(bv.file, "original_filename", None) or bv.file.filename or ""
    base = os.path.basename(fname).lower()
    if base.endswith(".bndb"):
        base = base[: -len(".bndb")]
    return base


def _module_matches(symbol_module: Optional[str], bv_basename: str) -> bool:
    """True if the JSON entry's `module` matches the loaded BV.

    Matching is case-insensitive and tolerant of `.dll` / no-extension
    variants (so "client.dll" and "client" both match a BV named
    "client.dll" or "client.bndb").
    """
    if not symbol_module:
        return True
    sm = symbol_module.strip().lower()
    if not sm:
        return True
    bn = bv_basename.lower()
    if sm == bn:
        return True
    sm_stem = sm[:-4] if sm.endswith(".dll") else sm
    bn_stem = bn[:-4] if bn.endswith(".dll") else bn
    return sm_stem == bn_stem


def _ensure_tag_type(bv):
    """Get-or-create the global tag type used by this plugin."""
    existing = bv.get_tag_type(TAG_TYPE_NAME)
    if existing is not None:
        return existing
    return bv.create_tag_type(TAG_TYPE_NAME, TAG_TYPE_ICON)


def _add_tag(bv, addr: int, label: str):
    """Pin a tag at `addr`, scoped appropriately for what the address is.

    The Binja idiom (per the API docs):
      - For an address inside a function -> Function.add_tag(name, data,
        addr=addr, auto=False) creates an *address tag* scoped to the
        function (appears in the function's tag panel, the disassembly,
        and the global tag panel).
      - For a data address with no containing function -> BinaryView.add_tag
        (addr, name, data, user=True) creates a *data tag*.

    We dedupe per-scope via the matching getter so re-imports don't stack
    identical tags.
    """
    _ensure_tag_type(bv)
    funcs = []
    try:
        funcs = bv.get_functions_containing(addr) or []
    except Exception:
        funcs = []

    if funcs:
        for func in funcs:
            try:
                existing = func.get_tags_at(addr, auto=False)
            except Exception:
                existing = []
            if any(t.type.name == TAG_TYPE_NAME and t.data == label for t in existing):
                continue
            # Function.add_tag(tag_type_name, data, addr=..., auto=False)
            # creates a user address-tag scoped to this function.
            func.add_tag(TAG_TYPE_NAME, label, addr=addr, auto=False)
    else:
        try:
            existing = bv.get_tags_at(addr, auto=False)
        except Exception:
            existing = []
        if any(t.type.name == TAG_TYPE_NAME and t.data == label for t in existing):
            return
        # BinaryView.add_tag(addr, tag_type_name, data, user=True)
        # creates a user data-tag at the address (no function scope).
        bv.add_tag(addr, TAG_TYPE_NAME, label, True)


def _set_comment(bv, addr: int, comment: str):
    """Apply a comment so it shows up in the decompiler view.

    `bv.set_comment_at` is the GLOBAL comment surface. Function-local
    comments (the ones rendered in the decomp / disassembly of a
    function) live on Function objects via `func.set_comment_at`. For
    every function containing `addr`, set the function-local comment;
    if none contain it (e.g. a `.data` slot), fall back to the global.
    """
    funcs = []
    try:
        funcs = bv.get_functions_containing(addr) or []
    except Exception:
        funcs = []
    if funcs:
        for func in funcs:
            try:
                func.set_comment_at(addr, comment)
            except Exception:
                pass
    else:
        try:
            bv.set_comment_at(addr, comment)
        except Exception:
            pass


def _has_our_tag_at(bv, addr: int) -> bool:
    """True if any sig_symbol tag (in any scope) exists at this address.

    Used to decide whether we're allowed to undo a previous decision
    (e.g. demote a wrongly-created function back to data) without
    clobbering user-authored state.
    """
    try:
        funcs = bv.get_functions_containing(addr) or []
    except Exception:
        funcs = []
    for func in funcs:
        try:
            for t in func.get_tags_at(addr, auto=False):
                if t.type.name == TAG_TYPE_NAME:
                    return True
        except Exception:
            pass
    try:
        for t in bv.get_tags_at(addr, auto=False):
            if t.type.name == TAG_TYPE_NAME:
                return True
    except Exception:
        pass
    return False


def _parse_type(bv, text: str):
    """Parse a C-style type string into a Type. Returns (Type, note).

    On parse failure returns (None, error_message). bv.parse_type_string
    raises SyntaxError on bad input; we surface that message verbatim
    so the user can fix the JSON.
    """
    try:
        parsed_type, _qname = bv.parse_type_string(text)
    except SyntaxError as e:
        return (None, f"parse_type_string error: {e}")
    except Exception as e:
        return (None, f"parse_type_string exception: {e!r}")
    return (parsed_type, "")


def _apply_function_rename(bv, addr: int, name: str, prototype: str = "") -> Tuple[bool, str]:
    """Ensure a function exists at addr, rename it, and optionally set its type.

    If a data var exists at addr from a prior (mis-classified) import — evidenced
    by the presence of our sig_symbol tag — undefine it first so the function
    create lands cleanly.
    """
    notes = []

    if _has_our_tag_at(bv, addr) and bv.get_data_var_at(addr) is not None:
        try:
            bv.undefine_user_data_var(addr)
            notes.append("undefined stale data var")
        except Exception as e:
            notes.append(f"could not undefine stale data var: {e}")

    func = bv.get_function_at(addr)
    created = False
    if func is None:
        # create_user_function returns the new Function (or None) directly.
        func = bv.create_user_function(addr)
        created = True
    if func is None:
        return (False, "; ".join(notes + ["could not create function"]))
    notes.append("renamed (new function)" if created else "renamed")

    existing = bv.get_symbol_at(addr)
    if existing is not None and not existing.auto and existing.name != name:
        notes.append(f"kept user name {existing.name!r} (would-be: {name!r})")
    else:
        bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))

    if prototype:
        # Function.set_user_type accepts a string and parses it internally
        # via bv.parse_type_string. The parsed type's name (if any) is
        # discarded by set_user_type, so our define_user_symbol name above
        # is preserved.
        try:
            func.set_user_type(prototype)
            notes.append("prototype applied")
        except SyntaxError as e:
            notes.append(f"prototype parse error: {e}")
        except Exception as e:
            notes.append(f"prototype apply error: {e!r}")

    return (True, "; ".join(notes))


def _apply_data_rename(bv, addr: int, name: str, data_type: str = "") -> Tuple[bool, str]:
    """Ensure a data var exists at addr with the right type, and rename it.

    If a function exists at addr from a prior (mis-classified) import — evidenced
    by the presence of our sig_symbol tag — remove it first so the data var
    create lands cleanly.
    """
    notes = []

    if _has_our_tag_at(bv, addr):
        func = bv.get_function_at(addr)
        if func is not None:
            try:
                bv.remove_user_function(func)
                notes.append("removed stale auto-created function")
            except Exception as e:
                notes.append(f"could not remove stale function: {e}")

    # Resolve the type to use for the data var.
    if data_type:
        parsed_type, parse_note = _parse_type(bv, data_type)
        if parsed_type is None:
            notes.append(f"data_type fallback to void* ({parse_note})")
            var_type = Type.pointer(bv.arch, Type.void())
        else:
            var_type = parsed_type
    else:
        var_type = Type.pointer(bv.arch, Type.void())

    # define_user_data_var is idempotent and also re-types an existing var,
    # so we can call it unconditionally rather than gating on get_data_var_at.
    try:
        bv.define_user_data_var(addr, var_type)
    except Exception as e:
        return (False, "; ".join(notes + [f"could not create data var: {e}"]))

    existing = bv.get_symbol_at(addr)
    if existing is not None and not existing.auto and existing.name != name:
        notes.append(f"kept user name {existing.name!r} (would-be: {name!r})")
    else:
        bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, name))
        notes.append("renamed")
    return (True, "; ".join(notes))


def _resolve_symbol(bv, entry: dict, bv_basename: str) -> SymbolStatus:
    name = entry.get("name", "<unnamed>")
    module = entry.get("module")

    if not _module_matches(module, bv_basename):
        return SymbolStatus(name=name, module=module, state="skipped-module")

    section = entry.get("section") or ".text"
    patterns = entry.get("patterns") or []
    if not patterns:
        return SymbolStatus(name=name, module=module, state="error", note="no patterns")

    last_note = ""
    for i, pat in enumerate(patterns):
        bytes_str = pat.get("bytes", "")
        if not bytes_str:
            last_note = f"pattern[{i}] empty"
            continue
        try:
            matches = sig_pattern.find_matches(bv, bytes_str, section_name=section)
        except sig_pattern.PatternError as e:
            last_note = f"pattern[{i}] invalid: {e}"
            continue

        if not matches:
            last_note = f"pattern[{i}] zero matches"
            continue

        match_addr = matches[0]
        ops = pat.get("resolve") or []
        try:
            resolved = sig_resolver.apply(bv, match_addr, ops)
        except sig_resolver.ResolveError as e:
            last_note = f"pattern[{i}] resolve error: {e}"
            continue
        if resolved is None:
            last_note = f"pattern[{i}] resolve read out of range"
            continue

        return SymbolStatus(
            name=name,
            module=module,
            state="applied",
            address=resolved,
            pattern_index=i,
            match_count=len(matches),
            note=f"matched (resolve: {sig_resolver.describe(ops)}); {len(matches)} pattern hit(s)",
        )

    return SymbolStatus(
        name=name,
        module=module,
        state="no-match",
        note=last_note or "no pattern matched",
    )


def _apply_symbol(bv, entry: dict, status: SymbolStatus, log) -> None:
    if status.state != "applied" or status.address is None:
        return

    addr = status.address
    name = entry.get("name", "<unnamed>")
    label = entry.get("label") or ""
    kind = (entry.get("kind") or "function").lower()
    user_comment = entry.get("comment") or ""
    prototype = entry.get("prototype") or ""
    data_type = entry.get("data_type") or ""

    apply_ok = True
    apply_note = ""

    if kind == "function":
        apply_ok, apply_note = _apply_function_rename(bv, addr, name, prototype)
    elif kind == "data":
        apply_ok, apply_note = _apply_data_rename(bv, addr, name, data_type)
    elif kind == "raw":
        apply_note = "raw (bookmark + comment only)"
    else:
        apply_ok = False
        apply_note = f"unknown kind {kind!r}"

    tag_label = name if not label else f"{name} :: {label}"
    _add_tag(bv, addr, tag_label)

    comment_lines = [f"[sig] {name}"]
    if label:
        comment_lines.append(label)
    if user_comment:
        comment_lines.append(user_comment)
    comment_lines.append(f"kind={kind}  pattern#{status.pattern_index}  ({status.match_count} hit(s))")
    _set_comment(bv, addr, "\n".join(comment_lines))

    status.note = (status.note + "; " + apply_note).strip("; ")
    if not apply_ok:
        status.state = "error"


def import_symbols(bv, doc: Dict[str, Any], log) -> ImportReport:
    """Apply every symbol in `doc["symbols"]` to `bv`. Wraps everything in
    a single undo group so a bad import can be rolled back in one click."""
    symbols = doc.get("symbols") or []
    bv_basename = _binary_basename(bv)
    log(f"[sig_symbol_importer] target binary: {bv_basename}; entries: {len(symbols)}")

    report = ImportReport()

    bv.begin_undo_actions()
    try:
        for entry in symbols:
            try:
                status = _resolve_symbol(bv, entry, bv_basename)
                _apply_symbol(bv, entry, status, log)
            except Exception as e:
                status = SymbolStatus(
                    name=entry.get("name", "<unnamed>"),
                    module=entry.get("module"),
                    state="error",
                    note=f"unhandled: {e!r}",
                )

            report.statuses.append(status)
            if status.state == "applied":
                report.applied += 1
            elif status.state == "skipped-module":
                report.skipped_module += 1
            elif status.state == "no-match":
                report.no_match += 1
            elif status.state == "resolve-failed":
                report.resolve_failed += 1
            else:
                report.errors += 1
    finally:
        bv.commit_undo_actions()

    log(
        f"[sig_symbol_importer] applied={report.applied} "
        f"skipped-module={report.skipped_module} "
        f"no-match={report.no_match} "
        f"errors={report.errors}"
    )
    for s in report.statuses:
        if s.state in ("no-match", "error"):
            log(f"[sig_symbol_importer] {s.state}: {s.name} ({s.module}) — {s.note}")
        elif s.state == "applied":
            log(f"[sig_symbol_importer] applied {s.name} @ {s.address:#x}  {s.note}")
    return report
