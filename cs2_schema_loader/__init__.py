"""
CS2 Schema Loader for Binary Ninja.

Reads cs2-dumper output (output/<module>_dll.hpp) and registers each schema
class as a named user type in the current BinaryView, so disassembly / decomp
of client.dll, server.dll, etc. shows real Source 2 names + offsets.

Plugin command:
  Plugins -> CS2 Schema -> Apply Schemas From cs2-dumper

Setting:
  cs2_schema.dumperOutputDir — path to the cs2-dumper `output/` directory.
"""

from __future__ import annotations

import os

from binaryninja import (
    PluginCommand, Settings, BackgroundTaskThread, log_info, log_error, log_warn,
    interaction,
)

# Use absolute imports of our package modules
from . import parser as schema_parser
from . import builder as schema_builder
from . import static_extractor


_SETTINGS_GROUP = "cs2_schema"
_SETTINGS_KEY = "cs2_schema.dumperOutputDir"
_SETTINGS_USE_VTABLE_UNION = "cs2_schema.useVtableUnion"


def _register_settings():
    s = Settings()
    s.register_group(_SETTINGS_GROUP, "CS2 Schema Loader")
    s.register_setting(
        _SETTINGS_KEY,
        '''{
            "title" : "cs2-dumper output directory",
            "type" : "string",
            "default" : "",
            "description" : "Path to the cs2-dumper `output/` folder containing client_dll.hpp, server_dll.hpp, etc.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }'''
    )
    s.register_setting(
        _SETTINGS_USE_VTABLE_UNION,
        '''{
            "title" : "Embed vtable as union with __base",
            "type" : "boolean",
            "default" : true,
            "description" : "Binary Ninja's RTTI processor auto-creates `*::VTable` struct types for classes with virtuals. When this is on, every schema class whose name matches one of those auto-generated types gets a union { vtable*, __base } at offset 0 — so `obj.vtable` and `obj.__base` are both valid. Disable if Binary Ninja's union display becomes a problem and you'd rather keep just `__base`.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }'''
    )


def _resolve_output_dir(bv) -> str:
    s = Settings()
    configured = s.get_string(_SETTINGS_KEY) or ""
    if configured and os.path.isdir(configured):
        return configured

    # Common defaults — try them in order before prompting.
    candidates = [
        r"E:\DEVELOPER\PROJECTS\sus\cs2-dumper\output",
        r"E:\DEVELOPER\PROJECTS\sus\vacnetme_workspace\..\cs2-dumper\output",
        os.path.expanduser(r"~\Documents\cs2-dumper\output"),
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c

    # Prompt the user
    chosen = interaction.get_directory_name_input("Select cs2-dumper output/ directory")
    if chosen and os.path.isdir(chosen):
        s.set_string(_SETTINGS_KEY, chosen)
        return chosen

    raise FileNotFoundError("cs2-dumper output directory not configured")


def _detect_module_name(bv) -> str:
    """Heuristic: pull the .dll filename out of bv.file.filename / bv.file.original_filename."""
    fname = getattr(bv.file, "original_filename", None) or bv.file.filename
    base = os.path.basename(fname)
    base = base.lower()
    # Strip BNDB suffix if present (e.g. client.bndb)
    if base.endswith(".bndb"):
        base = base[: -len(".bndb")]
    if not base.endswith(".dll"):
        base = base + ".dll"
    return base


class _Task(BackgroundTaskThread):
    def __init__(self, bv, output_dir: str, module_name: str):
        super().__init__(f"CS2 Schema Loader: applying schema for {module_name}", can_cancel=False)
        self.bv = bv
        self.output_dir = output_dir
        self.module_name = module_name

    def run(self):
        log_info(f"[cs2_schema] loading schema for {self.module_name} from {self.output_dir}")
        try:
            module = schema_parser.load_module(self.output_dir, self.module_name)
        except FileNotFoundError as e:
            log_error(f"[cs2_schema] {e}")
            return
        except Exception as e:
            log_error(f"[cs2_schema] failed to parse: {e}")
            return

        log_info(
            f"[cs2_schema] parsed {len(module.classes)} classes, {len(module.enums)} enums "
            f"for module {module.module_name}"
        )

        use_union = Settings().get_bool(_SETTINGS_USE_VTABLE_UNION)
        self.bv.begin_undo_actions()
        try:
            n_cls, n_enum = schema_builder.apply_module(
                self.bv, module, log_warn, use_vtable_union=use_union,
            )
            log_info(f"[cs2_schema] applied {n_cls} classes, {n_enum} enums")
        finally:
            self.bv.commit_undo_actions()


def _cmd_apply_detected(bv):
    """Detect module name from BinaryView filename and apply."""
    try:
        output_dir = _resolve_output_dir(bv)
    except Exception as e:
        log_error(f"[cs2_schema] {e}")
        return

    module = _detect_module_name(bv)
    log_info(f"[cs2_schema] detected module: {module}")
    _Task(bv, output_dir, module).start()


def _cmd_apply_chosen(bv):
    """Prompt for module name, then apply."""
    try:
        output_dir = _resolve_output_dir(bv)
    except Exception as e:
        log_error(f"[cs2_schema] {e}")
        return

    available = []
    for f in sorted(os.listdir(output_dir)):
        if f.endswith("_dll.hpp"):
            stem = f[: -len("_dll.hpp")]
            available.append(stem + ".dll")

    if not available:
        log_error(f"[cs2_schema] no schema dumps found in {output_dir}")
        return

    field = interaction.ChoiceField("Module", available)
    if not interaction.get_form_input([field], "Apply CS2 Schema"):
        return
    module = available[field.result]
    _Task(bv, output_dir, module).start()


def _cmd_set_output_dir(bv):
    chosen = interaction.get_directory_name_input("Select cs2-dumper output/ directory")
    if chosen and os.path.isdir(chosen):
        Settings().set_string(_SETTINGS_KEY, chosen)
        log_info(f"[cs2_schema] cs2-dumper output dir set to {chosen}")


class _StaticTask(BackgroundTaskThread):
    """Walk CSchemaRegistration::VFunc0 functions in this binary, extract every
    class binding from static data, and apply them as user types."""

    def __init__(self, bv):
        super().__init__("CS2 Schema Loader: extracting from static binary", can_cancel=False)
        self.bv = bv

    def run(self):
        try:
            result = static_extractor.extract_static(self.bv, log_info)
        except Exception as e:
            log_error(f"[cs2_schema:static] extraction failed: {e}")
            return

        module = result.module
        if not module.classes and not module.enums:
            log_warn("[cs2_schema:static] no schemas extracted — is this a CS2 module with embedded schema?")
            return

        use_union = Settings().get_bool(_SETTINGS_USE_VTABLE_UNION)
        self.bv.begin_undo_actions()
        try:
            n_cls, n_enum = schema_builder.apply_module(
                self.bv,
                module,
                log_warn,
                size_overrides=result.sizes,
                use_vtable_union=use_union,
            )
            log_info(f"[cs2_schema:static] applied {n_cls} classes, {n_enum} enums")
        finally:
            self.bv.commit_undo_actions()


def _cmd_apply_static(bv):
    _StaticTask(bv).start()


_register_settings()

PluginCommand.register(
    "CS2 Schema\\Apply Schemas From cs2-dumper (auto-detect module)",
    "Read cs2-dumper output and register every schema class as a named user type matching the current binary",
    _cmd_apply_detected,
)

PluginCommand.register(
    "CS2 Schema\\Apply Schemas From cs2-dumper (choose module)",
    "Same as auto-detect, but prompts you to pick the module",
    _cmd_apply_chosen,
)

PluginCommand.register(
    "CS2 Schema\\Set cs2-dumper output directory",
    "Configure the path to the cs2-dumper output/ folder",
    _cmd_set_output_dir,
)

PluginCommand.register(
    "CS2 Schema\\Extract Schema From Current Binary (static, no dumper needed)",
    "Walk CSchemaRegistration::VFunc0 in the loaded module and pull every class binding straight out of static data — no live process, no dumper output.",
    _cmd_apply_static,
)
