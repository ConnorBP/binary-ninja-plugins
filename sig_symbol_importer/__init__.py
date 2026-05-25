"""Sig Symbol Importer for Binary Ninja.

Loads a JSON manifest of symbol names + signature patterns, scans the
loaded module for each pattern, applies a resolution chain (mirroring
fvc's CPointer Absolute/Offset/Dereference), and:
  - renames the function or data symbol at the resolved address, AND
  - bookmarks the address via a `sig_symbol` tag + adds a comment.

Plugin commands (under "Plugins -> Sig Symbol Importer"):
  - Import symbols from JSON…
  - Re-import using last JSON
  - Export current symbols to JSON…
  - Set default JSON path

Setting:
  sig_symbol_importer.defaultJsonPath
"""

from __future__ import annotations

import json
import os
from typing import Optional

from binaryninja import (
    PluginCommand, Settings, BackgroundTaskThread,
    log_info, log_warn, log_error,
    interaction,
)

from . import importer as sig_importer
from . import exporter as sig_exporter


_SETTINGS_GROUP = "sig_symbol_importer"
_SETTINGS_KEY = "sig_symbol_importer.defaultJsonPath"


def _register_settings():
    s = Settings()
    s.register_group(_SETTINGS_GROUP, "Sig Symbol Importer")
    s.register_setting(
        _SETTINGS_KEY,
        '''{
            "title" : "Default symbols JSON path",
            "type" : "string",
            "default" : "",
            "description" : "Pre-fill the open-file dialog with this path. Also used by 'Re-import using last JSON'.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        }'''
    )


def _resolve_default_path() -> Optional[str]:
    s = Settings()
    p = s.get_string(_SETTINGS_KEY) or ""
    if p and os.path.isfile(p):
        return p
    return None


def _prompt_for_json() -> Optional[str]:
    # Note: get_open_filename_input(prompt, ext) does not accept a default-path
    # argument (only get_save_filename_input does). The saved default is still
    # used by the "Re-import using last JSON" command, which bypasses this
    # dialog entirely.
    chosen = interaction.get_open_filename_input(
        "Select symbols JSON",
        "JSON files (*.json);;All files (*)",
    )
    if not chosen:
        return None
    if not os.path.isfile(chosen):
        log_error(f"[sig_symbol_importer] not a file: {chosen}")
        return None
    return chosen


def _read_doc(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log_error(f"[sig_symbol_importer] failed to read {path}: {e}")
        return None


class _ImportTask(BackgroundTaskThread):
    def __init__(self, bv, json_path: str):
        super().__init__(f"Sig Symbol Importer: {os.path.basename(json_path)}", can_cancel=False)
        self.bv = bv
        self.json_path = json_path

    def run(self):
        doc = _read_doc(self.json_path)
        if doc is None:
            return
        sig_importer.import_symbols(self.bv, doc, log_info)
        # Stash this path as the default for next time.
        Settings().set_string(_SETTINGS_KEY, self.json_path)


def _cmd_import(bv):
    path = _prompt_for_json()
    if path is None:
        return
    _ImportTask(bv, path).start()


def _cmd_reimport(bv):
    path = _resolve_default_path()
    if path is None:
        log_warn("[sig_symbol_importer] no default JSON set; use 'Import symbols from JSON…' first.")
        return
    _ImportTask(bv, path).start()


def _cmd_export(bv):
    default = _resolve_default_path() or ""
    if default:
        default = os.path.splitext(default)[0] + ".exported.json"
    chosen = interaction.get_save_filename_input(
        "Save exported symbols to JSON",
        "JSON files (*.json);;All files (*)",
        default,
    )
    if not chosen:
        return
    try:
        n = sig_exporter.write_export(bv, chosen)
        log_info(f"[sig_symbol_importer] wrote {n} entries to {chosen}")
    except Exception as e:
        log_error(f"[sig_symbol_importer] export failed: {e}")


def _cmd_set_default_path(bv):
    chosen = interaction.get_open_filename_input(
        "Select default symbols JSON",
        "JSON files (*.json);;All files (*)",
    )
    if not chosen:
        return
    Settings().set_string(_SETTINGS_KEY, chosen)
    log_info(f"[sig_symbol_importer] default JSON path set to {chosen}")


_register_settings()

PluginCommand.register(
    "Sig Symbol Importer\\Import symbols from JSON...",
    "Load a JSON manifest of symbol names + signature patterns, scan, resolve, rename, and tag.",
    _cmd_import,
)

PluginCommand.register(
    "Sig Symbol Importer\\Re-import using last JSON",
    "Re-run the importer against the last JSON path.",
    _cmd_reimport,
)

PluginCommand.register(
    "Sig Symbol Importer\\Export current symbols to JSON...",
    "Walk every 'sig_symbol'-tagged address in the current BV and write its current name + address to a JSON file.",
    _cmd_export,
)

PluginCommand.register(
    "Sig Symbol Importer\\Set default JSON path",
    "Pre-select a JSON file for the importer to default to.",
    _cmd_set_default_path,
)
