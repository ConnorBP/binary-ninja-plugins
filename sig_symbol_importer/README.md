# Sig Symbol Importer

Import symbol names + bookmarks into Binary Ninja from a JSON manifest of
signature patterns. Designed to round-trip the signature files used by
the fvc cs2-sdk project: each entry has IDA-style hex bytes (with
optional backups) plus a resolution chain (`absolute` / `offset` /
`dereference`) that mirrors fvc's `CPointer`.

## JSON schema

```json
{
  "version": 1,
  "source": "fvc/cs2-sdk signatures.cpp",
  "symbols": [
    {
      "name": "GetBaseEntity",
      "label": "CGameEntitySystem::GetBaseEntity",
      "module": "client.dll",
      "section": ".text",
      "kind": "function",
      "prototype": "void* GetBaseEntity(void* svc, uint32_t handle)",
      "comment": "vfunc 15-ish bucket lookup",
      "patterns": [
        {
          "bytes": "8B D3 E8 ? ? ? ? 48 8B F0 48 85 C0 74",
          "platform": "windows",
          "resolve": [{"op": "absolute", "pre": 3, "post": 0}]
        },
        {"bytes": "4C 8D 49 10 81 FA FE 7F 00 00 77"}
      ]
    },
    {
      "name": "ArrayOfCmds",
      "module": "client.dll",
      "kind": "data",
      "data_type": "void**",
      "patterns": [
        {
          "bytes": "4C 8B 35 ? ? ? ? 4C 63 F8",
          "resolve": [{"op": "absolute", "pre": 3, "post": 0}]
        }
      ]
    }
  ]
}
```

### Fields

| field           | type   | required | meaning                                                                                                  |
| --------------- | ------ | -------- | -------------------------------------------------------------------------------------------------------- |
| `name`          | str    | yes      | The name to apply to the resolved address                                                                |
| `label`         | str    | no       | Original / human-readable identifier (e.g. `Class::Method`); kept in tag                                 |
| `module`        | str    | no       | DLL basename. Entries whose module doesn't match the loaded BV are skipped                               |
| `section`       | str    | no       | Section to scan (default `.text`). Falls back to executable segments.                                    |
| `kind`          | str    | no       | `function` (default), `data`, or `raw` (bookmark + comment only)                                         |
| `prototype`     | str    | no       | C function prototype, e.g. `"int foo(void* this, int x)"`. Applied via `Function.set_user_type` when kind=function. Parse errors are logged but non-fatal. |
| `data_type`     | str    | no       | C type expression for the data var, e.g. `"CUserCmd**"` or `"CEntityHandle"`. Applied via `BinaryView.define_user_data_var` when kind=data. Defaults to `void*` when omitted or unparseable. |
| `comment`       | str    | no       | Free-text note added to the address comment                                                              |
| `patterns`      | list   | yes      | Tried in order; first one with a match wins                                                              |

### Pattern fields

| field      | type   | required | meaning                                                                       |
| ---------- | ------ | -------- | ----------------------------------------------------------------------------- |
| `bytes`    | str    | yes      | IDA-style hex string. `?` / `??` = wildcard byte. Whitespace-separated tokens |
| `platform` | str    | no       | Informational; currently ignored at import time                               |
| `resolve`  | list   | no       | Op chain applied left-to-right to the match address                           |

### Resolve ops (mirror fvc `CPointer`)

| op            | params              | semantics                                                         |
| ------------- | ------------------- | ----------------------------------------------------------------- |
| `offset`      | `{value: N}`        | `ptr += N`                                                        |
| `absolute`    | `{pre: N, post: M}` | `ptr += N; disp = *(int32*)ptr; ptr = ptr + 4 + disp; ptr += M`   |
| `dereference` | `{count: N}`        | for _ in range(N): `ptr = *(uint64*)ptr`                          |

### Kinds

- **`function`** — at the resolved address, create a function if missing,
  then rename it. Use for sig anchors that land on a function start. If
  `prototype` is set, the function's type is overwritten via
  `Function.set_user_type` (the symbol name from the JSON is preserved —
  the parsed prototype's name, if any, is discarded). If the address was
  wrongly defined as data by a previous import (evidenced by a `sig_symbol`
  tag at the address), the data var is undefined first so the function
  creation lands cleanly.
- **`data`** — at the resolved address, create a typed data var, then
  rename it as a data symbol. Use for sig anchors that resolve to a
  global pointer slot in `.data` (e.g. `mov reg, [rip+disp32]` resolves
  to such a slot, not to a function). Type defaults to `void*`; set
  `data_type` to give it a more specific type. If a previous import
  wrongly defined a function here (evidenced by a `sig_symbol` tag), the
  stale function is removed first.
- **`raw`** — no rename. Just pin a `sig_symbol` tag + comment. Use for
  sigs whose resolution lands on a disp32/disp24/disp16 byte buried in
  an instruction (e.g. a member-offset embedded in `mov reg, [base+disp]`).

### How the generator classifies entries

The companion generator (`generate_symbols_json.py`) auto-detects `kind`
from the resolve chain shape:

| chain shape                                        | detected kind                          |
| -------------------------------------------------- | -------------------------------------- |
| no resolve (direct match)                          | `function` (anchor IS the prologue)    |
| pure `offset(N)` chain                             | `raw` (disp embedded in instruction)   |
| chain ending in `dereference`                      | `data`                                 |
| `absolute(pre, post)` where byte at `pre-1` is `E8`/`E9` | `function` (call/jmp rel32 target) |
| `absolute(pre, post)` otherwise                    | `data` (mov/lea reads a data slot)     |

The byte-before-disp32 rule is the same rule the compiler honors when
emitting the instruction — `E8`/`E9` opcodes followed by a disp32 are
the only x86_64 RIP-relative encodings where the target is itself code.
Everything else (`48 8B 05/0D/15/…`, `48 8D 05/…`, `FF 15`, etc.) is
reading or referencing a data slot. The heuristic was verified 12/12
against a hand-curated truth set.

If the generator gets a classification wrong, edit the JSON manually
and set the `kind` (and optionally `prototype` / `data_type`) yourself
— the importer never re-derives the kind from the resolve chain.

## Use

1. **Plugins -> Sig Symbol Importer -> Import symbols from JSON...**
   Pick a JSON manifest. Entries whose `module` matches the loaded BV are
   applied; others are skipped.

2. **Re-import using last JSON** — runs again with the path remembered
   from the previous import.

3. **Export current symbols to JSON...** — writes the current name +
   address of every `sig_symbol`-tagged location. Patterns/resolve are
   NOT written (they live in the source-of-truth JSON).

4. **Set default JSON path** — pre-fills the open dialog and lets
   `Re-import` work without prompting.

## Generating a manifest from fvc/cs2-sdk

A companion script lives in the workspace at
`fvc/cs2-sdk/tools/generate_symbols_json.py`. It parses
`signatures.cpp` and emits a JSON manifest in this schema.

## Notes

- Pattern scanning uses the first match. If a pattern hits multiple
  times in the section, the log records the count so you can tighten the
  pattern in the source manifest.
- All renames + tags are wrapped in a single Binja undo group, so a bad
  import can be rolled back in one click.
- Existing user-named symbols (non-auto) are preserved — the importer
  logs a "kept user name" note and tags the address anyway.
