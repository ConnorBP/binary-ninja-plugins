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
      "comment": "vfunc 15-ish bucket lookup",
      "patterns": [
        {
          "bytes": "8B D3 E8 ? ? ? ? 48 8B F0 48 85 C0 74",
          "platform": "windows",
          "resolve": [{"op": "absolute", "pre": 3, "post": 0}]
        },
        {"bytes": "4C 8D 49 10 81 FA FE 7F 00 00 77"}
      ]
    }
  ]
}
```

### Fields

| field           | type   | required | meaning                                                                    |
| --------------- | ------ | -------- | -------------------------------------------------------------------------- |
| `name`          | str    | yes      | The name to apply to the resolved address                                  |
| `label`         | str    | no       | Original / human-readable identifier (e.g. `Class::Method`); kept in tag   |
| `module`        | str    | no       | DLL basename. Entries whose module doesn't match the loaded BV are skipped |
| `section`       | str    | no       | Section to scan (default `.text`). Falls back to executable segments.      |
| `kind`          | str    | no       | `function` (default), `data`, or `raw` (bookmark + comment only)           |
| `comment`       | str    | no       | Free-text note added to the address comment                                |
| `patterns`      | list   | yes      | Tried in order; first one with a match wins                                |

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

- **`function`** — at the resolved address, create a function if missing, then
  rename it. Use for sig anchors that land on a function start.
- **`data`** — at the resolved address, create a `void*` data var if missing,
  then rename it as a data symbol. Use for sig anchors that resolve to a
  global pointer slot in `.data`.
- **`raw`** — no rename. Just pin a `sig_symbol` tag + comment. Use for sigs
  whose resolution lands on a disp32/disp24/disp16 byte buried in an
  instruction (e.g. a member-offset embedded in `mov reg, [base+disp]`).

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
