# CS2 Schema Loader (Binary Ninja plugin)

Apply CS2 schema-system class layouts as named user types in Binary Ninja, so when you reverse `client.dll` / `server.dll` / etc. the structs show up under their real Source 2 names (`CCSPlayerController`, `C_CSPlayerPawn`, `CBaseAnimGraph`, ...) with every field at its correct offset.

Two ways to populate the schema:

1. **From cs2-dumper output** — reads `output/<module>_dll.hpp` (preferred) or `.json`. The `.hpp` carries the `// type_name` comment for every field, so primitives, pointers, `CHandle<T>`, `CUtlVector<T>`, `Vector`, `QAngle`, etc. resolve to real Binary Ninja types. Class sizes are derived from per-class field offsets plus child-class first-own-field offsets (Source 2 has no tail padding).
2. **Straight from the loaded binary's static data** — no dumper, no live process. Walks every `CSchemaRegistration::VFunc0` symbol, picks out the call to `vtable[0x110]` (the binding-registration phase), reads the bindings array right out of `.data`. Each binding has the exact `m_nSizeOf` baked in, so class sizes are ground truth (not derived). Field type strings aren't statically present (`m_pType` is runtime-resolved), so fields fall back to gap-sized byte arrays — but you keep all the names, offsets, and sizes.

## Setup

1. Generate the dump with cs2-dumper (you already have it in this workspace at `E:\DEVELOPER\PROJECTS\sus\cs2-dumper\output`).
2. Open `client.dll` (or `server.dll`, `engine2.dll`, etc.) in Binary Ninja.
3. Run **Plugins → CS2 Schema → Apply Schemas From cs2-dumper (auto-detect module)**.
4. The first run will prompt for the cs2-dumper `output/` directory if it can't auto-locate it; the path is saved in Binary Ninja's settings under `cs2_schema.dumperOutputDir`.

## Commands

- **Apply Schemas From cs2-dumper (auto-detect module)** — picks the dump file matching the loaded binary's filename (`client.dll → client_dll.hpp`).
- **Apply Schemas From cs2-dumper (choose module)** — manual module picker.
- **Set cs2-dumper output directory** — configure / re-configure the path.
- **Extract Schema From Current Binary (static, no dumper needed)** — pulls the schema graph straight out of the loaded module's static data via the `CSchemaRegistration::VFunc0` discovery pipeline. Use this when you don't want to (or can't) run cs2-dumper, or when you're on a build the dumper hasn't been re-run for.

## Settings

- `cs2_schema.dumperOutputDir` — path to cs2-dumper's `output/` folder.
- `cs2_schema.useVtableUnion` (default **on**) — Binary Ninja's RTTI processor auto-creates a `*::VTable` struct type for every class with virtuals when the binary is analyzed. When this setting is on, every schema class whose name matches one of those types (qualified-name ending in `::<ClassName>::VTable`) gets its offset-0 base emitted as

  ```
  union {
      <ClassName>::VTable* vtable;
      <ParentClass>        __base;
  };
  ```

  …so both `obj.vtable` and `obj.__base.someField` work. Disable this setting if Binary Ninja's poor display of non-first union members becomes annoying — you'll get plain `__base` only.

## What it produces

- One Binary Ninja user type per schema class. Inheritance is preserved as a `__base : ParentClass` member at offset 0.
- One typed enumeration per schema enum, with the underlying width from the schema alignment.
- Fields named exactly as in the schema, placed at exact byte offsets, with binja types for every primitive / pointer / common Source 2 template, and opaque named structs for everything else.

After applying, set a function parameter or data variable to one of these new types via Binary Ninja's normal type-change workflow (`y` on a variable / right-click → Change Type), and the field layout drops in.

## Notes

- This is purely static — it doesn't attach to a running game process. The dump file must match the binary you're reversing (cs2-dumper writes a `info.json` with the build number; check it).
- If you regenerate the dump after a Source 2 update, just re-run the plugin command and it will re-define everything.
- The plugin detects the module from the loaded BinaryView's filename. If your file is named oddly, use the "choose module" command.
- The class-size derivation matches the binja-verified `m_nSizeOf = 0x950` for `CCSPlayerController` exactly. Sizes for classes with no children and no easily-typed last field default to `last_field_offset + 8`, rounded up to 8-byte alignment.

## File layout

```
cs2_schema_loader/
  __init__.py        # plugin entry — registers PluginCommand + setting
  parser.py          # cs2-dumper .hpp / .json parser (no Binary Ninja deps)
  builder.py         # type resolver + struct builder (uses binja API)
  static_extractor.py # walks CSchemaRegistration::VFunc0 in the loaded binary
  plugin.json        # Binary Ninja plugin manifest
```

## How the static extractor finds bindings

CS2 modules register their schema classes during DLL load in 4 phases per
batch (one batch per template-instantiated `CSchemaRegistration_<module>`).
The phases are dispatched by `CSchemaRegistration::VFunc0(this, schemaSystem, phase, ...)`,
and phase 2 is the only one we care about for class layout — it calls

    schemaSystem->vtable[0x110]("module.dll", "module", &scope_out, count, &bindings_array, …)

with `count` = number of classes in this batch and `bindings_array` = an
array of `count` pointers to static `SchemaClassBinding` structs. The
extractor walks every `CSchemaRegistration::VFunc0` (binja exposes them
all under that exact symbol name — one per .obj that registered classes),
finds the `vtable[0x110]` call in HLIL, and reads the bindings array out
of static memory.

Per-binding offsets verified against client.dll build 14160:

| Offset | Field |
|---|---|
| +0x08 | `const char* m_Name` |
| +0x20 | `uint32_t m_nSizeOf` |
| +0x24 | `int16_t m_nFieldsCount` |
| +0x26 | `int16_t m_nStaticMetadataCount` |
| +0x30 | `SchemaClassFieldData_t* m_Fields` |
| +0x38 | `SchemaBaseClassInfo_t* m_BaseClasses` |
| +0x40 | `SchemaStaticMetadata_t* m_pStaticMetadata` |

Each field record is 0x20 bytes: name at +0x00, single-inheritance offset
at +0x10. Each base-class record is 16 bytes: offset-in-derived at +0x00,
parent-binding pointer at +0x08.
