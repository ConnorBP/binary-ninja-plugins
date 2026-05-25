"""
Translates a parsed SchemaModule into named user types in a Binary Ninja BinaryView.

Strategy:
  1) Define each schema enum as a typed enumeration.
  2) Topologically sort schema classes by parent. Leaf classes first only matters
     for size propagation, not type registration — for binja we register parents
     first so children can reference them as a base type.
  3) Compute each class's total size:
        - If any child class has parent == this class, take min(child.first_own_field_offset).
          That is exactly sizeof(this) (no tail padding, by Source 2 convention).
        - Otherwise take max(field.offset) + estimated last-field-size, then OR with
          parent size, alignment-rounded up.
  4) Emit a Structure for each class: parent embedded at offset 0 as `__base`, then
     own fields at their absolute offsets.

Field types are resolved by `TypeResolver` from the cs2-dumper `// type_name` comment.
Unknown / opaque types fall back to a fixed-size byte array sized by the gap to the
next field (or 8 bytes for the last field).
"""

from __future__ import annotations

import re
import traceback
from dataclasses import dataclass
from typing import Optional, Callable

try:
    import binaryninja as bn
    from binaryninja import (
        Type, StructureBuilder, EnumerationBuilder, NamedTypeReferenceBuilder,
        StructureVariant, QualifiedName,
    )
except ImportError:  # parser-only environments / smoke tests
    bn = None  # type: ignore

try:
    from .parser import SchemaModule, SchemaClass, SchemaField, SchemaEnum
except ImportError:
    from parser import SchemaModule, SchemaClass, SchemaField, SchemaEnum  # type: ignore


# ---------- size table for primitives + common Source 2 templates ----------

_PRIM_SIZES: dict[str, int] = {
    # ints / bools / chars
    "bool": 1, "char": 1, "byte": 1, "uint8": 1, "int8": 1,
    "int16": 2, "uint16": 2, "short": 2, "ushort": 2, "wchar_t": 2,
    "int32": 4, "uint32": 4, "int": 4, "uint": 4, "unsignedint": 4, "DWORD": 4,
    "int64": 8, "uint64": 8, "longlong": 8, "unsignedlonglong": 8, "long": 8, "ulong": 8,
    "float": 4, "float32": 4,
    "double": 8, "float64": 8,
    # source2 specific
    "Color": 4,
    "Vector": 12, "Vector2D": 8, "Vector4D": 16, "VectorAligned": 16,
    "QAngle": 12, "Quaternion": 16, "RotationVector": 12,
    "Matrix3x4_t": 48, "Matrix3x4a_t": 48, "matrix3x4_t": 48,
    "matrix3x4a_t": 48, "VMatrix": 64,
    "GameTime_t": 4, "GameTick_t": 4, "WorldGroupId_t": 4,
    "CTransform": 32,
    "CGlobalSymbol": 8, "CUtilStringToken": 4,
    "CUtlString": 8,
    "CUtlStringToken": 4,
    "CUtlSymbol": 4,
    "CUtlSymbolLarge": 8,
    "CUtlBinaryBlock": 24,
    "CBufferString": 16,
    "KeyValues3": 16, "KeyValues": 8,
    "CKV3MemberName": 16,
    "CResourceNameTyped": 8,  # opaque smart-string handle (template-stripped)
}

# Sizes for templated types where the template arg doesn't change layout.
_TEMPLATE_SIZES: dict[str, int] = {
    "CHandle": 4,
    "CEntityHandle": 4,
    "CGameSceneNodeHandle": 4,
    "CStrongHandle": 8,
    "CStrongHandleCopyable": 8,
    "CWeakHandle": 8,
    "CResourceHandle": 8,
    "CResourceArray": 16,
    "CResourceNameTyped": 8,
    "CResourceString": 8,
    "CUtlVector": 24,
    "CCopyableUtlVector": 24,
    "CCopyableUtlVectorFixed": 0,  # filled in dynamically by element_count * elem_size
    "CUtlVectorEmbeddedNetworkVar": 32,
    "C_NetworkUtlVectorBase": 24,
    "CNetworkUtlVectorBase": 24,
    "CNetworkVarChainer": 32,
    "CUtlLeanVector": 16,
    "CUtlLeanVectorFixedGrowable": 0,
    "CBitVec": 0,  # depends on bit count; fall through
    "CFixedBitVecBase": 0,
    "CSmartPtr": 8,
    "CHandleMap": 8,  # opaque
    "CTransformUtl": 32,
    "fltx4": 16,
    "FourQuaternions": 64,
    "FourVectors2D": 32,
    "FourVectors": 48,
    "AABB_t": 24,
    "FourCovMatrices3": 0,
}


@dataclass
class TypeResolution:
    """A resolved field type — either a binja Type object plus its byte size."""
    bn_type: object  # binaryninja.Type
    size: int


# ---------- string parsing for template / array / pointer types ----------

_PTR_RE = re.compile(r"\s*\*\s*$")
_ARRAY_RE = re.compile(r"^(?P<inner>.+?)\s*\[\s*(?P<n>\d+)\s*\]\s*$")
_TEMPLATE_RE = re.compile(r"^(?P<name>[\w:]+)\s*<\s*(?P<args>.+)\s*>\s*$")


def _strip_spaces(s: str) -> str:
    return re.sub(r"\s+", "", s)


def _split_template_args(args: str) -> list[str]:
    """Split a template arg list at top-level commas, ignoring nested `<>`."""
    parts = []
    depth = 0
    cur = []
    for ch in args:
        if ch == "<":
            depth += 1
            cur.append(ch)
        elif ch == ">":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return parts


# ---------- type resolver ----------

class TypeResolver:
    """Resolves cs2-dumper type_name strings into (bn.Type, byte_size).

    Holds references to the already-registered class & enum sizes for size
    propagation through struct fields.
    """

    def __init__(self, bv, class_sizes: dict[str, int], known_enums: dict[str, int]):
        self.bv = bv
        self.arch = bv.arch
        self.ptr_size = bv.arch.address_size
        self.class_sizes = class_sizes  # name -> size (may be 0 if unknown so far)
        self.known_enums = known_enums  # name -> width

    # -- public API --

    def resolve(self, type_name: Optional[str], default_size: int = 8) -> TypeResolution:
        if not type_name:
            return TypeResolution(Type.array(Type.int(1, sign=False), default_size), default_size)
        try:
            return self._resolve(type_name)
        except Exception:
            # Hard fallback: opaque bytes blob
            return TypeResolution(Type.array(Type.int(1, sign=False), default_size), default_size)

    def lookup_size(self, type_name: Optional[str]) -> int:
        if not type_name:
            return 8
        try:
            return self._size_of(type_name)
        except Exception:
            return 8

    # -- internals --

    def _resolve(self, name: str) -> TypeResolution:
        s = name.strip()

        # Pointer suffix (right-associative — pull off one `*` at a time)
        if _PTR_RE.search(s):
            inner = _PTR_RE.sub("", s, count=1).strip()
            inner_res = self._resolve(inner) if inner else None
            inner_t = inner_res.bn_type if inner_res else Type.void()
            return TypeResolution(Type.pointer(self.arch, inner_t), self.ptr_size)

        # Array suffix
        m = _ARRAY_RE.match(s)
        if m:
            inner_res = self._resolve(m.group("inner"))
            n = int(m.group("n"))
            return TypeResolution(Type.array(inner_res.bn_type, n), inner_res.size * n)

        # Templated type
        m = _TEMPLATE_RE.match(s)
        if m:
            base = m.group("name")
            args = _split_template_args(m.group("args"))
            return self._resolve_template(base, args, original=s)

        # Bare name
        return self._resolve_bare(s)

    def _resolve_template(self, base: str, args: list[str], original: str) -> TypeResolution:
        # Special-cased templates with known sizes; we still build a named type
        # reference so binja shows the original templated name.

        size = _TEMPLATE_SIZES.get(base, 0)

        if base in ("CUtlVectorFixed", "CCopyableUtlVectorFixed", "CUtlLeanVectorFixedGrowable"):
            # CUtlVectorFixed<T, N>: N inline elements of T plus 16 bytes of header
            if len(args) >= 2:
                try:
                    n = int(args[1])
                    inner_res = self._resolve(args[0])
                    size = 16 + inner_res.size * n
                except Exception:
                    size = 24
            else:
                size = 24
        elif base in ("CBitVec", "CFixedBitVecBase"):
            if args:
                try:
                    bits = int(args[0])
                    size = (bits + 7) // 8
                    size = (size + 3) & ~3  # 4-byte aligned
                except Exception:
                    size = 4
            else:
                size = 4

        if size == 0:
            # Unknown templated type — opaque pointer-sized placeholder
            size = 8

        # Use a NamedTypeReference so binja's UI prints the original template name
        # instead of `char[8]`.
        sanitized = self._sanitize_name(original)
        ref_type = self._get_or_define_opaque_struct(sanitized, size)
        return TypeResolution(ref_type, size)

    def _resolve_bare(self, name: str) -> TypeResolution:
        # Strip any spaces ("unsigned int" -> "unsignedint" matches our table)
        flat = _strip_spaces(name)

        # Exact primitive
        if flat in _PRIM_SIZES:
            return self._prim(flat)

        # Source 2 sometimes uses suffixed primitive aliases like int32_t etc.
        if flat in ("int32_t", "uint32_t", "int8_t", "uint8_t", "int16_t", "uint16_t", "int64_t", "uint64_t"):
            mapping = {"_t": ""}
            return self._prim(flat.removesuffix("_t"))

        # User-defined (class or enum)
        if name in self.class_sizes or flat in self.class_sizes:
            cls_name = name if name in self.class_sizes else flat
            sz = self.class_sizes.get(cls_name) or 8
            ref_type = self._named_type_ref(cls_name)
            return TypeResolution(ref_type, sz)

        if name in self.known_enums:
            sz = self.known_enums[name]
            ref_type = self._named_type_ref(name)
            return TypeResolution(ref_type, sz)

        # Last resort: define as opaque struct of 8 bytes
        return TypeResolution(self._get_or_define_opaque_struct(self._sanitize_name(name), 8), 8)

    def _prim(self, key: str) -> TypeResolution:
        sz = _PRIM_SIZES[key]
        if key == "bool":
            return TypeResolution(Type.bool(), 1)
        if key in ("float", "float32"):
            return TypeResolution(Type.float(4), 4)
        if key in ("double", "float64"):
            return TypeResolution(Type.float(8), 8)
        # ints
        sign_table = {"int8": True, "int16": True, "int32": True, "int64": True, "int": True,
                      "long": True, "longlong": True,
                      "char": True}
        sign = sign_table.get(key, False)
        # Vector / matrix etc treated as opaque structs
        if key in ("Vector", "Vector2D", "Vector4D", "VectorAligned", "QAngle", "Quaternion",
                   "RotationVector", "Matrix3x4_t", "Matrix3x4a_t", "matrix3x4_t",
                   "matrix3x4a_t", "VMatrix", "CTransform", "Color"):
            ref_type = self._get_or_define_opaque_struct(key, sz)
            return TypeResolution(ref_type, sz)
        return TypeResolution(Type.int(sz, sign=sign), sz)

    def _size_of(self, name: str) -> int:
        return self._resolve(name).size

    # -- type-registry helpers --

    _OPAQUE_DEFINED: set[str] = set()

    def _get_or_define_opaque_struct(self, name: str, size: int):
        """Define `name` as an opaque struct of the given size (once), and
        return a NamedTypeReference Type so it shows up by name in field listings.
        """
        if name not in self._OPAQUE_DEFINED:
            existing = self.bv.get_type_by_name(name)
            if existing is None:
                sb = StructureBuilder.create()
                # opaque body — single byte array padding
                if size > 0:
                    sb.append(Type.array(Type.int(1, sign=False), size), "_opaque")
                sb.width = max(size, 1)
                sb.packed = True
                try:
                    self.bv.define_user_type(name, Type.structure_type(sb))
                except Exception:
                    # name collision — give up, use raw byte array
                    return Type.array(Type.int(1, sign=False), max(size, 1))
            self._OPAQUE_DEFINED.add(name)

        return self._named_type_ref(name)

    def _named_type_ref(self, name: str):
        # A NamedTypeReference lets us reference a struct/enum by name without
        # forcing it to be defined yet.
        try:
            ntr = NamedTypeReferenceBuilder.create(name=name).immutable_copy()
            return Type.named_type_from_type(name, ntr)
        except Exception:
            # Older API path
            try:
                return Type.named_type_from_registered_type(self.bv, name)
            except Exception:
                # Last resort
                return Type.array(Type.int(1, sign=False), 8)

    @staticmethod
    def _sanitize_name(s: str) -> str:
        """Make a template / pointer string into a legal binja type name."""
        out = (
            s.replace(" ", "")
             .replace("<", "__lt__")
             .replace(">", "__gt__")
             .replace(",", "__comma__")
             .replace("*", "__ptr__")
             .replace("&", "__ref__")
             .replace(":", "__")
        )
        return out


# ---------- topological sort + size propagation ----------

def topo_sort_classes(classes: list[SchemaClass]) -> list[SchemaClass]:
    by_name = {c.name: c for c in classes}
    visited: set[str] = set()
    in_progress: set[str] = set()
    order: list[SchemaClass] = []

    def visit(c: SchemaClass):
        if c.name in visited:
            return
        if c.name in in_progress:
            # cycle — break it by treating this as a leaf
            return
        in_progress.add(c.name)
        if c.parent and c.parent in by_name:
            visit(by_name[c.parent])
        in_progress.discard(c.name)
        visited.add(c.name)
        order.append(c)

    for c in classes:
        visit(c)
    return order


def compute_class_sizes(classes: list[SchemaClass], resolver_size_fn) -> dict[str, int]:
    """Compute total instance size for each class.

    Two-phase:
      Phase A: derive a lower bound from own fields:
                 size_lb = max(field.offset for field) + last_field_size
               If no fields, 0.
      Phase B: for each class with at least one child, set
                 size = min(child.first_own_field_offset for child)
               (Source 2 schemas don't typically use tail padding between parent
                end and child begin, so this is exact.)
      Then propagate: every class's size = max(own_lb, parent_size, child_constraint).

    Iterate to a fixed point.
    """
    by_name = {c.name: c for c in classes}
    children: dict[str, list[str]] = {}
    for c in classes:
        if c.parent and c.parent in by_name:
            children.setdefault(c.parent, []).append(c.name)

    sizes: dict[str, int] = {c.name: 0 for c in classes}

    # Initial lower bound from own fields
    for c in classes:
        if not c.fields:
            continue
        last = max(c.fields, key=lambda f: f.offset)
        last_size = resolver_size_fn(last.type_name) if last.type_name else 8
        sizes[c.name] = max(sizes[c.name], last.offset + last_size)

    # Iterate: parent size from min child first-own-offset; child size >= parent size
    changed = True
    iters = 0
    while changed and iters < 16:
        changed = False
        iters += 1
        for c in classes:
            # Parent constraint
            if c.parent and c.parent in by_name:
                parent_size = sizes[c.parent]
                if parent_size > sizes[c.name]:
                    sizes[c.name] = parent_size
                    changed = True
            # Children constraint (parent must accommodate child base layout)
            kids = children.get(c.name, [])
            if kids:
                child_offs = []
                for kid in kids:
                    kc = by_name[kid]
                    if kc.fields:
                        child_offs.append(min(f.offset for f in kc.fields))
                if child_offs:
                    sz = min(child_offs)
                    # If child's first own field is below current size, the child has
                    # bigger parent-size requirement than we do — we trust the field offset.
                    if sz > sizes[c.name]:
                        sizes[c.name] = sz
                        changed = True

    # Pad to 8-byte alignment for safety (matches Source 2 alignment for ptrs)
    for k in list(sizes):
        s = sizes[k]
        if s == 0:
            sizes[k] = 1  # minimal nonzero
        else:
            sizes[k] = (s + 7) & ~7

    return sizes


# ---------- emission ----------

def emit_enums(bv, module: SchemaModule, log) -> dict[str, int]:
    """Define each schema enum as a typed enum. Returns name -> width."""
    widths: dict[str, int] = {}
    for e in module.enums:
        try:
            width = max(1, e.alignment)
            eb = EnumerationBuilder.create()
            seen_values: set[int] = set()
            for nm, val in e.members:
                if val in seen_values:
                    # binja rejects duplicate enum values; suffix the name
                    nm = f"{nm}__dup{val}"
                seen_values.add(val)
                eb.append(nm, val)
            enum_type = Type.enumeration_type(bv.arch, eb, width=width)
            bv.define_user_type(e.name, enum_type)
            widths[e.name] = width
        except Exception as ex:
            log(f"  enum {e.name}: failed ({ex})")
    return widths


def discover_vtable_types(bv) -> dict:
    """Build {class_name: QualifiedName} mapping for every existing user type
    whose qualified name ends in `::<class_name>::VTable` (or just `<class_name>::VTable`).

    When multiple vtable types exist for the same class (e.g. a primary
    `Foo::VTable` plus subobject vtables `Foo::Bar::VTable`), we prefer the
    shortest qualified name — that's typically the primary vtable, the one
    that lives at offset 0 of an instance.
    """
    out: dict[str, object] = {}
    if bv is None:
        return out
    for qname in bv.types.keys():
        try:
            parts = list(qname)
        except Exception:
            continue
        if len(parts) < 2:
            continue
        if str(parts[-1]) != "VTable":
            continue
        cls_name = str(parts[-2])
        if not cls_name:
            continue
        existing = out.get(cls_name)
        if existing is None or len(list(existing)) > len(parts):
            out[cls_name] = qname
    return out


def emit_classes(
    bv,
    module: SchemaModule,
    resolver: TypeResolver,
    sizes: dict[str, int],
    log,
    vtable_map: Optional[dict] = None,
) -> int:
    """If `vtable_map` (class_name -> QualifiedName) is provided, classes that
    have a discovered vtable get a union of `vtable*` and `__base` at offset 0.
    Otherwise every parented class just gets a plain `__base : Parent` member
    (unchanged behavior)."""
    if vtable_map is None:
        vtable_map = {}

    n_ok = 0
    for c in topo_sort_classes(module.classes):
        try:
            sb = StructureBuilder.create()
            try:
                sb.type = StructureVariant.ClassStructureType
            except Exception:
                pass
            sb.packed = True

            total_size = sizes.get(c.name, 0) or 1

            # Resolve vtable for this class, if any
            vtable_qname = vtable_map.get(c.name)
            vtable_ptr_t = None
            if vtable_qname is not None:
                try:
                    vtable_ref = Type.named_type_reference(
                        bn.enums.NamedTypeReferenceClass.StructNamedTypeClass,
                        vtable_qname,
                    )
                    vtable_ptr_t = Type.pointer(bv.arch, vtable_ref)
                except Exception as ex:
                    log(f"  {c.name}: failed to build vtable ptr type ({ex})")
                    vtable_ptr_t = None

            # Layout decisions for offset 0:
            #   has parent + has vtable: union { vtable*, ParentClass }   ← user-requested
            #   has parent  no vtable:   ParentClass                       ← original behavior
            #   no parent + has vtable:  vtable*                          ← root with vtable
            #   no parent  no vtable:    nothing                          ← pure data class
            inserted_offset_zero = False

            if c.parent:
                parent_size = sizes.get(c.parent, 0)
                if parent_size > 0:
                    parent_ref = resolver._named_type_ref(c.parent)

                    if vtable_ptr_t is not None and parent_size >= bv.arch.address_size:
                        # Build an anonymous union: { vtable*, __base }
                        try:
                            union_sb = StructureBuilder.create()
                            union_sb.type = StructureVariant.UnionStructureType
                            union_sb.packed = True
                            union_sb.append(vtable_ptr_t, "vtable")
                            union_sb.append(parent_ref, "__base")
                            union_t = Type.structure_type(union_sb)
                            sb.insert(0, union_t, "vtable_or_base")
                            inserted_offset_zero = True
                        except Exception as ex:
                            log(f"  {c.name}: vtable union failed, falling back to __base only ({ex})")

                    if not inserted_offset_zero:
                        try:
                            sb.insert(0, parent_ref, "__base")
                        except Exception:
                            sb.append(parent_ref, "__base")
                        inserted_offset_zero = True
            elif vtable_ptr_t is not None:
                # Root class with vtable — vtable* directly at offset 0
                try:
                    sb.insert(0, vtable_ptr_t, "vtable")
                    inserted_offset_zero = True
                except Exception as ex:
                    log(f"  {c.name}: failed to insert vtable ptr at 0 ({ex})")

            # Sort own fields by offset
            sorted_fields = sorted(c.fields, key=lambda f: f.offset)

            for idx, fld in enumerate(sorted_fields):
                # Compute hint size (gap to next field) to bound the resolved type's size
                if idx + 1 < len(sorted_fields):
                    gap = sorted_fields[idx + 1].offset - fld.offset
                else:
                    gap = total_size - fld.offset
                gap = max(gap, 1)

                resolved = resolver.resolve(fld.type_name, default_size=gap)
                use_type = resolved.bn_type
                use_size = resolved.size

                # If resolved size > available gap, fall back to opaque bytes
                if use_size > gap:
                    use_type = Type.array(Type.int(1, sign=False), gap)

                try:
                    sb.insert(fld.offset, use_type, fld.name)
                except Exception as ex:
                    # Try once more with a raw bytes blob — most common cause is a name clash
                    # with __base or an oddly-typed inner struct still being defined.
                    try:
                        sb.insert(fld.offset, Type.array(Type.int(1, sign=False), gap), fld.name)
                    except Exception:
                        log(f"  {c.name}.{fld.name}@0x{fld.offset:x}: {ex}")

            sb.width = total_size

            bv.define_user_type(c.name, Type.structure_type(sb))
            n_ok += 1
        except Exception as ex:
            log(f"class {c.name}: failed ({ex})")
            log(traceback.format_exc())
    return n_ok


def apply_module(
    bv,
    module: SchemaModule,
    log,
    size_overrides: Optional[dict] = None,
    use_vtable_union: bool = False,
) -> tuple[int, int]:
    """Apply a parsed module to the BinaryView.

    `size_overrides` is an optional {class_name: size_in_bytes} map of authoritative
    sizes (e.g. read from each binding's `m_nSizeOf` field during static extraction).
    Where present these win over derived sizes.

    `use_vtable_union`: when True, every class that has an existing user-type
    whose qualified-name ends in `::<class>::VTable` gets a union {vtable*, __base}
    at offset 0 instead of a plain `__base`. Off by default.

    Returns (n_classes_defined, n_enums_defined).
    """
    enum_widths = emit_enums(bv, module, log)

    # Initial pass: estimate class sizes using a resolver that has no class sizes yet
    # (we'll use it just for primitive size lookups — class sizes default to 8).
    class_sizes: dict[str, int] = {c.name: 0 for c in module.classes}
    bootstrap_resolver = TypeResolver(bv, class_sizes, enum_widths)

    sizes = compute_class_sizes(module.classes, bootstrap_resolver.lookup_size)
    class_sizes.update(sizes)

    # Authoritative override pass — these come from the static binding's m_nSizeOf
    # and are exact (no derivation). They also propagate via children: if `Foo` has
    # an authoritative size, every child's size is at least Foo's size.
    if size_overrides:
        for name, sz in size_overrides.items():
            if sz > 0 and sz > class_sizes.get(name, 0):
                class_sizes[name] = sz
        # Propagate to children
        by_name = {c.name: c for c in module.classes}
        children: dict[str, list[str]] = {}
        for c in module.classes:
            if c.parent and c.parent in by_name:
                children.setdefault(c.parent, []).append(c.name)
        # Topo walk: parents first, push parent_size up to children when needed
        ordered = topo_sort_classes(module.classes)
        for c in ordered:
            if c.parent and c.parent in class_sizes:
                p_sz = class_sizes[c.parent]
                if p_sz > class_sizes.get(c.name, 0):
                    class_sizes[c.name] = p_sz

    # Real resolver, now aware of class sizes
    resolver = TypeResolver(bv, class_sizes, enum_widths)

    vtable_map = {}
    if use_vtable_union:
        try:
            vtable_map = discover_vtable_types(bv)
            log(f"[cs2_schema] discovered {len(vtable_map)} vtable types for union-embedding")
        except Exception as ex:
            log(f"[cs2_schema] vtable discovery failed: {ex}")
            vtable_map = {}

    n_classes = emit_classes(bv, module, resolver, class_sizes, log, vtable_map=vtable_map)
    return n_classes, len(enum_widths)
