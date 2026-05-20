#!/usr/bin/env python3
"""
Source guard for SR2 scaffolded headers.

Enforces the following rules on .hpp files under include/Develop/Projects/SR2/pgm/src/:

1. Raw C++ scalar types are forbidden — use SR2 typedefs (u8/s8/c8, u16/s16, u32/s32, etc.).
2. 'namespace clsFoo' and 'namespace stcFoo' are invalid — cls/stc are classes/structs.
3. Redefinition of types already declared in canonical shared headers (NNS_VECTOR, etc.).
4. Keyword/prefix mismatch: 'cls' names must use 'class', 'stc' names must use 'struct'.
5. No elaborated class/struct keyword inside member declarations (e.g. 'class Foo m_sFoo;'
   should be 'Foo m_sFoo;').
6. Non-empty headers must begin with an include guard (#pragma once or #ifndef/#define).

Exit 0 (pass) + write stamp file if no violations.
Exit 1 (fail) with actionable messages if violations found.

Usage:
    python tools/source_guard.py include/.../Foo.hpp
    python tools/source_guard.py include/.../Foo.hpp build/source_guard/Foo.ok

Only one header may be checked per invocation. The optional second argument is a
stamp file path for Ninja, not another header.
"""

import re
import sys
import os
import glob as _glob
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Rule 1 — Forbidden raw scalar types in struct/class member declarations
# ---------------------------------------------------------------------------
# Only checked on lines that look like member declarations (contain ';' and
# are inside a struct/class body). We avoid flagging #include or comments.
_RAW_TYPES: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bunsigned\s+int\b"),       "unsigned int",       "u32"),
    (re.compile(r"\bsigned\s+int\b"),         "signed int",         "s32"),
    (re.compile(r"\bunsigned\s+short\b"),     "unsigned short",     "u16"),
    (re.compile(r"\bsigned\s+short\b"),       "signed short",       "s16"),
    (re.compile(r"\bunsigned\s+char\b"),      "unsigned char",      "u8"),
    (re.compile(r"\bsigned\s+char\b"),        "signed char",        "s8"),
    (re.compile(r"\bunsigned\s+long\s+long\b"), "unsigned long long", "u64"),
    (re.compile(r"\bsigned\s+long\s+long\b"),   "signed long long",   "s64"),
    # Bare primitives — must appear AFTER the compound forms above so the more
    # specific "unsigned int" / "signed int" rules fire first on those lines.
    (re.compile(r"(?<!unsigned )(?<!signed )\bint\b"),   "int",    "s32"),
    (re.compile(r"\bfloat\b"),                           "float",  "f32"),
    (re.compile(r"\bdouble\b"),                          "double", "f64"),
    # char/short/long bare forms (compound forms already handled above)
    (re.compile(r"(?<!unsigned )(?<!signed )\bchar\b"),  "char",   "c8"),
    (re.compile(r"(?<!unsigned )(?<!signed )\bshort\b"), "short",  "s16"),
    # bare long (not long long — negative lookahead excludes " long" following it)
    (re.compile(r"(?<!unsigned )(?<!signed )\blong\b(?!\s+long)"), "long", "s32"),
]

# ---------------------------------------------------------------------------
# Rule 2 — Forbidden 'namespace cls*' and 'namespace stc*' declarations
# ---------------------------------------------------------------------------
_NAMESPACE_PREFIX_RE = re.compile(r"\bnamespace\s+((?:cls|stc)\w+)")

# ---------------------------------------------------------------------------
# Rule 3 — Types that already have a canonical header definition
# ---------------------------------------------------------------------------
_KNOWN_SHARED_TYPES: List[Tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"\bNNS_VECTOR\b"),
        "NNS_VECTOR",
        "Object/Player/Data/CharaData.hpp",
    ),
    (
        re.compile(r"\bNNS_VECTORFAST\b"),
        "NNS_VECTORFAST",
        "Object/Player/Data/CharaData.hpp",
    ),
    (
        re.compile(r"\bNNS_MATRIX\b"),
        "NNS_MATRIX",
        "Object/Player/Data/CharaData.hpp",
    ),
    (
        re.compile(r"\bNNS_MATFAST\b"),
        "NNS_MATFAST",
        "Object/Player/Data/CharaData.hpp",
    ),
]

# Matches lines that define (not just use) a type — 'struct/class TypeName {'
_DEFINITION_RE = re.compile(r"^(?:class|struct)\s+(\w+)\s*(?:\{|:)")

# ---------------------------------------------------------------------------
# Rule 4 — keyword/prefix mismatch: cls* → class, stc* → struct
# ---------------------------------------------------------------------------
# Catches definitions AND forward-declarations (ends with {, :, or ;).
_KEYWORD_PREFIX_RE = re.compile(r"^(class|struct)\s+(\w+)\s*(?:\{|:|;)")

# ---------------------------------------------------------------------------
# Rule 5 — No elaborated class/struct keyword in member declarations
# ---------------------------------------------------------------------------
# Matches 'class Foo m_bar', 'class Foo* m_bar', 'class Foo& m_bar' inside
# a class body.  Does NOT match forward-decls ('class Foo;') because there is
# no second identifier after the type name.
_ELABORATE_MEMBER_RE = re.compile(r"\b(class|struct)\s+(\w+)\s*[*&]?\s*\w")


# ---------------------------------------------------------------------------
# Rule 7 — virtual keyword in a class that has no vtable symbol
# ---------------------------------------------------------------------------

def _find_symbol_addrs(header_path: str) -> Optional[str]:
    """Walk up from header_path to find config/*/symbol_addrs.txt."""
    dir_ = os.path.dirname(os.path.abspath(header_path))
    for _ in range(12):
        matches = _glob.glob(os.path.join(dir_, "config", "*", "symbol_addrs.txt"))
        if matches:
            return matches[0]
        parent = os.path.dirname(dir_)
        if parent == dir_:
            break
        dir_ = parent
    return None


def _load_vtable_and_ctor_syms(symbol_addrs: str) -> Tuple[set, set]:
    """Return (vtable_syms, ctor_syms) from symbol_addrs.txt.

    vtable_syms: set of __vt__N{ClassName} names (exact, no templates).
    ctor_syms:   set of class names that have at least one __ct__ symbol,
                 indicating the class is concrete (not abstract/fictional).
    """
    vtable_syms: set = set()
    ctor_syms: set = set()
    _ctor_re = re.compile(r"__ct__(\d+)(\w+)")
    try:
        with open(symbol_addrs, encoding="utf-8", errors="replace") as f:
            for line in f:
                sym_part = line.split("=")[0].strip()
                m_vt = re.match(r"__vt__\d+\w+$", sym_part)
                if m_vt:
                    vtable_syms.add(sym_part)
                m_ct = _ctor_re.match(sym_part)
                if m_ct:
                    expected_len = int(m_ct.group(1))
                    cls_candidate = m_ct.group(2)[:expected_len]
                    ctor_syms.add(cls_candidate)
    except OSError:
        pass
    return vtable_syms, ctor_syms


def _collect_virtual_classes(lines: List[str]) -> Dict[str, int]:
    """Return {class_name: first_virtual_lineno} for every non-template class body
    that contains a 'virtual' declaration."""
    result: Dict[str, int] = {}
    # Stack of (class_name, brace_depth_at_open_brace)
    class_stack: List[Tuple[str, int]] = []
    template_classes: set = set()
    brace_depth = 0
    prev_stripped = ""  # last non-blank, non-comment line seen

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\n")
        stripped = line.strip()

        # Maintain brace depth, skipping comment-only lines
        if stripped.startswith("//") or stripped.startswith("/*"):
            brace_depth += line.count("{") - line.count("}")
            continue

        # Pop classes whose scope ended before this line
        while class_stack and brace_depth <= class_stack[-1][1]:
            class_stack.pop()

        # Detect class/struct definition with opening brace on same line
        m_cls = re.match(r"^\s*(?:class|struct)\s+(\w+)\b", line)
        if m_cls and "{" in line:
            cls_name = m_cls.group(1)
            # If the immediately preceding non-blank significant line started with
            # 'template', this class is a template — skip vtable check for it.
            if prev_stripped.startswith("template"):
                template_classes.add(cls_name)
            depth_before = brace_depth
            brace_depth += line.count("{") - line.count("}")
            class_stack.append((cls_name, depth_before))
            if stripped:
                prev_stripped = stripped
            continue

        brace_depth += line.count("{") - line.count("}")

        # Detect 'virtual' keyword in a non-template class body
        if class_stack and "virtual" in stripped and not stripped.startswith("#"):
            cls = class_stack[-1][0]
            if cls not in result and cls not in template_classes:
                result[cls] = lineno

        if stripped:
            prev_stripped = stripped

    return result


def _is_member_decl_line(line: str) -> bool:
    """Heuristic: a line is a member declaration if it has ';' and isn't a comment/#include."""
    stripped = line.strip()
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("#"):
        return False
    return ";" in stripped


def check_file(path: str) -> List[str]:
    """Return list of error message strings for the given header file."""
    errors: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return [f"{path}: cannot read file: {e}"]

    inside_struct = False  # rough tracker for struct/class body scope
    brace_depth = 0
    struct_entry_depth = 0

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\n")
        stripped = line.strip()

        # Track struct/class body depth (rough — sufficient for member checks)
        if re.match(r"^\s*(?:class|struct)\s+\w+", line):
            if "{" in line:
                inside_struct = True
                struct_entry_depth = brace_depth + line.count("{") - line.count("}")
        brace_depth += line.count("{") - line.count("}")
        if inside_struct and brace_depth < struct_entry_depth:
            inside_struct = False

        # Skip comments and preprocessor lines for most checks
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("#"):
            continue

        # Rule 1: forbidden raw types in member declarations
        if inside_struct and _is_member_decl_line(line):
            for pat, raw_name, sr2_name in _RAW_TYPES:
                if pat.search(line):
                    errors.append(
                        f"{path}:{lineno}: "
                        f"Raw type '{raw_name}' is not allowed. Use SR2 typedef '{sr2_name}' instead.\n"
                        f"  Add '#include \"types.h\"' if it is missing."
                    )

        # Rule 2: namespace cls*/stc* declarations
        m = _NAMESPACE_PREFIX_RE.search(line)
        if m:
            ns_name = m.group(1)
            ns_lower = ns_name.lower()
            if ns_lower.startswith("cls"):
                errors.append(
                    f"{path}:{lineno}: "
                    f"'namespace {ns_name}' is invalid. 'cls' prefix means this is a class.\n"
                    f"  Forward-declare as: class {ns_name};"
                )
            elif ns_lower.startswith("stc"):
                errors.append(
                    f"{path}:{lineno}: "
                    f"'namespace {ns_name}' is invalid. 'stc' prefix means this is a struct.\n"
                    f"  Forward-declare as: struct {ns_name};"
                )

        # Rule 3: redefinition of known shared types (only flag the definition line)
        # Skip if this file IS the canonical header (it is allowed to define its own types).
        def_m = _DEFINITION_RE.match(stripped)
        if def_m:
            type_name = def_m.group(1)
            for _pat, known_name, canonical_header in _KNOWN_SHARED_TYPES:
                if type_name == known_name:
                    if path.replace("\\", "/").endswith(canonical_header):
                        continue
                    errors.append(
                        f"{path}:{lineno}: "
                        f"'{known_name}' is already defined in {canonical_header}.\n"
                        f"  Remove this definition and include the canonical header instead."
                    )

        # Rule 4: keyword/prefix mismatch
        kp_m = _KEYWORD_PREFIX_RE.match(stripped)
        if kp_m:
            keyword, type_name = kp_m.group(1), kp_m.group(2)
            if keyword == "struct" and type_name.startswith("cls"):
                errors.append(
                    f"{path}:{lineno}: "
                    f"'struct {type_name}' — 'cls' prefix requires 'class' keyword.\n"
                    f"  Fix: change to 'class {type_name}'."
                )
            elif keyword == "class" and type_name.startswith("stc"):
                errors.append(
                    f"{path}:{lineno}: "
                    f"'class {type_name}' — 'stc' prefix requires 'struct' keyword.\n"
                    f"  Fix: change to 'struct {type_name}'."
                )

        # Rule 5: redundant elaborated class/struct keyword in member declarations
        # Skip lines with '(' (method declarations) or '{' (nested class openings).
        if inside_struct and _is_member_decl_line(line) and "{" not in line and "(" not in line:
            code_part = line.split("//")[0]
            em = _ELABORATE_MEMBER_RE.search(code_part)
            if em:
                kw, type_name = em.group(1), em.group(2)
                errors.append(
                    f"{path}:{lineno}: "
                    f"Redundant '{kw}' keyword before '{type_name}' in member declaration.\n"
                    f"  Fix: remove the '{kw}' keyword — write '{type_name}' directly."
                )

    # Rule 7: virtual keyword in a class that has no vtable symbol.
    # Only enforced on scaffold-output headers (under pgm/src/).
    # lib/OO base classes and templates legitimately use virtual without a
    # bare __vt__ symbol (e.g. clsSingleton is a template; clsOOVector is
    # abstract) — applying the check there produces false positives.
    _norm_path = path.replace("\\", "/")
    symbol_addrs = _find_symbol_addrs(path) if "/pgm/src/" in _norm_path else None
    if symbol_addrs:
        vtable_syms, ctor_syms = _load_vtable_and_ctor_syms(symbol_addrs)
        for cls_name, first_lineno in _collect_virtual_classes(lines).items():
            expected = f"__vt__{len(cls_name)}{cls_name}"
            # Only flag concrete classes (those with a constructor symbol).
            # Abstract/placeholder base classes have no __ct__ entry and are
            # legitimately virtual without a vtable symbol of their own.
            if expected not in vtable_syms and cls_name in ctor_syms:
                errors.append(
                    f"{path}:{first_lineno}: "
                    f"Class '{cls_name}' declares 'virtual' function(s) but has no vtable "
                    f"symbol ('{expected}' not in symbol_addrs.txt).\n"
                    f"  This class has no virtual functions — remove all 'virtual' keywords."
                )

    # Rule 6: include guard — file-level check
    # Skip empty files (placeholders); only enforce on files with actual content.
    has_content = any(
        ln.strip() and not ln.strip().startswith("//") and not ln.strip().startswith("/*")
        for ln in lines
    )
    if has_content:
        header_text = "".join(lines[:20])
        if "#ifndef" not in header_text:
            errors.append(
                f"{path}:1: "
                "Missing include guard. Add a '#ifndef'/'#define'/'#endif' guard.\n"
                "  Standard form:\n"
                "    #ifndef PATH_CLASSNAME_HPP\n"
                "    #define PATH_CLASSNAME_HPP\n"
                "    ... (file content) ...\n"
                "    #endif // PATH_CLASSNAME_HPP"
            )

    return errors


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <header.hpp> [stamp.ok]", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) > 3:
        print(
            f"Usage: {sys.argv[0]} <header.hpp> [stamp.ok]\n"
            "source_guard.py checks exactly one header per invocation; "
            "run it once per file.",
            file=sys.stderr,
        )
        sys.exit(2)

    header_path = sys.argv[1]
    stamp_path = sys.argv[2] if len(sys.argv) >= 3 else None

    if stamp_path and os.path.splitext(stamp_path)[1].lower() in {".h", ".hh", ".hpp", ".hxx"}:
        print(
            f"Refusing to treat header as stamp file: {stamp_path}\n"
            "source_guard.py checks exactly one header per invocation; "
            "run it once per file.",
            file=sys.stderr,
        )
        sys.exit(2)

    errors = check_file(header_path)
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        sys.exit(1)

    # Write stamp file so ninja knows the check passed
    if stamp_path:
        os.makedirs(os.path.dirname(stamp_path), exist_ok=True)
        with open(stamp_path, "w") as f:
            f.write("")

    sys.exit(0)


if __name__ == "__main__":
    main()
