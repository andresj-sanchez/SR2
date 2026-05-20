#!/usr/bin/env python3
"""
C guard for SR2 library .c files.

Checks:
1. Every function declared in the corresponding .h is defined in the .c.
2. Defined functions appear in line-info order (ascending source line,
   matching the original binary's address order).
3. Include paths are full-rooted (same rule as stub_guard — MWCC -i include
   does not search subdirectories).

No raw-type rule (C library code legitimately uses int/char/float).

Usage:
    python tools/c_guard.py src/usr/local/sega/px/src/pxvertexbuffer.c
    python tools/c_guard.py src/usr/local/sega/px/src/pxvertexbuffer.c build/c_guard/pxvertexbuffer.ok
"""

import os
import re
import sys
from typing import List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from _common import find_c_sym_line, sym_lineno  # noqa: E402


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Matches identifier( — used in both .h (declarations) and .c (definitions)
_IDENT_BEFORE_PAREN_RE = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')

# C keywords that appear before ( but are not function names
_C_KEYWORDS = frozenset([
    "if", "else", "for", "while", "do", "switch", "case", "return",
    "sizeof", "typeof", "alignof", "offsetof",
    "void", "int", "char", "float", "double", "long", "short",
    "unsigned", "signed", "struct", "union", "enum",
    "typedef", "static", "extern", "const", "volatile", "register",
    "inline", "restrict", "_Bool", "_Complex", "auto",
])

# Short include path check — same rule as stub_guard
_SHORT_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s+"(?!Develop/|types\.h|NNS_|hk|nns_|usr/)([^"]+)"'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_header(c_path: str) -> str:
    """Given a .c path under src/, return the corresponding .h under include/."""
    p = c_path.replace("\\", "/")
    if p.startswith("src/"):
        p = "include/" + p[4:]
    return p[:-2] + ".h"


def _last_func_name(line: str) -> Optional[str]:
    """Return the last function-like identifier before ( on a line, or None."""
    matches = list(_IDENT_BEFORE_PAREN_RE.finditer(line))
    for m in reversed(matches):
        name = m.group(1)
        if name not in _C_KEYWORDS:
            return name
    return None


def _collect_h_declarations(h_path: str) -> List[str]:
    """Return function names declared in a C header (brace-depth-0 lines ending with ';')."""
    decls: List[str] = []
    if not os.path.exists(h_path):
        return decls
    try:
        with open(h_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return decls

    depth = 0
    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("#"):
            depth += line.count("{") - line.count("}")
            continue
        if depth == 0 and "(" in line and stripped.endswith(";"):
            name = _last_func_name(line)
            if name and name not in decls:
                decls.append(name)
        depth += line.count("{") - line.count("}")
    return decls


def _collect_c_definitions(c_path: str) -> List[str]:
    """Return function names defined in a .c file, in file order."""
    result: List[str] = []
    seen: set = set()
    try:
        with open(c_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return result

    brace_depth = 0
    in_sig = False
    paren_balance = 0
    pending_name: Optional[str] = None

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("//") or stripped.startswith("#"):
            brace_depth += line.count("{") - line.count("}")
            continue

        if not in_sig and brace_depth == 0 and "(" in line and not stripped.endswith(";"):
            name = _last_func_name(line)
            if name:
                in_sig = True
                paren_balance = 0
                pending_name = name

        if in_sig:
            paren_balance += line.count("(") - line.count(")")
            if paren_balance <= 0:
                in_sig = False
                if pending_name and pending_name not in seen:
                    result.append(pending_name)
                    seen.add(pending_name)
                pending_name = None

        brace_depth += line.count("{") - line.count("}")

    return result


def _check_include_paths(path: str) -> List[str]:
    """Flag short #include paths (same rule as stub_guard)."""
    errors: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                m = _SHORT_INCLUDE_RE.match(line)
                if m:
                    inc = m.group(1)
                    if "/" in inc:
                        errors.append(
                            f'{path}:{lineno}: short include path: #include "{inc}"\n'
                            f'  Fix: use full path from include/ root, e.g. "usr/local/..."'
                        )
    except OSError:
        pass
    return errors


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def check_file(path: str) -> List[str]:
    errors: List[str] = []

    errors.extend(_check_include_paths(path))

    h_path = _find_header(path)
    declared = _collect_h_declarations(h_path)
    defined = _collect_c_definitions(path)
    defined_set = set(defined)

    # Rule 1: every declared function must be defined
    for func in declared:
        if func not in defined_set:
            errors.append(
                f"{path}: missing definition for '{func}'\n"
                f"  Declared in {h_path} but not defined in this .c file."
            )

    # Rule 2: defined functions must be in line-info order
    anchored: List[Tuple[str, int]] = []
    for func in defined:
        sym_line = find_c_sym_line(func)
        if sym_line is not None:
            lineno = sym_lineno(sym_line)
            if lineno != 2**31:
                anchored.append((func, lineno))

    out_of_order = False
    prev_lineno = -1
    for func, lineno in anchored:
        if lineno < prev_lineno:
            out_of_order = True
            break
        prev_lineno = lineno

    if out_of_order:
        correct = sorted(anchored, key=lambda x: x[1])
        lines = [f"{path}: definitions are out of source-line order. Correct order for anchored functions:"]
        for func, lineno in correct:
            lines.append(f"  line {lineno:6d}  {func}")
        lines.append("  (Functions without line-info can remain in any position relative to each other.)")
        errors.append("\n".join(lines))

    return errors


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <stub.c> [stamp.ok]", file=sys.stderr)
        sys.exit(1)

    c_path = sys.argv[1]
    stamp_path = sys.argv[2] if len(sys.argv) >= 3 else None

    errors = check_file(c_path)
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        sys.exit(1)

    if stamp_path:
        os.makedirs(os.path.dirname(stamp_path), exist_ok=True)
        with open(stamp_path, "w") as f:
            f.write("")

    sys.exit(0)


if __name__ == "__main__":
    main()
