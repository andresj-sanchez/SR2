#!/usr/bin/env python3
"""
Stub guard for SR2 scaffolded .cpp files.

Checks that every non-weak function listed in symbol_addrs.txt for each class
defined in the .cpp is present as a definition stub.  Uses the same
classification logic as decomp-scaffold.py (via _common.get_non_weak_funcs) so
the two tools always agree.

Inline method definitions in the corresponding .hpp are also recognised as
valid definitions — a method with a body in the header does NOT need a
separate out-of-line stub in the .cpp.

Also enforces namespace hygiene rules in .cpp TUs:
  A. 'using namespace nsp*;' is forbidden — use fully-qualified names.
  B. Enum definitions inside 'namespace nsp*' blocks are forbidden — enum
     values belong in the header stub, not the .cpp.

Also enforces SR2 typedef conventions in .cpp function signatures:
  C. Raw C++ scalar types (int, char, float, etc.) are forbidden in function
     return types and parameter lists — use u8/s8/c8/u16/s16/u32/s32/f32/f64.

Exit 0 (pass) + write stamp file if no missing definitions.
Exit 1 (fail) with actionable messages if any definitions are absent.

Usage:
    python tools/stub_guard.py src/.../Foo.cpp
    python tools/stub_guard.py src/.../Foo.cpp build/stub_guard/Foo.ok
"""

import os
import re
import sys
import bisect
from typing import Dict, List, Optional, Set, Tuple

# Ensure tools/ is on the path so _common imports work
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from _common import get_dwarf_params, get_non_weak_funcs, sym_lineno  # noqa: E402

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
LINE_INFO_PATH = os.path.join(ROOT_DIR, "symbols", "sr2_line_info.nothpp")
PROJECT_PREFIX = "Develop/Projects/SR2/pgm/"
_SOURCE_LINE_CACHE: Optional[List[Tuple[int, str]]] = None


# Matches any out-of-line definition in the .cpp: ClassName::method( or ClassName::~ClassName(
_DEF_RE = re.compile(r"\b(\w+)::(~?\w+)\s*\(")

# Matches a class/struct that opens its body on the same line (not a forward decl)
_CLASS_OPEN_RE = re.compile(r"\b(?:class|struct)\s+(\w+)\b[^;{]*\{")

# Tokens that look like method names but aren't
_NOT_METHODS = frozenset([
    "if", "else", "for", "while", "do", "switch", "try", "catch",
    "return", "new", "delete", "sizeof", "nullptr", "true", "false",
    "typedef", "template", "explicit", "namespace", "enum", "union",
    "class", "struct", "virtual", "static", "inline", "const", "operator",
    "throw", "noexcept", "override",
])


def _get_clean_hpp_tokens(hpp_path: str, delimiters: str) -> List[str]:
    """Reads a header, removes comments/strings/macros, and splits by structural delimiters."""
    try:
        with open(hpp_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return []
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"^\s*#.*", "", text, flags=re.MULTILINE)
    return re.split(f"([{delimiters}])", text)


def _collect_defined(path: str) -> Dict[str, Set[str]]:
    """Return {ClassName: {method_name, ...}} for all out-of-line definitions in the .cpp.

    Only collects at file scope (brace depth 0) to avoid misidentifying qualified
    call sites inside function bodies (e.g. BaseClass::method()) as definitions.
    """
    defined: Dict[str, Set[str]] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            depth = 0
            for line in f:
                if depth == 0:
                    for cls, meth in _DEF_RE.findall(line):
                        defined.setdefault(cls, set()).add(meth)
                depth += line.count('{') - line.count('}')
    except OSError as e:
        print(f"{path}: cannot read file: {e}", file=sys.stderr)
        sys.exit(1)
    return defined


def _find_header(cpp_path: str) -> str:
    """Given a .cpp path under src/, return the corresponding .hpp under include/."""
    p = cpp_path.replace("\\", "/")
    if p.startswith("src/"):
        p = "include/" + p[4:]
    return p[:-4] + ".hpp"


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def _relpath(path: str) -> str:
    if not os.path.isabs(path):
        return path.replace("\\", "/")
    return os.path.relpath(path, ROOT_DIR).replace("\\", "/")


def _source_line_to_repo_path(path: str) -> Optional[str]:
    norm = _normalize_path(path)
    idx = norm.find(PROJECT_PREFIX)
    if idx < 0:
        return None
    return "src/" + norm[idx:]


def _load_source_line_info() -> List[Tuple[int, str]]:
    global _SOURCE_LINE_CACHE
    if _SOURCE_LINE_CACHE is not None:
        return _SOURCE_LINE_CACHE

    entries: List[Tuple[int, str]] = []
    if not os.path.exists(LINE_INFO_PATH):
        _SOURCE_LINE_CACHE = entries
        return entries

    re_insn = re.compile(r"^\s+([0-9A-Fa-f]{5,})\s*:\t")
    re_src = re.compile(r"^(\S[^\r\n]*):(\d+)\s*$")
    pending: List[str] = []
    with open(LINE_INFO_PATH, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            m_src = re_src.match(line)
            if m_src:
                pending.append(m_src.group(1))
                continue
            m_insn = re_insn.match(line)
            if m_insn:
                addr = int(m_insn.group(1), 16)
                for src in pending:
                    entries.append((addr, src))
                pending = []

    entries.sort(key=lambda item: item[0])
    _SOURCE_LINE_CACHE = entries
    return entries


def _source_for_sym_line(sym_line: str) -> Optional[str]:
    m = _SYM_ADDR_RE.search(sym_line)
    if not m:
        return None
    entries = _load_source_line_info()
    if not entries:
        return None
    addr = int(m.group(1), 16)
    addrs = [entry[0] for entry in entries]
    pos = bisect.bisect_left(addrs, addr)
    candidates: List[int] = []
    if pos < len(entries):
        candidates.append(pos)
    if pos > 0:
        candidates.append(pos - 1)
    if not candidates:
        return None
    best = min(candidates, key=lambda idx: abs(entries[idx][0] - addr))
    if abs(entries[best][0] - addr) > 4:
        return None
    return _source_line_to_repo_path(entries[best][1])


def _filter_funcs_for_cpp(
    path: str, class_name: str, funcs: List[Tuple[str, str, str]]
) -> List[Tuple[str, str, str]]:
    if not class_name.startswith("nsp"):
        return funcs

    current = _normalize_path(_relpath(path)).lower()
    filtered: List[Tuple[str, str, str]] = []
    for sym_line, mangled, demangled in funcs:
        source_path = _source_for_sym_line(sym_line)
        if source_path is None and ("allow_duplicated:true" in sym_line or "visibility:local" in sym_line):
            continue
        if source_path is None or _normalize_path(source_path).lower() == current:
            filtered.append((sym_line, mangled, demangled))
    return filtered


def _collect_inline_from_header(hpp_path: str) -> Dict[str, Set[str]]:
    """
    Return {ClassName: {method_name, ...}} for every inline method definition.
    Token-based parsing with {} and ; delimiters to robustly handle multi-line
    formatting, initializer lists, and virtual destructors.
    """
    defined: Dict[str, Set[str]] = {}
    tokens = _get_clean_hpp_tokens(hpp_path, "{};")
    if not tokens:
        return defined

    class_stack: List[Tuple[str, int]] = []
    depth = 0

    for i, token in enumerate(tokens):
        if token == "{":
            prev = tokens[i - 1] if i > 0 else ""

            # 1. Detect class/struct opening
            matches = re.findall(r"\b(?:class|struct)\s+(\w+)\b", prev)
            if matches:
                class_stack.append((matches[-1], depth))
                depth += 1
                continue

            # 2. Detect inline method definitions
            if class_stack and depth == class_stack[-1][1] + 1:
                current_class = class_stack[-1][0]
                idx = prev.find("(")
                if idx != -1 and "(*" not in prev and "(&" not in prev:
                    # Method name is the identifier immediately preceding the parameter list
                    m = re.search(r"(?<!\w)(~?\w+)$", prev[:idx].strip())
                    if m:
                        meth = m.group(1)
                        if meth not in _NOT_METHODS:
                            defined.setdefault(current_class, set()).add(meth)

            depth += 1

        elif token == "}":
            depth -= 1
            while class_stack and depth <= class_stack[-1][1]:
                class_stack.pop()

    return defined


# ---------------------------------------------------------------------------
# Namespace hygiene rules for .cpp TUs
# ---------------------------------------------------------------------------

# Rule A: 'using namespace nsp*;' hides qualification — bare enum values look global
_USING_NSP_RE = re.compile(r"\busing\s+namespace\s+(nsp\w+)\s*;")

# Matches the opening of a 'namespace nsp*' block
_NSP_OPEN_RE = re.compile(r"\bnamespace\s+nsp\w+\b")

# Matches an enum definition (has opening brace, not just a forward-decl or cast)
_ENUM_DEF_RE = re.compile(r"\benum\b[^;]*\{")


def _check_namespace_rules(path: str) -> List[str]:
    """Flag 'using namespace nsp*' and enum definitions inside namespace nsp* blocks."""
    errors: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return errors

    depth = 0
    nsp_stack: List[int] = []  # brace-depth at which each nsp namespace was entered

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # Rule A: using namespace nsp*; forbidden in .cpp
        m = _USING_NSP_RE.search(line)
        if m:
            errors.append(
                f"{path}:{lineno}: 'using namespace {m.group(1)};' in a .cpp file.\n"
                f"  Use fully-qualified names instead (e.g. {m.group(1)}::VALUE)."
            )

        # Track entry into namespace nsp* blocks
        if _NSP_OPEN_RE.search(line) and "{" in line:
            nsp_stack.append(depth)

        depth += line.count("{") - line.count("}")

        # Rule B: enum definition inside a nsp namespace block
        if nsp_stack and depth > nsp_stack[-1]:
            if _ENUM_DEF_RE.search(line):
                errors.append(
                    f"{path}:{lineno}: enum definition inside a 'namespace nsp*' block.\n"
                    f"  Enum values belong in the header — update the stub in the .hpp instead."
                )

        # Pop any scopes we've exited
        while nsp_stack and depth <= nsp_stack[-1]:
            nsp_stack.pop()

    return errors


# ---------------------------------------------------------------------------
# Raw type check for .cpp function signatures
# ---------------------------------------------------------------------------
# Same typedef set as source_guard — compound forms listed before bare forms
# so "unsigned int" fires before bare "int" on the same line.
_CPP_RAW_TYPES: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bunsigned\s+int\b"),              "unsigned int",       "u32"),
    (re.compile(r"\bsigned\s+int\b"),                "signed int",         "s32"),
    (re.compile(r"\bunsigned\s+short\b"),            "unsigned short",     "u16"),
    (re.compile(r"\bsigned\s+short\b"),              "signed short",       "s16"),
    (re.compile(r"\bunsigned\s+char\b"),             "unsigned char",      "u8"),
    (re.compile(r"\bsigned\s+char\b"),               "signed char",        "s8"),
    (re.compile(r"\bunsigned\s+long\s+long\b"),      "unsigned long long", "u64"),
    (re.compile(r"\bsigned\s+long\s+long\b"),        "signed long long",   "s64"),
    (re.compile(r"(?<!unsigned )(?<!signed )\bint\b"),   "int",   "s32"),
    (re.compile(r"\bfloat\b"),                           "float", "f32"),
    (re.compile(r"\bdouble\b"),                          "double", "f64"),
    (re.compile(r"(?<!unsigned )(?<!signed )\bchar\b"),  "char",  "c8"),
    (re.compile(r"(?<!unsigned )(?<!signed )\bshort\b"), "short", "s16"),
    (re.compile(r"(?<!unsigned )(?<!signed )\blong\b(?!\s+long)"), "long", "s32"),
]

# Matches the start of an out-of-line function definition
_FUNC_SIG_START_RE = re.compile(r"\b\w+::\w+\s*\(")


def _check_raw_types(path: str) -> List[str]:
    """Return error strings for raw C++ types used in .cpp function signatures."""
    errors: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return errors

    in_sig = False
    paren_balance = 0

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("#"):
            continue

        if not in_sig:
            if not _FUNC_SIG_START_RE.search(line):
                continue
            in_sig = True
            paren_balance = 0

        # We are on a signature line (first or continuation).
        paren_balance += line.count("(") - line.count(")")

        for pat, raw_name, sr2_name in _CPP_RAW_TYPES:
            if pat.search(line):
                errors.append(
                    f"{path}:{lineno}: Raw type '{raw_name}' in function signature. "
                    f"Use SR2 typedef '{sr2_name}' instead."
                )

        if paren_balance <= 0:
            in_sig = False

    return errors


# Detects short-form include paths that MWCC can't resolve.
# MWCC with -i include does NOT search subdirectories, so any include that
# doesn't start with "Develop/" (or another root-relative prefix like "types.h")
# will silently fail when the .o cache is cold.
_SHORT_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s+"(?!Develop/|types\.h|NNS_|hk|nns_|usr/)([^"]+)"'
)
# Prefixes that are known-valid short forms (single-level, no sub-path separator needed)
_VALID_SHORT_PREFIXES = ("types.h",)


def _check_include_paths(path: str) -> List[str]:
    """Return error strings for any #include that uses a short (non-full) path.

    MWCC PS2 with -i include does not recurse subdirectories.  Includes must use
    the full path relative to the include/ root, e.g.:
        #include "Develop/Projects/SR2/pgm/src/Object/Gimmick/GimmickBody.hpp"
    Short forms like #include "Object/Gimmick/GimmickBody.hpp" are silently
    broken — they only appear to work when a cached .o is reused.
    """
    errors: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                m = _SHORT_INCLUDE_RE.match(line)
                if m:
                    inc = m.group(1)
                    # Allow single-level includes with no '/' (e.g. "types.h")
                    if "/" in inc:
                        errors.append(
                            f'{path}:{lineno}: short include path: #include "{inc}"\n'
                            f'  Fix: use full path from include/ root, e.g. '
                            f'"Develop/Projects/SR2/pgm/src/..."'
                        )
    except OSError:
        pass
    return errors


# ---------------------------------------------------------------------------
# Override keyword check — MWCC PS2 does not support C++11 'override'
# ---------------------------------------------------------------------------
# Matches 'override' as a standalone keyword (not inside a comment or string)
_OVERRIDE_RE = re.compile(r'\boverride\b')


def _check_override_keyword(cpp_path: str) -> List[str]:
    """Check that the corresponding .hpp does not use the 'override' keyword.

    MWCC PS2 (MWCCPS2 3.0.1b198) does not support the C++11 'override' keyword.
    Using it causes a compile error with a confusing message like:
      'override' is not a valid keyword in this context

    This guard scans the .hpp file and reports any use of 'override' with a clear
    fix suggestion.
    """
    errors: List[str] = []
    hpp_path = _find_header(cpp_path)
    if not os.path.exists(hpp_path):
        return errors
    try:
        with open(hpp_path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith("//") or stripped.startswith("/*"):
                    continue
                if _OVERRIDE_RE.search(line):
                    errors.append(
                        f"{cpp_path}: 'override' keyword found in {hpp_path}:{lineno}.\n"
                        f"  MWCC PS2 does not support C++11 'override'.\n"
                        f"  Fix: remove the 'override' keyword from the declaration.\n"
                        f"  Line: {stripped}"
                    )
    except OSError:
        pass
    return errors


def _collect_defined_ordered(path: str) -> List[Tuple[str, str]]:
    """Return [(class_name, method_name), ...] for out-of-line definitions in file order.

    Only collects at file scope (brace depth 0) to avoid misidentifying qualified
    call sites inside function bodies as definitions.
    """
    result: List[Tuple[str, str]] = []
    seen: set = set()
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            depth = 0
            for line in f:
                if depth == 0:
                    for cls, meth in _DEF_RE.findall(line):
                        key = (cls, meth)
                        if key not in seen:
                            seen.add(key)
                            result.append(key)
                depth += line.count('{') - line.count('}')
    except OSError:
        pass
    return result


# Matches Ghidra-style placeholder parameter names (param_1, param_2, etc.)
_PARAM_PLACEHOLDER_RE = re.compile(r'\bparam_\d+\b')

# Extracts a hex address from a symbol_addrs line (= 0xABCD1234)
_SYM_ADDR_RE = re.compile(r'=\s*0x([0-9A-Fa-f]+)')

# Matches the start of a method signature (name immediately before '(')
_METHOD_NAME_RE = re.compile(r'(?<!\w)(~?\w+)\s*\(')

# Tokens that are pure type keywords / SR2 typedefs — never valid parameter names.
_TYPE_TOKENS: frozenset = frozenset({
    'const', 'volatile', 'unsigned', 'signed',
    'u8', 's8', 'c8', 'u16', 's16', 'u32', 's32', 'u64', 's64',
    'f32', 'f64', 'bool', 'void', 'int', 'char', 'float', 'double',
    'long', 'short',
})


def _param_token_is_name(token: str) -> bool:
    """Return True if a parameter's last token looks like a name rather than a type."""
    if not token:
        return False
    if token in ('*', '&', '**'):
        return False
    if token.endswith(('*', '&')):  # type-with-pointer/ref, no name follows
        return False
    if token in _TYPE_TOKENS:
        return False
    return True


def _has_anonymous_params(params_text: str) -> bool:
    """Return True if any top-level parameter has a type but no name.

    Detects bare anonymous parameters such as ``(u32, u8, f32)`` or
    ``(clsFoo*, const u32)`` where the agent omitted the Hungarian names.
    """
    if not params_text or params_text.strip() in ('', 'void'):
        return False
    params: List[str] = []
    depth = 0
    current: List[str] = []
    for ch in params_text:
        if ch in '(<':
            depth += 1
            current.append(ch)
        elif ch in ')>':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            params.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        params.append(''.join(current).strip())
    for param in params:
        if not param:
            continue
        tokens = param.split()
        if not tokens:
            continue
        if not _param_token_is_name(tokens[-1]):
            return True
    return False


def _extract_param_text(sig_text: str) -> Optional[str]:
    """Return the text inside the outermost () of a function signature."""
    depth_p = 0
    depth_a = 0
    start = -1
    for i, ch in enumerate(sig_text):
        if ch == '(':
            if depth_p == 0 and depth_a == 0:
                start = i + 1
            depth_p += 1
        elif ch == ')':
            depth_p -= 1
            if depth_p == 0 and depth_a == 0 and start >= 0:
                return sig_text[start:i].strip()
        elif ch == '<' and depth_p > 0:
            depth_a += 1
        elif ch == '>' and depth_p > 0 and depth_a > 0:
            depth_a -= 1
    return None


def _count_params(params_text: str) -> int:
    """Count top-level parameters in a parameter list string."""
    if not params_text or params_text.strip() in ('', 'void'):
        return 0
    count = 1
    depth = 0
    for ch in params_text:
        if ch in '(<':
            depth += 1
        elif ch in ')>':
            depth -= 1
        elif ch == ',' and depth == 0:
            count += 1
    return count


def _collect_signatures(path: str) -> "Dict[Tuple[str, str, int], str]":
    """Return {(class, method, param_count): sig_text} for out-of-line definitions.

    Keyed by param count so overloads (same method name, different arity) each get
    their own slot — prevents false-positive count mismatches on overloaded methods.
    Only collects at file scope (brace depth 0) to avoid treating qualified call
    sites inside function bodies as definitions.
    """
    sigs: Dict[Tuple[str, str, int], str] = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except OSError:
        return sigs

    depth = 0  # file-scope brace depth
    in_sig = False
    paren_depth = 0
    sig_parts: List[str] = []
    sig_base: Optional[Tuple[str, str]] = None

    for raw_line in lines:
        line = raw_line.rstrip('\n')
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('#'):
            depth += line.count('{') - line.count('}')
            continue

        if not in_sig:
            if depth == 0:
                m = _DEF_RE.search(line)
                if m and not stripped.endswith(';'):
                    in_sig = True
                    paren_depth = line.count('(') - line.count(')')
                    sig_parts = [line]
                    sig_base = (m.group(1), m.group(2))
        else:
            sig_parts.append(line)
            paren_depth += line.count('(') - line.count(')')

        if in_sig and paren_depth <= 0:
            if sig_base:
                text = ' '.join(sig_parts)
                count = _count_params(_extract_param_text(text) or "")
                sigs.setdefault((sig_base[0], sig_base[1], count), text)
            in_sig = False
            sig_parts = []
            sig_base = None

        depth += line.count('{') - line.count('}')

    return sigs


def _collect_hpp_method_sigs(hpp_path: str) -> "Dict[Tuple[str, str, int], str]":
    """Return {(class_name, method_name, param_count): sig_text} for method sigs in a .hpp.

    Captures both declarations ending in ';' and inline definitions ending in '{'.
    Keyed by param count so overloads each get their own slot.
    Only matches methods at the direct class-body depth (not inside method bodies).
    """
    sigs: Dict[Tuple[str, str, int], str] = {}
    if not os.path.exists(hpp_path):
        return sigs
    try:
        with open(hpp_path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except OSError:
        return sigs

    class_stack: List[Tuple[str, int]] = []  # (class_name, brace_depth_before_opening_{)
    depth = 0
    in_sig = False
    paren_depth = 0
    sig_parts: List[str] = []
    sig_base: Optional[Tuple[str, str]] = None

    for raw_line in lines:
        line = raw_line.rstrip('\n')
        stripped = line.strip()

        if stripped.startswith('//') or stripped.startswith('#'):
            continue

        # Detect class/struct whose body opens on this line (before counting braces).
        if not in_sig:
            m_cls = _CLASS_OPEN_RE.search(stripped)
            if m_cls:
                class_stack.append((m_cls.group(1), depth))

        # Accumulate or start a signature.
        if not in_sig:
            # Only look for methods at direct class-body depth.
            if class_stack and depth == class_stack[-1][1] + 1:
                m = _METHOD_NAME_RE.search(line)
                if m:
                    meth = m.group(1)
                    if meth not in _NOT_METHODS:
                        in_sig = True
                        paren_depth = line.count('(') - line.count(')')
                        sig_parts = [line]
                        sig_base = (class_stack[-1][0], meth)
        else:
            sig_parts.append(line)
            paren_depth += line.count('(') - line.count(')')

        # Emit when the parameter list closes.
        if in_sig and paren_depth <= 0:
            if sig_base:
                text = ' '.join(sig_parts)
                count = _count_params(_extract_param_text(text) or "")
                sigs.setdefault((sig_base[0], sig_base[1], count), text)
            in_sig = False
            sig_parts = []
            sig_base = None

        depth += line.count('{') - line.count('}')
        while class_stack and depth <= class_stack[-1][1]:
            class_stack.pop()

    return sigs


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Return type check: derived class virtual function vs base class declaration
# ---------------------------------------------------------------------------
# Catches the MWCC error:
#   'clsFoo::method()' differs from virtual base function 'clsBar::method()'
#   in return type only
#
# Compares the derived class's header declaration against the base class's
# header declaration (not against DWARF, which can be inaccurate).

# SR2 typedefs that map to canonical types for comparison
_TYPE_MAP: Dict[str, str] = {
    "void": "void",
    "u8": "unsigned char",
    "s8": "signed char",
    "u16": "unsigned short",
    "s16": "signed short",
    "u32": "unsigned int",
    "s32": "signed int",
    "u64": "unsigned long long",
    "s64": "signed long long",
    "f32": "float",
    "f64": "double",
    "c8": "char",
    "char": "char",
    "bool": "unsigned char",
}

# Reverse map: canonical type -> SR2 typedef suggestion
_CANONICAL_TO_TYPEDEF: Dict[str, str] = {
    "void": "void",
    "unsigned char": "u8",
    "signed char": "s8",
    "unsigned short": "u16",
    "signed short": "s16",
    "unsigned int": "u32",
    "signed int": "s32",
    "unsigned long long": "u64",
    "signed long long": "s64",
    "float": "f32",
    "double": "f64",
    "char": "c8",
}


def _canonical_to_typedef(canonical: str) -> str:
    """Convert a canonical type to the SR2 typedef suggestion."""
    return _CANONICAL_TO_TYPEDEF.get(canonical, canonical)


def _normalize_return_type(rt: str) -> str:
    """Normalize a return type string to a canonical form for comparison."""
    rt = rt.strip()
    # Handle pointer types: strip trailing '*'
    rt = rt.rstrip("*").strip()
    # Handle 'enum' prefix (headers may or may not include 'enum')
    if rt.startswith("enum "):
        rt = rt[5:].strip()
    # Handle 'struct' prefix
    if rt.startswith("struct "):
        rt = rt[7:].strip()
    # Map SR2 typedefs to canonical types
    if rt in _TYPE_MAP:
        return _TYPE_MAP[rt]
    # Handle 'const' qualifier
    if rt.startswith("const "):
        rt = rt[6:].strip()
        if rt in _TYPE_MAP:
            return _TYPE_MAP[rt]
    # Handle 'unsigned' / 'signed' compound types
    if rt in ("unsigned", "signed", "unsigned int", "signed int", "unsigned char",
              "signed char", "unsigned short", "signed short", "unsigned long",
              "signed long", "unsigned long long", "signed long long"):
        return rt
    # Unknown type — return as-is
    return rt


def _extract_return_type_from_hpp_sig(sig_text: str) -> Optional[str]:
    """Extract the return type from a header method signature.

    The sig_text contains the full declaration line, e.g.:
      'virtual void checkRequestDrawDebris();'
      'virtual s32 getPackId() const { return 24000; }'
      'u8 checkFreeArea(s32 s32Param1, s32 s32Param2);'
    """
    # Remove 'virtual', 'inline', 'static' keywords
    cleaned = re.sub(r'\b(?:virtual|inline|static|explicit)\s+', '', sig_text).strip()
    # Remove the method name and everything after the opening '('
    paren_open = cleaned.find("(")
    if paren_open < 0:
        return None
    prefix = cleaned[:paren_open].strip()
    # Remove 'const', 'override', 'noexcept' qualifiers from the end
    prefix = re.sub(r'\s+(?:const|override|noexcept)\s*$', '', prefix).strip()
    # The return type is everything BEFORE the method name.
    # The method name is the last word (or last ::word for nested names).
    if "::" in prefix:
        method_part = prefix.rsplit("::", 1)[1].strip()
        rt = prefix[:prefix.rindex(method_part)].strip()
    else:
        parts = prefix.split()
        if len(parts) < 2:
            return None
        method_part = parts[-1]
        rt = prefix[:prefix.rindex(method_part)].strip()
    return rt if rt else None


def _collect_base_class_names(hpp_path: str) -> List[str]:
    """Extract base class names from a header file's class definition."""
    bases: List[str] = []
    if not os.path.exists(hpp_path):
        return bases
    try:
        with open(hpp_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                m = re.match(r"(?:class|struct)\s+(\w+)", stripped)
                if m and ":" in stripped and "{" in stripped:
                    colon_idx = stripped.find(":")
                    brace_idx = stripped.find("{")
                    if colon_idx < brace_idx:
                        inheritance = stripped[colon_idx + 1:brace_idx].strip()
                        # Strip template arguments to avoid treating template parameters
                        # like clsBaseGimmickBody<Foo, Bar, Baz> as multiple base classes
                        inheritance_no_tmpl = re.sub(r"<[^>]*>", "", inheritance)
                        for part in inheritance_no_tmpl.split(","):
                            for word in part.strip().split():
                                if word not in ("public", "private", "protected", "virtual"):
                                    if re.match(r"^\w+$", word):
                                        bases.append(word)
                                    break
    except OSError:
        pass
    return bases


def _collect_all_base_class_names(hpp_path: str) -> List[str]:
    """Recursively collect all base class names in the inheritance chain."""
    all_bases: List[str] = []
    visited: set = set()
    queue: List[str] = [hpp_path]
    while queue:
        current_hpp = queue.pop(0)
        immediate_bases = _collect_base_class_names(current_hpp)
        for base_name in immediate_bases:
            if base_name in visited:
                continue
            visited.add(base_name)
            all_bases.append(base_name)
            base_hpp = _find_header_for_class(base_name)
            if base_hpp and os.path.exists(base_hpp):
                queue.append(base_hpp)
    return all_bases


def _get_all_hpp_sigs(hpp_path: str) -> Dict[Tuple[str, str, int], str]:
    """Collect hpp signatures from the header and all its base class headers (recursively)."""
    sigs = _collect_hpp_method_sigs(hpp_path)
    all_base_names = _collect_all_base_class_names(hpp_path)
    for base_name in all_base_names:
        base_hpp = _find_header_for_class(base_name)
        if base_hpp and os.path.exists(base_hpp):
            sigs.update(_collect_hpp_method_sigs(base_hpp))
    return sigs


def _find_header_for_class(class_name: str) -> Optional[str]:
    """Try to find the header file for a class name."""
    # Try common patterns
    patterns = [
        f"include/Develop/Projects/SR2/pgm/src/Object/{class_name}.hpp",
        f"include/Develop/Projects/SR2/pgm/src/Object/Gimmick/{class_name}.hpp",
        f"include/Develop/Projects/SR2/pgm/src/Game/{class_name}.hpp",
    ]
    for pattern in patterns:
        if os.path.exists(pattern):
            return pattern
    # Try searching in include/
    for root, dirs, files in os.walk("include"):
        for f in files:
            if f == class_name + ".hpp":
                return os.path.join(root, f)
    return None


def _check_return_type_mismatch(cpp_path: str) -> List[str]:
    """Check that virtual function return types match between derived and base class.

    This catches the MWCC error:
      'clsFoo::method()' differs from virtual base function 'clsBar::method()'
      in return type only

    Compares the derived class's header declaration against the base class's
    header declaration (not against DWARF, which can be inaccurate).
    """
    errors: List[str] = []
    hpp_path = _find_header(cpp_path)
    if not os.path.exists(hpp_path):
        return errors

    # Collect all hpp signatures including base classes
    all_sigs = _get_all_hpp_sigs(hpp_path)

    # For each class defined in the .cpp, check functions against base class headers
    try:
        from _common import grep_symbol_addrs, demangle_symbol
    except ImportError:
        return errors

    defined_classes = _collect_defined(cpp_path)

    for class_name in sorted(defined_classes):
        # Get ALL base classes for this class (full inheritance chain)
        base_names = _collect_all_base_class_names(hpp_path)
        if not base_names:
            continue

        non_weak, weak = grep_symbol_addrs(class_name)
        all_funcs = non_weak + weak
        if not all_funcs:
            continue

        for sym_line in all_funcs:
            mangled = sym_line.split("=")[0].strip()
            if mangled.startswith("__vt__"):
                continue
            demangled = demangle_symbol(mangled) or mangled
            if "(" not in demangled:
                continue

            # Skip constructors/destructors
            method_before = demangled.split("(")[0].strip()
            parts = method_before.rsplit("::", 1)
            if len(parts) == 2:
                method_name = parts[1].strip()
            else:
                method_name = method_before.strip()
            if method_name.startswith("~") or method_name == class_name:
                continue

            # Find the derived class's signature
            expected_count = _count_params(_extract_param_text(demangled) or "")
            derived_sig = all_sigs.get((class_name, method_name, expected_count), "")
            if not derived_sig:
                continue

            derived_rt = _extract_return_type_from_hpp_sig(derived_sig)
            if not derived_rt:
                continue

            # Search base classes for the same method
            for base_name in base_names:
                base_sig = all_sigs.get((base_name, method_name, expected_count), "")
                if not base_sig:
                    continue
                base_rt = _extract_return_type_from_hpp_sig(base_sig)
                if not base_rt:
                    continue

                # Compare normalized return types
                if _normalize_return_type(derived_rt) != _normalize_return_type(base_rt):
                    derived_typedef = _canonical_to_typedef(derived_rt)
                    base_typedef = _canonical_to_typedef(base_rt)
                    errors.append(
                        f"{cpp_path}: virtual function '{class_name}::{method_name}' "
                        f"has return type '{derived_typedef}' (aka '{derived_rt}') but the "
                        f"base class '{base_name}' declares it as "
                        f"'{base_typedef}' (aka '{base_rt}').\n"
                        f"  Derived declares: {derived_sig.strip()}\n"
                        f"  Base declares: {base_sig.strip()}\n"
                        f"  Fix: change the return type in the derived class to '{base_typedef}'"
                    )
                    break  # Only report once per method

    return errors


def _method_name_from_demangled(demangled: str) -> str:
    before_paren = demangled.split("(")[0].strip()
    parts = before_paren.rsplit("::", 1)
    if len(parts) == 2:
        return parts[1].strip()
    return before_paren.strip()


def check_file(path: str) -> List[str]:
    """Return list of error strings for missing definitions, bad includes, and namespace rules."""
    errors: List[str] = []

    errors.extend(_check_include_paths(path))
    errors.extend(_check_namespace_rules(path))
    errors.extend(_check_raw_types(path))
    errors.extend(_check_return_type_mismatch(path))
    errors.extend(_check_override_keyword(path))

    defined = _collect_defined(path)
    if not defined:
        return errors

    # Track which classes are defined out-of-line in the .cpp itself.
    # Only these classes need their non-weak symbols stubbed in this TU.
    cpp_defined_classes = set(defined.keys())

    defined_ordered = _collect_defined_ordered(path)
    sigs = _collect_signatures(path)

    # Augment with inline definitions from the corresponding header so that
    # methods already defined with a body in the .hpp are not reported missing.
    hpp_path = _find_header(path)
    for cls, methods in _collect_inline_from_header(hpp_path).items():
        defined.setdefault(cls, set()).update(methods)

    hpp_sigs = _collect_hpp_method_sigs(hpp_path)

    # Pre-compute (class, method) pairs that have at least one sig in each file,
    # used to distinguish "method present but wrong arity" from "method absent".
    cpp_sig_methods = {(k[0], k[1]) for k in sigs}
    hpp_sig_methods = {(k[0], k[1]) for k in hpp_sigs}

    # Collect linenos while checking completeness, for the order check below.
    method_linenos: Dict[str, int] = {}

    for class_name in sorted(defined):
        # Only require non-weak stubs for classes that have out-of-line definitions
        # in this .cpp. Classes that appear only via inline header definitions (e.g.
        # a sibling class declared in the same .hpp) belong to a different TU and
        # their non-weak symbols must not be stubbed here.
        if class_name not in cpp_defined_classes:
            continue
        funcs = _filter_funcs_for_cpp(path, class_name, get_non_weak_funcs(class_name))
        if not funcs:
            continue
        required_method_names = {
            _method_name_from_demangled(demangled) for _sym_line, _mangled, demangled in funcs
        }
        if not (defined.get(class_name, set()) & required_method_names):
            continue
        for _sym_line, _mangled, demangled in funcs:
            # demangled looks like "ClassName::method(args...)"
            method_name = _method_name_from_demangled(demangled)
            # Destructors: ~ClassName -> method key is "~ClassName"
            if method_name not in defined.get(class_name, set()):
                errors.append(
                    f"{path}: missing definition for {class_name}::{method_name}\n"
                    f"  Required by symbol: {_sym_line.split('=')[0].strip()}\n"
                    f"  Add stub: {demangled.split('(')[0].strip()}({_get_param_placeholder(demangled)}) {{}}"
                )
            else:
                lineno = sym_lineno(_sym_line)
                if lineno != 2**31:
                    method_linenos[f"{class_name}::{method_name}"] = lineno

                # --- Param count check (free: uses demangled, no DWARF lookup) ---
                # Key includes param_count so overloads don't collide.
                # Only report a count error when the method IS present but has no
                # overload matching the expected arity (avoids false positives on
                # legitimately overloaded methods like registTask(T*) / registTask(T*,T*)).
                expected_count = _count_params(_extract_param_text(demangled) or "")
                exact_key = (class_name, method_name, expected_count)
                for label, sig_dict, method_set in [
                    (".cpp", sigs, cpp_sig_methods),
                    (".hpp", hpp_sigs, hpp_sig_methods),
                ]:
                    if (class_name, method_name) not in method_set:
                        continue  # method not in this file at all; not a count error
                    if exact_key not in sig_dict:
                        errors.append(
                            f"{path}: {class_name}::{method_name} has no overload with "
                            f"{expected_count} parameter(s) in {label} but symbol expects {expected_count}.\n"
                            f"  Symbol: {demangled}\n"
                            f"  Fix: restore the correct parameter list"
                        )

                # --- Param name check (lazy: only when param_N present) ---
                m_addr = _SYM_ADDR_RE.search(_sym_line)
                for label, sig_dict in [
                    (".cpp", sigs),
                    (".hpp", hpp_sigs),
                ]:
                    sig_text = sig_dict.get(exact_key, "")
                    if not sig_text or not _PARAM_PLACEHOLDER_RE.search(sig_text):
                        continue
                    # Try DWARF for a concrete fix suggestion.
                    if m_addr:
                        dwarf_map = get_dwarf_params("0x" + m_addr.group(1))
                        real = [n for n in dwarf_map.values()
                                if not re.match(r'^param_\d+$', n)]
                        if real:
                            errors.append(
                                f"{path}: {class_name}::{method_name} uses placeholder "
                                f"param names in {label} but DWARF has real names.\n"
                                f"  DWARF names: {', '.join(real)}\n"
                                f"  Fix: apply these names to the matching-type "
                                f"param_N placeholder(s); use Hungarian convention for the rest"
                            )
                            continue
                    # No DWARF names — still flag; convention names apply.
                    errors.append(
                        f"{path}: {class_name}::{method_name} uses placeholder "
                        f"param names in {label} — use Hungarian convention names.\n"
                        f"  Fix: rename param_N to type-prefixed ParamN "
                        f"(e.g. s32Param1, u8Param1, pParam1, rParam1)"
                    )

                # --- Anonymous param check (catches bare types with no name at all) ---
                for label, sig_dict in [
                    (".cpp", sigs),
                    (".hpp", hpp_sigs),
                ]:
                    sig_text = sig_dict.get(exact_key, "")
                    if not sig_text:
                        continue
                    params_text = _extract_param_text(sig_text)
                    if not params_text or not _has_anonymous_params(params_text):
                        continue
                    errors.append(
                        f"{path}: {class_name}::{method_name} has anonymous parameters "
                        f"in {label} (bare types with no names).\n"
                        f"  Symbol: {demangled}\n"
                        f"  Fix: add Hungarian names — use DWARF names when available, "
                        f"else type-prefix + ParamN (e.g. u32Param1, u8Param2, f32Param3)"
                    )

    # Check that stubs appear in the same order as the original source.
    # Build the list of (file_position, cls, meth, lineno) for anchored functions.
    anchored = [
        (i, cls, meth, method_linenos[f"{cls}::{meth}"])
        for i, (cls, meth) in enumerate(defined_ordered)
        if f"{cls}::{meth}" in method_linenos
    ]
    out_of_order = False
    prev_lineno = -1
    for _i, cls, meth, lineno in anchored:
        if lineno < prev_lineno:
            out_of_order = True
            break
        prev_lineno = lineno

    if out_of_order:
        correct = sorted(anchored, key=lambda x: x[3])
        lines = [f"{path}: stubs are out of source-line order. Correct order for anchored functions:"]
        for _i, cls, meth, lineno in correct:
            lines.append(f"  line {lineno:6d}  {cls}::{meth}")
        lines.append("  (Functions without line-info can remain in any position relative to each other.)")
        lines.append(f"  Fix: python tools/reorder_stubs.py {path}")
        errors.append("\n".join(lines))

    return errors


def _get_param_placeholder(demangled: str) -> str:
    """Extract the raw parameter list from a demangled signature."""
    paren_open = demangled.find("(")
    paren_close = demangled.rfind(")")
    if paren_open == -1 or paren_close == -1:
        return ""
    return demangled[paren_open + 1 : paren_close]


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <stub.cpp> [stamp.ok]", file=sys.stderr)
        sys.exit(1)

    cpp_path = sys.argv[1]
    stamp_path = sys.argv[2] if len(sys.argv) >= 3 else None

    errors = check_file(cpp_path)
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
