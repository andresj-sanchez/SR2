#!/usr/bin/env python3
"""
Batch-fix anonymous parameters in scaffold stubs.

Finds functions whose parameter list contains bare types with no names
(e.g. ``void Foo::bar(u32, f32) {}``), looks up DWARF-annotated parameter
names for each function address, and rewrites both the ``.cpp`` definition
and the corresponding ``.hpp`` declaration with named params, using the same
DWARF-first / Hungarian-fallback logic as the scaffold tool.

All heavy data (symbol_addrs.txt, DWARF functions) is preloaded once for
speed — no subprocess calls during the main loop.

Usage:
    python tools/fix_anon_params.py src/.../Foo.cpp [...]
    python tools/fix_anon_params.py --all        # scan all stubs
    python tools/fix_anon_params.py --dry-run    # preview only
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).parent))
from _common import ROOT_DIR

_SR2_SYMBOLS  = os.path.join(ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "symbol_addrs.txt")
_DWARF_FUNCS  = os.path.join(ROOT_DIR, "symbols", "Dwarf", "functions.nothpp")
_SRC_ROOTS = [
    os.path.join(ROOT_DIR, "src", "Develop", "Projects", "SR2", "pgm", "src"),
    os.path.join(ROOT_DIR, "src", "Develop", "Projects", "SR2", "pgm", "lib"),
]
_DTK          = os.path.join(ROOT_DIR, "build", "tools", "dtk")

# ── type classifier ─────────────────────────────────────────────────────────

_TYPE_TOKENS: frozenset = frozenset({
    'const', 'volatile', 'unsigned', 'signed',
    'u8', 's8', 'c8', 'u16', 's16', 'u32', 's32', 'u64', 's64',
    'f32', 'f64', 'bool', 'void', 'int', 'char', 'float', 'double',
    'long', 'short',
})


def _is_name(token: str) -> bool:
    if not token:
        return False
    if token in ('*', '&', '**'):
        return False
    if token.endswith(('*', '&')):
        return False
    return token not in _TYPE_TOKENS


def _split_top_level(s: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in s:
        if ch in '(<':
            depth += 1
            cur.append(ch)
        elif ch in ')>':
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return [p for p in parts if p]


def _has_anon(params_str: str) -> bool:
    if not params_str or params_str.strip() in ('', 'void'):
        return False
    for param in _split_top_level(params_str):
        toks = param.split()
        if toks and not _is_name(toks[-1]):
            return True
    return False


def _count_params(s: str) -> int:
    if not s or s.strip() in ('', 'void'):
        return 0
    return len(_split_top_level(s))


# ── Hungarian fallback (SR2 typedefs + raw C++) ──────────────────────────────

_HU_MAP = {
    'u8': 'u8', 's8': 's8', 'c8': 'c8',
    'u16': 'u16', 's16': 's16',
    'u32': 'u32', 's32': 's32',
    'u64': 'u64', 's64': 's64',
    'f32': 'f32', 'f64': 'f64',
    'float': 'f32', 'double': 'f64',
    'int': 's32', 'signed int': 's32',
    'unsigned int': 'u32',
    'short': 's16', 'unsigned short': 'u16',
    'char': 's8', 'signed char': 's8', 'unsigned char': 'u8',
    'long': 's32', 'unsigned long': 'u32',
    'bool': 'b',
}


def _hungarian(type_str: str, n: int) -> str:
    t = type_str.strip()
    base = re.sub(r'\b(const|volatile)\b', '', t).strip()
    if base.endswith('&'):
        return f"rParam{n}"
    if '*' in base:
        b2 = re.sub(r'\*+', '', base).replace('const', '').strip()
        if 'c8' in b2 or 'char' in b2.lower():
            return f"pcParam{n}"
        if 'void' in b2.lower():
            return f"pvParam{n}"
        return f"pParam{n}"
    tl = base.lower()
    if tl in _HU_MAP:
        return f"{_HU_MAP[tl]}Param{n}"
    if tl.startswith('enm') or '::enm' in tl:
        return f"eParam{n}"
    return f"sParam{n}"


def _inject_names(params_str: str, pos_map: Dict[int, str]) -> str:
    params = _split_top_level(params_str)
    if not params or params == ['void']:
        return params_str
    out = []
    for i, param in enumerate(params):
        toks = param.split()
        if not toks or _is_name(toks[-1]):
            out.append(param)
            continue
        name = pos_map.get(i, _hungarian(param, i + 1))
        out.append(f"{param} {name}")
    return ', '.join(out)


# ── Preload symbol_addrs.txt ─────────────────────────────────────────────────
# Index: class_name -> [(mangled, addr_hex)]

_SymIdx = Dict[str, List[Tuple[str, str]]]
_sym_index: Optional[_SymIdx] = None


def _load_sym_index() -> _SymIdx:
    global _sym_index
    if _sym_index is not None:
        return _sym_index
    idx: _SymIdx = {}
    addr_re = re.compile(r'=\s*0x([0-9A-Fa-f]+)')
    # MWCC owner tag:  __N<classname>  where N = len(classname)
    owner_re = re.compile(r'__(\d+)([A-Za-z_]\w*)')
    with open(_SR2_SYMBOLS, encoding='utf-8', errors='replace') as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue
            sym = stripped.split('=')[0].strip()
            if sym.startswith('@STRING@') or sym.startswith('__vt__'):
                continue
            # Skip weak / allow_duplicated symbols (handled by header inlines)
            if 'visibility:weak' in stripped and 'allow_duplicated:true' in stripped:
                continue
            addr_m = addr_re.search(stripped)
            if not addr_m:
                continue
            addr = '0x' + addr_m.group(1)
            # Find all owner tags and index by class name
            for m in owner_re.finditer(sym):
                n = int(m.group(1))
                name = m.group(2)
                if len(name) == n:
                    idx.setdefault(name, []).append((sym, addr))
    _sym_index = idx
    return idx


def _method_from_mangled(mangled: str, class_name: str) -> str:
    """Extract method name from an MWCC mangled symbol."""
    tag = f"__{len(class_name)}{class_name}"
    idx = mangled.find(tag)
    if idx >= 0:
        return mangled[:idx]
    return mangled


# ── Preload DWARF functions file ─────────────────────────────────────────────
# Index: addr_int -> Dict[position, param_name]

_DwarfIdx = Dict[int, Dict[int, str]]
_dwarf_index: Optional[_DwarfIdx] = None
_range_re = re.compile(r'^//\s*Range:\s*(0x[0-9A-Fa-f]+)', re.MULTILINE)
_chunk_re = re.compile(r'/\*[^*]+\*/')
_skip_kw = frozenset([
    'class', 'struct', 'const', 'volatile', 'void', 'unsigned', 'signed',
    'short', 'long', 'int', 'float', 'double', 'char', 'bool',
])


def _extract_dwarf_name(chunk: str) -> Optional[str]:
    """Extract an identifier name from a DWARF param fragment."""
    for tok in reversed(chunk.split()):
        tok = tok.strip('(),;')
        if not tok:
            continue
        if re.match(r'^[A-Za-z_]\w*$', tok) and tok not in _skip_kw:
            return tok
    return None


def _dwarf_split_top(s: str) -> List[str]:
    """Split by top-level commas."""
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in s:
        if ch in '(<':
            depth += 1
            cur.append(ch)
        elif ch in ')>':
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return [p for p in parts if p]


def _parse_dwarf_params(sig_line: str) -> Dict[int, str]:
    """Parse one DWARF function signature line into {position: name}."""
    inner_m = re.search(r'\((.+)\)\s*(?:\{)?\s*$', sig_line)
    if not inner_m:
        return {}
    raw = inner_m.group(1)
    chunks = _chunk_re.split(raw)
    param_map: Dict[int, str] = {}
    position = 0
    for chunk in chunks[:-1]:
        chunk = chunk.strip().lstrip(',').strip()
        if not chunk:
            position += 1
            continue
        sub = _dwarf_split_top(chunk)
        position += len(sub) - 1
        name = _extract_dwarf_name(sub[-1]) if sub else None
        if name:
            param_map[position] = name
        position += 1
    return param_map


def _load_dwarf_index() -> _DwarfIdx:
    global _dwarf_index
    if _dwarf_index is not None:
        return _dwarf_index
    idx: _DwarfIdx = {}
    if not os.path.exists(_DWARF_FUNCS):
        _dwarf_index = idx
        return idx

    with open(_DWARF_FUNCS, encoding='utf-8', errors='replace') as f:
        content = f.read()

    # Find each Range: annotation and the next non-comment code line
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        rm = _range_re.match(line)
        if rm:
            addr_int = int(rm.group(1), 16)
            # Look at the next few lines for the function signature
            for j in range(i + 1, min(i + 5, len(lines))):
                sig = lines[j].strip()
                if sig.startswith('//') or not sig:
                    continue
                params = _parse_dwarf_params(sig)
                idx[addr_int] = params
                break
        i += 1

    _dwarf_index = idx
    return idx


# ── DTK demangle (batch-friendly, only for method name extraction) ───────────

def _demangle_one(mangled: str) -> Optional[str]:
    """Demangle one symbol via dtk. Used only as fallback."""
    if not os.path.exists(_DTK):
        return None
    r = subprocess.run([_DTK, 'demangle', mangled], capture_output=True, text=True)
    return r.stdout.strip() or None


# ── Build per-file fix table ─────────────────────────────────────────────────

def _build_fix_map(class_names: List[str]) -> Dict[Tuple[str, int], Dict[int, str]]:
    """Return {(method_lower, param_count): dwarf_pos_map} for all classes."""
    sym_idx = _load_sym_index()
    dwarf_idx = _load_dwarf_index()
    result: Dict[Tuple[str, int], Dict[int, str]] = {}

    for cls in class_names:
        for mangled, addr in sym_idx.get(cls, []):
            method = _method_from_mangled(mangled, cls)
            # Parse param count from address in DWARF
            addr_int = int(addr, 16)
            pos_map = dwarf_idx.get(addr_int, {})
            # Count params from DWARF sig OR fall back to 0 (let stub count decide)
            # We'll match by method name only if unambiguous, else by method+count
            # Store addr so we can resolve param count from DWARF at match time
            key_base = method.lower()
            # We may not know param count yet without demangling.
            # Use addr to get param count from DWARF sig line (already parsed).
            # Actually derive count from pos_map + any unannotated slots using
            # the DWARF sig: re-search for the sig line quickly.
            # Simpler: just store (method, addr) and resolve at fix time.
            # Store multiple addrs per method to handle overloads.
            result.setdefault((key_base, -1), {})  # placeholder
            # Build a specific (method, pc) key if we can count params
            # from the DWARF param map max position+1
            pc = (max(pos_map.keys()) + 1) if pos_map else -1
            key = (key_base, pc)
            if key not in result:
                result[key] = pos_map
    return result


def _build_fix_map_v2(class_names: List[str]) -> Dict[Tuple[str, int], Dict[int, str]]:
    """
    Build {(method_lower, param_count): dwarf_pos_map}.
    Uses preloaded sym_index + dwarf_index; no subprocesses.
    Param count is determined by demangling via dtk (fast, batched by class).
    """
    sym_idx = _load_sym_index()
    dwarf_idx = _load_dwarf_index()
    result: Dict[Tuple[str, int], Dict[int, str]] = {}

    for cls in class_names:
        syms = sym_idx.get(cls, [])
        for mangled, addr in syms:
            method = _method_from_mangled(mangled, cls)
            addr_int = int(addr, 16)
            pos_map = dwarf_idx.get(addr_int, {})

            # Determine param count from demangling
            demangled = _demangle_one(mangled)
            if demangled:
                op = demangled.find('(')
                cp = demangled.rfind(')')
                if op >= 0 and cp > op:
                    pc = _count_params(demangled[op + 1:cp])
                else:
                    pc = 0
            else:
                # Fallback: use pos_map max+1 or 0
                pc = (max(pos_map.keys()) + 1) if pos_map else 0

            key = (method.lower(), pc)
            if key not in result:
                result[key] = pos_map

    return result


# ── Param-block extraction ───────────────────────────────────────────────────

def _find_param_block(text: str, paren_pos: int) -> Tuple[int, int]:
    assert text[paren_pos] == '('
    depth = 0
    for i in range(paren_pos, len(text)):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return paren_pos, i
    return paren_pos, -1


# ── Fix text ────────────────────────────────────────────────────────────────

# A param is "anonymous" if the token immediately before `,` or `)` is one
# of: builtin type, identifier ending in `*` / `&` (pointer/reference type),
# or `*` / `&` alone. We don't try to be precise here — the per-line
# `_has_anon` check rejects false positives later. The goal of this regex
# is just to skip files that obviously don't need fixing.
_ANON_TAIL = (
    r'(?:\b(?:u8|s8|c8|u16|s16|u32|s32|u64|s64|f32|f64|bool|'
    r'int|char|float|double|short|long|unsigned|signed|void)\b'
    r'|\w+\s*[*&]+'
    r'|[*&]+)\s*[,)]'
)
_ANON_QUICK_RE = re.compile(r'::\w+\s*\([^)]*' + _ANON_TAIL)
_ANON_QUICK_HPP_RE = re.compile(r'\b\w+\s*\([^)]*' + _ANON_TAIL)


def has_anon_quick(text: str) -> bool:
    """Fast pre-check for anon params in a .cpp."""
    return bool(_ANON_QUICK_RE.search(text))


def has_anon_quick_hpp(text: str) -> bool:
    """Fast pre-check for anon params in a .hpp."""
    return bool(_ANON_QUICK_HPP_RE.search(text))


def _fix_text(text: str, fix_map: Dict[Tuple[str, int], Dict[int, str]],
              cls_filter: Optional[str], is_hpp: bool) -> Tuple[str, int]:
    """Replace anonymous param lists. Returns (new_text, fix_count)."""
    if is_hpp:
        fname_re = re.compile(r'(?<![:\w])(~?\w+)\s*\(')
    elif cls_filter:
        fname_re = re.compile(
            re.escape(cls_filter) + r'\s*::\s*(~?\w+)\s*\('
        )
    else:
        fname_re = re.compile(r'(?<![:\w])(\w+)\s*::\s*(~?\w+)\s*\(')

    result: List[str] = []
    pos = 0
    total = 0

    for m in fname_re.finditer(text):
        paren_start = text.index('(', m.start())
        if paren_start < pos:
            continue

        open_i, close_i = _find_param_block(text, paren_start)
        if close_i < 0:
            continue

        params_str = text[open_i + 1:close_i]

        if not _has_anon(params_str):
            continue

        pc = _count_params(params_str)
        method = m.group(1) if (is_hpp or cls_filter) else m.group(2)

        # Filter out keywords/type-tokens that look like method names
        # (e.g. 'return (s32)expr' would otherwise be treated as method
        # 'return' with anon param 's32' — that's a C-style cast, not a decl).
        if method in _SKIP_NAMES:
            continue

        key = (method.lower(), pc)

        # Try exact match first, then sentinel pc=-1 (used by _build_fix_map),
        # then pc=0 fallback. Empty pos_map is fine — _inject_names will use
        # Hungarian fallback for every position.
        pos_map = (fix_map.get(key)
                   or fix_map.get((method.lower(), -1))
                   or fix_map.get((method.lower(), 0))
                   or {})

        named = _inject_names(params_str, pos_map)
        if named == params_str:
            # Nothing changed (all already named somehow) — skip
            continue

        result.append(text[pos:open_i + 1])
        result.append(named)
        pos = close_i  # ')' will be copied from next segment start
        total += 1

    result.append(text[pos:])
    return ''.join(result), total


# ── Per-file driver ──────────────────────────────────────────────────────────

_CLS_RE = re.compile(r'(?:^|\s)([A-Za-z_]\w{2,})::\w+\s*\(', re.MULTILINE)
_NON_CLASS = frozenset({
    'if', 'for', 'while', 'switch', 'return', 'sizeof',
    'const', 'static', 'extern', 'inline', 'virtual',
    'void', 'int', 'char', 'float', 'double', 'short', 'long',
    'unsigned', 'signed', 'bool', 'true', 'false', 'nullptr',
    'std', 'this',
})

# Names that look like function names but are actually statements / casts /
# control flow. If the regex captures one of these as the "method name",
# skip — it's almost certainly an expression inside an inline body.
_SKIP_NAMES = _NON_CLASS | _TYPE_TOKENS | frozenset({
    'else', 'do', 'case', 'default', 'break', 'continue', 'goto',
    'typeof', 'alignof', 'static_cast', 'dynamic_cast',
    'const_cast', 'reinterpret_cast', 'typeid', 'new', 'delete',
    'throw', 'try', 'catch', 'NULL',
    'union', 'enum', 'namespace', 'using', 'typedef',
    'public', 'private', 'protected', 'friend',
    'mutable', 'volatile', 'register', 'auto',
    'template', 'typename', 'explicit', 'operator',
})


def extract_classes(text: str) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for m in _CLS_RE.finditer(text):
        cls = m.group(1)
        if cls in _NON_CLASS or cls in seen:
            continue
        seen.add(cls)
        out.append(cls)
    return out


# .hpp class declarations: `class clsFoo` / `struct stcBar` / `class clsFoo : public clsBase`
_HPP_CLS_RE = re.compile(r'\b(?:class|struct)\s+([A-Za-z_]\w{2,})\b', re.MULTILINE)


def extract_classes_hpp(text: str) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for m in _HPP_CLS_RE.finditer(text):
        cls = m.group(1)
        if cls in _NON_CLASS or cls in seen:
            continue
        seen.add(cls)
        out.append(cls)
    return out


def fix_file(cpp_path: str, dry_run: bool = False) -> Tuple[int, int]:
    if not os.path.exists(cpp_path):
        return 0, 0

    with open(cpp_path, encoding='utf-8', errors='replace') as f:
        cpp_text = f.read()

    # Derive .hpp path
    rel = os.path.relpath(cpp_path, ROOT_DIR)
    if rel.startswith('src' + os.sep):
        hpp_rel = 'include' + os.sep + rel[4:]
    else:
        hpp_rel = rel
    hpp_path = os.path.join(ROOT_DIR, os.path.splitext(hpp_rel)[0] + '.hpp')

    hpp_text: Optional[str] = None
    if os.path.exists(hpp_path):
        with open(hpp_path, encoding='utf-8', errors='replace') as f:
            hpp_text = f.read()

    cpp_anon = has_anon_quick(cpp_text)
    hpp_anon = bool(hpp_text and has_anon_quick_hpp(hpp_text))
    if not cpp_anon and not hpp_anon:
        return 0, 0

    # Pull class names from BOTH files so .hpp-only fixes work too
    class_names = extract_classes(cpp_text)
    if hpp_text:
        for cls in extract_classes_hpp(hpp_text):
            if cls not in class_names:
                class_names.append(cls)
    if not class_names:
        return 0, 0

    # Build fix map WITHOUT subprocess (use preloaded data).
    # We skip the demangling step here and rely solely on:
    #   method name (from mangled) + DWARF pos_map.
    # Param count matching uses the stub's own count.
    sym_idx = _load_sym_index()
    dwarf_idx = _load_dwarf_index()
    fix_map: Dict[Tuple[str, int], Dict[int, str]] = {}

    for cls in class_names:
        for mangled, addr in sym_idx.get(cls, []):
            method = _method_from_mangled(mangled, cls)
            addr_int = int(addr, 16)
            pos_map = dwarf_idx.get(addr_int, {})
            # Store with pc=ANY sentinel (-1); resolved at fix time by stub count
            key_any = (method.lower(), -1)
            if key_any not in fix_map:
                fix_map[key_any] = pos_map

    cpp_fixes = 0
    hpp_fixes = 0
    new_cpp = cpp_text
    new_hpp = hpp_text

    for cls in class_names:
        new_cpp, n = _fix_text(new_cpp, fix_map, cls_filter=cls, is_hpp=False)
        cpp_fixes += n

    if hpp_text is not None:
        new_hpp, hpp_fixes = _fix_text(new_hpp, fix_map, cls_filter=None, is_hpp=True)

    if not dry_run:
        if cpp_fixes and new_cpp != cpp_text:
            with open(cpp_path, 'w', encoding='utf-8') as f:
                f.write(new_cpp)
        if hpp_fixes and new_hpp is not None and new_hpp != hpp_text:
            with open(hpp_path, 'w', encoding='utf-8') as f:
                f.write(new_hpp)

    return cpp_fixes, hpp_fixes


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='*', help='.cpp files to fix')
    ap.add_argument('--all', action='store_true',
                    help='Scan all .cpp stubs under src/Develop')
    ap.add_argument('--dry-run', action='store_true',
                    help='Print fixes without writing files')
    args = ap.parse_args()

    if args.all:
        cpp_files: List[str] = []
        for root in _SRC_ROOTS:
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    if fn.endswith('.cpp'):
                        cpp_files.append(os.path.join(dirpath, fn))
    else:
        cpp_files = [os.path.abspath(p) for p in args.files]

    if not cpp_files:
        ap.error('Provide .cpp files or use --all')

    print(f"Loading symbol index...", flush=True)
    _load_sym_index()
    print(f"Loading DWARF function index...", flush=True)
    _load_dwarf_index()
    print(f"Scanning {len(cpp_files)} file(s)...", flush=True)

    total_cpp = total_hpp = 0
    changed: List[str] = []

    for cpp_path in sorted(cpp_files):
        cf, hf = fix_file(cpp_path, dry_run=args.dry_run)
        if cf or hf:
            rel = os.path.relpath(cpp_path, ROOT_DIR)
            tag = ' [DRY]' if args.dry_run else ''
            print(f"  {rel}: {cf} cpp, {hf} hpp{tag}")
            changed.append(rel)
            total_cpp += cf
            total_hpp += hf

    print(f"\nDone: {total_cpp} .cpp fix(es), {total_hpp} .hpp fix(es) across {len(changed)} file(s).")
    if args.dry_run:
        print("(dry-run — no files written)")


if __name__ == '__main__':
    main()
