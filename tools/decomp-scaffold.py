#!/usr/bin/env python3

"""
Scaffold context gatherer — collects DWARF, symbol, vtable, and dependency
information needed to write an accurate .hpp / .cpp stub for a new class.

Usage:
  python tools/decomp-scaffold.py -c ClassName
  python tools/decomp-scaffold.py -c ClassName --brief
  python tools/decomp-scaffold.py -c ClassName --no-line-lookup
  python tools/decomp-scaffold.py -c ClassName --deps-deep
  python tools/decomp-scaffold.py -c ClassName --enum enmStatus
"""

import argparse
import bisect
import re
import os
import subprocess
import sys
from typing import Dict, List, Optional, Tuple
from _common import (
    ROOT_DIR,
    # TOOLS_DIR,
    WorkflowError,
    demangle_symbol as _demangle_symbol,
    get_dwarf_params as _get_dwarf_params,
    grep_symbol_addrs as _grep_symbol_addrs_shared,
    print_section,
    python_tool,
    run_capture,
    run_stream,
    # tool_path,
)


_SR2_SYMBOLS = os.path.join(ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "symbol_addrs.txt")
# NOTE: Despite the "GC" prefix (a legacy naming artifact), this project is a
# PS2 decompilation — there is no GameCube build.  symbols/Dwarf contains the
# PS2 DWARF data extracted from the SLUS-21642-PROTO-070901 ELF.
GC_DWARF = os.path.join(ROOT_DIR, "symbols", "Dwarf")
RAW_DWARF_DUMP = os.path.join(ROOT_DIR, "symbols", "sr2_dwarfdump.nothpp")
DEBUG_LINES = os.path.join(ROOT_DIR, "symbols", "sr2_line_info.nothpp")
SONIC_YAML = os.path.join(ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "sonic.yaml")


def _find_enum_owners(enum_name: str) -> Dict[str, List[str]]:
    """Scan symbol_addrs.txt for Q2-mangled references to enum_name.

    Returns a dict mapping owner_name -> [mangled_symbol, ...].
    Owner may be a class (clsFoo), namespace (nspFoo), or any other identifier.
    Uses the MWCC mangling rule: Q2<N><Owner><M><EnumName>.
    Searches the entire symbol file, not just the current class's symbols.
    """
    owners: Dict[str, List[str]] = {}
    if not os.path.exists(_SR2_SYMBOLS):
        return owners
    n = len(enum_name)
    suffix = str(n) + enum_name
    pattern = re.compile(r"Q2(\d{1,3})([A-Za-z_]\w*)" + re.escape(suffix))
    with open(_SR2_SYMBOLS) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            mangled = stripped.split("=")[0].strip()
            for m in pattern.finditer(mangled):
                decl_len = int(m.group(1))
                owner = m.group(2)
                if len(owner) == decl_len:
                    owners.setdefault(owner, []).append(mangled)
    return owners


_re_enum_value_fp = re.compile(r"^\s+([A-Za-z_]\w*)\s*=\s*(-?\d+)", re.MULTILINE)


def _enum_value_fingerprint(block: str) -> frozenset:
    """Frozenset of 'NAME=value' tokens from an enum body string."""
    return frozenset(
        f"{m.group(1)}={m.group(2)}" for m in _re_enum_value_fp.finditer(block)
    )


def _find_enum_body_for_class(class_name: str, enum_name: str) -> Optional[str]:
    """Scan the raw DWARF dump to find which enum body belongs to class_name.

    Locates the first 'class/struct class_name {' definition whose body contains
    'enum enum_name ... offset' (i.e. actually has that field), then returns the
    first 'enum enum_name { ... }' block that appears after that definition closes.
    Returns the raw block text, or None if not found.
    """
    if not os.path.exists(RAW_DWARF_DUMP):
        return None
    class_re = re.compile(
        r"^(?:class|struct)\s+" + re.escape(class_name) + r"\s*(?::|{)"
    )
    member_ref_re = re.compile(
        r"\benum\s+" + re.escape(enum_name) + r"\b.*\boffset\b"
    )
    enum_start_re = re.compile(r"^enum\s+" + re.escape(enum_name) + r"\s*\{")

    # State machine:
    #   find_class  -> in_class (on matching class header)
    #   in_class    -> find_class (class closed, no member found)
    #              -> find_enum  (class closed, member found)
    #   find_enum   -> in_enum   (enum header found)
    #   in_enum     -> return body when braces close
    state = "find_class"
    brace_depth = 0
    has_member = False
    lines: List[str] = []
    enum_depth = 0

    with open(RAW_DWARF_DUMP) as f:
        for line in f:
            if state == "find_class":
                if class_re.match(line):
                    state = "in_class"
                    brace_depth = line.count("{") - line.count("}")
                    has_member = False

            elif state == "in_class":
                brace_depth += line.count("{") - line.count("}")
                if member_ref_re.search(line):
                    has_member = True
                if brace_depth <= 0:
                    state = "find_enum" if has_member else "find_class"

            elif state == "find_enum":
                if enum_start_re.match(line):
                    state = "in_enum"
                    enum_depth = line.count("{") - line.count("}")
                    lines = [line]

            elif state == "in_enum":
                lines.append(line)
                enum_depth += line.count("{") - line.count("}")
                if enum_depth <= 0:
                    return "".join(lines)

    return None


def _grep_symbol_addrs(class_name: str) -> Tuple[List[str], List[str]]:
    """Delegate to _common.grep_symbol_addrs (shared with stub_guard.py)."""
    return _grep_symbol_addrs_shared(class_name)


def _parse_length_prefixed_name(text: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"(?P<len>\d+)(?P<tail>.+)", text)
    if not m:
        return None
    length = int(m.group("len"))
    tail = m.group("tail")
    if len(tail) < length:
        return None
    return tail[:length], tail[length:]


def _parse_template_owner_symbol(mangled: str, class_name: str) -> Optional[Tuple[str, str, str]]:
    """Return (method_name, owner_name, suffix) for symbols owned by class_name<T...>."""
    mangled = re.sub(r"^(?:@\d+@)+", "", mangled)
    if mangled.startswith("__vt__"):
        return None

    special = re.match(r"__(?P<kind>ct|dt)__", mangled)
    if special:
        parsed = _parse_length_prefixed_name(mangled[special.end() :])
        if not parsed:
            return None
        owner_name, suffix = parsed
        method_name = class_name if special.group("kind") == "ct" else f"~{class_name}"
    else:
        if "__" not in mangled:
            return None
        method_name, rest = mangled.split("__", 1)
        if not method_name or method_name.startswith("_") or not re.match(r"^[A-Za-z_]\w*$", method_name):
            return None
        parsed = _parse_length_prefixed_name(rest)
        if not parsed:
            return None
        owner_name, suffix = parsed

    if not owner_name.startswith(f"{class_name}<") or not owner_name.endswith(">"):
        return None
    if not suffix.startswith(("F", "C")):
        return None
    return method_name, owner_name, suffix


def _grep_template_symbol_addrs(class_name: str) -> Tuple[List[str], List[str]]:
    """Return symbols owned by template instantiations of class_name<T...>."""
    non_weak: List[str] = []
    weak: List[str] = []
    if not os.path.exists(_SR2_SYMBOLS):
        return non_weak, weak
    with open(_SR2_SYMBOLS, encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or "=" not in stripped:
                continue
            mangled = stripped.split("=", 1)[0].strip()
            if not _parse_template_owner_symbol(mangled, class_name):
                continue
            if "visibility:weak" in stripped or "allow_duplicated:true" in stripped:
                weak.append(stripped)
            else:
                non_weak.append(stripped)
    return non_weak, weak


def _merge_symbol_lines(primary: List[str], extra: List[str]) -> List[str]:
    seen = set(primary)
    merged = list(primary)
    for line in extra:
        if line not in seen:
            seen.add(line)
            merged.append(line)
    return merged


def _dedupe_template_symbol_lines(symbol_lines: List[str], class_name: str) -> List[str]:
    """Collapse repeated template instantiations to one representative per method encoding."""
    result: List[str] = []
    seen_template_keys = set()
    for line in symbol_lines:
        mangled = line.split("=", 1)[0].strip()
        parsed = _parse_template_owner_symbol(mangled, class_name)
        if parsed:
            method_name, _owner_name, suffix = parsed
            key = (method_name, suffix)
            if key in seen_template_keys:
                continue
            seen_template_keys.add(key)
        result.append(line)
    return result


def _extract_first_address(symbol_lines: List[str]) -> Optional[str]:
    """Extract the hex address from the first symbol line."""
    addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
    for line in symbol_lines:
        m = addr_re.search(line)
        if m:
            return "0x" + m.group(1)
    return None


_LINE_INFO_CACHE: Optional[List[Tuple[int, int, str]]] = None  # [(addr, lineno, filepath)]


def _load_line_info() -> List[Tuple[int, int, str]]:
    """Parse DEBUG_LINES once into a sorted [(addr, lineno, filepath)] list."""
    global _LINE_INFO_CACHE
    if _LINE_INFO_CACHE is not None:
        return _LINE_INFO_CACHE
    entries: List[Tuple[int, int, str]] = []
    if not os.path.exists(DEBUG_LINES):
        _LINE_INFO_CACHE = entries
        return entries
    re_insn = re.compile(r'^\s+([0-9A-Fa-f]{5,})\s*:\t')
    re_src = re.compile(r'^\S[^\r\n]*:(\d+)\s*$')
    pending_line: Optional[str] = None
    pending_lineno: Optional[int] = None
    with open(DEBUG_LINES, 'r', errors='replace') as fh:
        for raw in fh:
            line = raw.rstrip('\n')
            m = re_src.match(line)
            if m:
                pending_line = line.rsplit(':', 1)[0]  # extract filepath
                pending_lineno = int(m.group(1))
                continue
            m = re_insn.match(line)
            if m and pending_lineno is not None:
                entries.append((int(m.group(1), 16), pending_lineno, pending_line or ""))
                pending_line = None
                pending_lineno = None
    _LINE_INFO_CACHE = entries
    return entries


_ADDR_RE_SYM = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")


def _parse_owner_from_mangled(name: str) -> Optional[str]:
    """Return the class owner encoded in a MWCC method symbol, if any."""
    if name.startswith("@") or "__vt__" in name:
        return None

    m = re.search(r"__(?:ct|dt)__(\d+)([A-Za-z_]\w*)F", name)
    if not m:
        m = re.search(r"__(\d+)([A-Za-z_]\w*)F", name)
    if not m:
        return None
    n = int(m.group(1))
    owner = m.group(2)[:n]
    return owner if len(owner) == n and "<" not in owner else None


def _extract_first_symbol(symbol_lines: List[str]) -> Optional[Tuple[str, int]]:
    """Extract (mangled_name, address) from the first symbol_addrs line."""
    for line in symbol_lines:
        m = _ADDR_RE_SYM.search(line)
        if not m or "=" not in line:
            continue
        mangled = line.split("=", 1)[0].strip()
        return mangled, int(m.group(1), 16)
    return None


def _source_file_for_function_label(addr: int, mangled: str, owner: str) -> Optional[str]:
    """Return the first source annotation inside the exact owned function block.

    Raw line info contains objdump function labels such as:
      00311bc0 <__dt__12clsGearEmDefFv>:

    Address-nearest lookup can be polluted by neighbouring functions or inline
    calls.  For scaffold ownership, anchor on the exact function label and only
    trust it if the mangled symbol's primary owner is the requested class.
    """
    if _parse_owner_from_mangled(mangled) != owner or not os.path.exists(DEBUG_LINES):
        return None

    label_re = re.compile(rf"^0*{addr:X}\s+<{re.escape(mangled)}>:", re.IGNORECASE)
    any_label_re = re.compile(r"^[0-9A-Fa-f]{5,}\s+<[^>]+>:")
    src_re = re.compile(r"^(\S[^\r\n]*):(\d+)\s*$")
    in_function = False

    with open(DEBUG_LINES, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not in_function:
                if label_re.match(line):
                    in_function = True
                continue

            if any_label_re.match(line):
                return None
            m = src_re.match(line)
            if m:
                return m.group(1)
    return None


def _addr_to_filepath(addr: int) -> Optional[str]:
    """Look up the source file path for a given virtual address using line info.

    Returns the Windows-style filepath (e.g. 'C:\\Develop\\...\\Foo.cpp') or None.
    """
    entries = _load_line_info()
    if not entries:
        return None
    addrs = [e[0] for e in entries]
    pos = bisect.bisect_left(addrs, addr)
    candidates = []
    if pos < len(entries):
        candidates.append(pos)
    if pos > 0:
        candidates.append(pos - 1)
    best = min(candidates, key=lambda i: abs(entries[i][0] - addr))
    if abs(entries[best][0] - addr) > 4:
        return None
    return entries[best][2] if entries[best][2] else None


def _sym_lineno(sym_line: str) -> int:
    """Return source line number for a symbol_addrs line, or maxint if unknown."""
    m = _ADDR_RE_SYM.search(sym_line)
    if not m:
        return 2**31
    addr = int(m.group(1), 16)
    entries = _load_line_info()
    if not entries:
        return 2**31
    addrs = [e[0] for e in entries]
    pos = bisect.bisect_left(addrs, addr)
    candidates = []
    if pos < len(entries):
        candidates.append(pos)
    if pos > 0:
        candidates.append(pos - 1)
    best = min(candidates, key=lambda i: abs(entries[i][0] - addr))
    if abs(entries[best][0] - addr) > 4:  # more than one MIPS instruction away
        return 2**31
    return entries[best][1]


def _get_sonic_yaml_entries(class_name: str) -> List[str]:
    """Find sonic.yaml segment lines that reference the class.

    Tries the full class name first, then the name with a leading 'cls' prefix
    stripped (since MWCC classes like clsMotion live in files named Motion).
    Only returns lines that look like segment entries (contain asmtu/src/h).
    """
    search_terms = [class_name]
    for prefix in ("cls", "Cls"):
        if class_name.lower().startswith(prefix.lower()) and len(class_name) > len(prefix):
            search_terms.append(class_name[len(prefix):])

    segment_re = re.compile(r"\b(asmtu|src|\.h)\b")
    entries: List[str] = []
    seen: set = set()
    if not os.path.exists(SONIC_YAML):
        return entries
    with open(SONIC_YAML) as f:
        for line in f:
            stripped = line.rstrip()
            if stripped in seen:
                continue
            if not segment_re.search(stripped):
                continue
            for term in search_terms:
                if f"/{term}" in stripped or f"/{term}]" in stripped:
                    seen.add(stripped)
                    entries.append(stripped)
                    break
    return entries


def _decode_float_values(addr_str: str, byte_count: int) -> Optional[List[float]]:
    """Read byte_count bytes from the ELF at addr_str and decode as little-endian IEEE 754 floats.

    Returns a list of float values (one per 4-byte word), or None on any failure.
    PS2 MIPS (R5900) is little-endian; standard IEEE 754 single precision.
    """
    if byte_count <= 0 or byte_count % 4 != 0:
        return None
    result = subprocess.run(
        python_tool("elf_lookup.py", addr_str, "--mode", "bytes", "--length", str(byte_count)),
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    hex_re = re.compile(r"\+0x[0-9A-Fa-f]+:\s+((?:[0-9A-Fa-f]{2}\s*)+)")
    raw_bytes: List[int] = []
    for line in result.stdout.splitlines():
        m = hex_re.search(line)
        if m:
            raw_bytes.extend(int(b, 16) for b in m.group(1).split())
    if len(raw_bytes) < byte_count:
        return None
    import struct
    floats = []
    for i in range(0, byte_count, 4):
        floats.append(struct.unpack("<f", bytes(raw_bytes[i : i + 4]))[0])
    return floats


def _decode_double_values(addr_str: str, byte_count: int) -> Optional[List[float]]:
    """Read byte_count bytes from the ELF and decode as little-endian IEEE 754 doubles."""
    if byte_count <= 0 or byte_count % 8 != 0:
        return None
    result = subprocess.run(
        python_tool("elf_lookup.py", addr_str, "--mode", "bytes", "--length", str(byte_count)),
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    hex_re = re.compile(r"\+0x[0-9A-Fa-f]+:\s+((?:[0-9A-Fa-f]{2}\s*)+)")
    raw_bytes: List[int] = []
    for line in result.stdout.splitlines():
        m = hex_re.search(line)
        if m:
            raw_bytes.extend(int(b, 16) for b in m.group(1).split())
    if len(raw_bytes) < byte_count:
        return None
    import struct
    doubles = []
    for i in range(0, byte_count, 8):
        doubles.append(struct.unpack("<d", bytes(raw_bytes[i : i + 8]))[0])
    return doubles


def _decode_int_values(
    addr_str: str, byte_count: int, element_size: int, signed: bool, is_bool: bool
) -> Optional[List]:
    """Read byte_count bytes from the ELF and decode as little-endian integers."""
    if byte_count <= 0 or byte_count % element_size != 0:
        return None
    result = subprocess.run(
        python_tool("elf_lookup.py", addr_str, "--mode", "bytes", "--length", str(byte_count)),
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    hex_re = re.compile(r"\+0x[0-9A-Fa-f]+:\s+((?:[0-9A-Fa-f]{2}\s*)+)")
    raw_bytes: List[int] = []
    for line in result.stdout.splitlines():
        m = hex_re.search(line)
        if m:
            raw_bytes.extend(int(b, 16) for b in m.group(1).split())
    if len(raw_bytes) < byte_count:
        return None
    import struct
    fmt_map = {(1, False): "B", (1, True): "b", (2, False): "H", (2, True): "h",
               (4, False): "I", (4, True): "i", (8, False): "Q", (8, True): "q"}
    fmt = fmt_map.get((element_size, signed))
    if fmt is None:
        return None
    values = []
    for i in range(0, byte_count, element_size):
        v = struct.unpack("<" + fmt, bytes(raw_bytes[i : i + element_size]))[0]
        if is_bool:
            values.append(True if v else False)
        else:
            values.append(v)
    return values


def _format_int_value(v) -> str:
    """Format an integer static value: decimal primary, hex hint in comment for large values.

    bool -> 'true'/'false'
    small (abs < 256) -> plain decimal
    large -> 'decimal  /* 0xHEX */'
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if abs(v) < 256:
        return str(v)
    return f"{v}  /* {hex(v).upper().replace('X', 'x')} */"


def _format_double_literal(val: float) -> str:
    """Format a double as a C double literal with enough precision to round-trip."""
    import struct
    for digits in range(15, 18):
        s = f"{val:.{digits}g}"
        if struct.pack("<d", float(s)) == struct.pack("<d", val):
            break
    if "." not in s and "e" not in s:
        s += ".0"
    return s


def _format_float_literal(val: float) -> str:
    """Format a float as a C float literal with enough precision to round-trip."""
    import struct
    for digits in range(6, 10):
        s = f"{val:.{digits}g}"
        if struct.pack("<f", float(s)) == struct.pack("<f", val):
            break
    if "." not in s and "e" not in s:
        s += ".0"
    return s + "f"


def _find_fraction(val: float):
    """Try to find p/q (small integers, q <= 1000) such that p/q compiles to the same
    IEEE 754 single-precision bits as val.  Returns (p, q) in lowest terms, or None."""
    import struct
    from math import gcd
    target = struct.pack("<f", val)
    for q in range(1, 1001):
        p = round(val * q)
        if p == 0:
            continue
        try:
            if struct.pack("<f", float(p) / float(q)) == target:
                g = gcd(abs(p), q)
                return p // g, q // g
        except (OverflowError, ZeroDivisionError):
            pass
    return None


def _scaffold_float_display(val: float):
    """Return (code_form, raw_comment_or_None) for a float static initializer.

    When a clean fraction p/q exists and the raw decimal is long (>=6 sig-figs),
    code_form is 'p.0f / q.0f' and raw_comment is the raw decimal literal.
    Otherwise code_form is the raw decimal and raw_comment is None.
    """
    raw = _format_float_literal(val)
    # Count significant digits in the raw form (ignore sign, decimal point, trailing 'f').
    sig = raw.lstrip("-").replace(".", "").rstrip("f").lstrip("0")
    if len(sig) >= 5:
        frac = _find_fraction(val)
        if frac is not None:
            p, q = frac
            if q > 1:
                p_str = f"{float(p):.0f}" if float(p) == int(p) else str(float(p))
                q_str = f"{float(q):.0f}" if float(q) == int(q) else str(float(q))
                return f"{p_str}.0f / {q_str}.0f", raw
    return raw, None


_INCLUDE_PREFIX_RE = re.compile(
    r"include[/\\](Develop[/\\]Projects[/\\]SR2[/\\]pgm[/\\].*\.hpp)",
    re.IGNORECASE,
)


def _extract_include_path(stdout: str) -> Optional[str]:
    """Return the first full-definition #include path from find-symbol.py output.

    Skips headers where the type is only forward-declared (no '{' or ': public'
    appears in the output alongside that header).
    """
    # Collect all .hpp paths and check if any line has a full definition marker.
    found_path: Optional[str] = None
    has_full_def = False
    for line in stdout.splitlines():
        if "forward decl" in line:
            continue
        if found_path and re.search(r"\{|:\s*public\b|:\s*private\b|:\s*protected\b", line):
            has_full_def = True
        m = _INCLUDE_PREFIX_RE.search(line)
        if m and found_path is None:
            found_path = m.group(1).replace("\\", "/")
    return found_path if (found_path and has_full_def) else None


def _parse_base_classes(struct_output: str) -> List[str]:
    """Extract base class names from the struct/class header line."""
    for line in struct_output.splitlines():
        stripped = line.strip()
        # Must start with struct/class, but must NOT be a member declaration
        # Member declarations have ';' before '{' (e.g. "class Foo * member; // size: ...")
        # Class definitions have '{' at the end (with optional ':' for inheritance)
        if not re.match(r"(?:struct|class)\s+\w+", stripped):
            continue
        brace_idx = stripped.find("{")
        if brace_idx < 0:
            continue
        # Reject lines with ';' before '{' — these are member declarations
        semicolon_idx = stripped.find(";")
        if 0 <= semicolon_idx < brace_idx:
            continue
        # Must have ':' for inheritance (otherwise no base classes to extract)
        colon_idx = stripped.find(":")
        if colon_idx < 0 or colon_idx > brace_idx:
            continue
        inheritance = stripped[colon_idx + 1 : brace_idx].strip()
        bases: List[str] = []
        for part in inheritance.split(","):
            for w in part.strip().split():
                if w not in ("public", "private", "protected", "virtual"):
                    if re.match(r"^\w+$", w):
                        bases.append(w)
                    break
        return bases
    return []


def _read_raw_bytes(addr_str: str, byte_count: int) -> Optional[List[int]]:
    """Read byte_count bytes from the ELF at addr_str. Returns list of ints or None."""
    result = subprocess.run(
        python_tool("elf_lookup.py", addr_str, "--mode", "bytes", "--length", str(byte_count)),
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    hex_re = re.compile(r"\+0x[0-9A-Fa-f]+:\s+((?:[0-9A-Fa-f]{2}\s*)+)")
    raw: List[int] = []
    for line in result.stdout.splitlines():
        m = hex_re.search(line)
        if m:
            raw.extend(int(b, 16) for b in m.group(1).split())
    return raw if len(raw) >= byte_count else None


def _parse_size8_asm_hint(sym_line: str, struct_output: str) -> Optional[str]:
    """Parse an 8-byte MIPS function body and return a likely C++ hint string.

    PS2 MIPS size-8 = exactly 2 instructions.  The compiler uses the jr-ra delay
    slot to do the actual work, so the canonical layout is:
        instr[0]  jr    ra
        instr[1]  <load or addiu>   ← delay slot

    Recognised patterns (rs=a0 = 'this'):
        lw   v0, offset(a0)   →  return member;
        lwc1 ft, offset(a0)   →  return float_member;
        lhu  v0, offset(a0)   →  return member;   (unsigned short)
        lbu  v0, offset(a0)   →  return member;   (unsigned byte)
        addiu v0, a0, offset  →  return &member;

    Returns a hint string like 'return m_field;' or a generic offset comment,
    or None if the pattern is unrecognised.
    """
    import struct as _struct

    addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
    m = addr_re.search(sym_line)
    if not m:
        return None

    raw = _read_raw_bytes("0x" + m.group(1), 8)
    if not raw:
        return None

    instr0 = _struct.unpack("<I", bytes(raw[0:4]))[0]
    instr1 = _struct.unpack("<I", bytes(raw[4:8]))[0]

    JR_RA = 0x03E00008  # jr ra encodes as this exact word

    if instr0 == JR_RA and instr1 == 0:
        return "{ }  // empty body"
    MOV_S_F0_F12 = 0x46006006
    if instr0 == JR_RA and instr1 == MOV_S_F0_F12:
        return "return param;"

    # addiu v0, zero, N  (opcode=0x09, rs=0, rt=2) — integer constant return
    # also handles: or v0, zero, zero  (0x00001025) — return 0
    if instr0 == JR_RA:
        _op1 = (instr1 >> 26) & 0x3F
        _rs1 = (instr1 >> 21) & 0x1F
        _rt1 = (instr1 >> 16) & 0x1F
        if _op1 == 0x09 and _rs1 == 0 and _rt1 == 2:
            n = instr1 & 0xFFFF
            if n >= 0x8000:
                n -= 0x10000
            return f"return {n};"
        if instr1 == 0x00001025:  # or v0, zero, zero
            return "return 0;"

    def _load_info(instr: int) -> Optional[Tuple[int, str]]:
        """Return (byte_offset, kind) if instr is a load/addiu from a0, else None.

        kind is one of: 'word', 'float', 'addr'.
        """
        opcode = (instr >> 26) & 0x3F
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000:
            imm -= 0x10000  # sign-extend 16-bit immediate
        if rs != 4:  # a0 is register 4 — the 'this' pointer
            return None
        if opcode == 0x23 and rt == 2:   # lw v0, offset(a0)
            return (imm, "word")
        if opcode == 0x31:               # lwc1 ft, offset(a0) — any float reg
            return (imm, "float")
        if opcode == 0x09 and rt == 2:   # addiu v0, a0, offset
            return (imm, "addr")
        if opcode == 0x25 and rt == 2:   # lhu v0, offset(a0)
            return (imm, "word")
        if opcode == 0x24 and rt == 2:   # lbu v0, offset(a0)
            return (imm, "word")
        return None

    def _store_info(instr: int) -> Optional[Tuple[int, str]]:
        """Return (byte_offset, kind) if instr is a store to (a0) from a1, $zero, or a float reg.

        Recognised patterns (rs=a0 = 'this', a1 = first param):
            sw   a1,   offset(a0)   opcode=0x2B, rs=4, rt=5
            sw   $zero,offset(a0)   opcode=0x2B, rs=4, rt=0  → kind="null"
            swc1 ft,   offset(a0)   opcode=0x39, rs=4        (float — any ft)
            sh   a1,   offset(a0)   opcode=0x29, rs=4, rt=5
            sh   $zero,offset(a0)   opcode=0x29, rs=4, rt=0  → kind="null"
            sb   a1,   offset(a0)   opcode=0x28, rs=4, rt=5
            sb   $zero,offset(a0)   opcode=0x28, rs=4, rt=0  → kind="null"
        """
        opcode = (instr >> 26) & 0x3F
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000:
            imm -= 0x10000
        if rs != 4:
            return None
        if opcode == 0x2B and rt == 5:   # sw a1, offset(a0)
            return (imm, "word")
        if opcode == 0x2B and rt == 0:   # sw $zero, offset(a0)
            return (imm, "null")
        if opcode == 0x39:               # swc1 ft, offset(a0) — any float reg
            return (imm, "float")
        if opcode == 0x29 and rt == 5:   # sh a1, offset(a0)
            return (imm, "hword")
        if opcode == 0x29 and rt == 0:   # sh $zero, offset(a0)
            return (imm, "null")
        if opcode == 0x28 and rt == 5:   # sb a1, offset(a0)
            return (imm, "byte")
        if opcode == 0x28 and rt == 0:   # sb $zero, offset(a0)
            return (imm, "null")
        return None

    info = None
    store = None
    if instr0 == JR_RA:       # most common: jr ra then delay-slot work
        info = _load_info(instr1)
        if info is None:
            store = _store_info(instr1)
    elif instr1 == JR_RA:     # less common: work then jr ra (nop delay slot not counted)
        info = _load_info(instr0)
        if info is None:
            store = _store_info(instr0)

    if info is None and store is None:
        return None

    # Parse member lines: TYPE m_name; // offset 0xXX, size 0xYY
    member_re = re.compile(
        r"^\s+(.+?)\s+(\w+)\s*;.*//\s*offset\s+(0x[0-9A-Fa-f]+),\s*size\s+(0x[0-9A-Fa-f]+)"
    )
    members = []
    for line in struct_output.splitlines():
        mobj = member_re.match(line)
        if mobj:
            members.append((
                mobj.group(1).strip(),   # type string
                mobj.group(2),           # member name
                int(mobj.group(3), 16),  # offset
                int(mobj.group(4), 16),  # size
            ))

    # Setter path — resolve store offset against struct members
    if store is not None:
        store_offset, store_kind = store
        if store_kind == "null":
            # sw/sh/sb $zero — zero or null assignment
            for type_str, name, moff, _ in members:
                if moff == store_offset:
                    rhs = "nullptr" if "*" in type_str else "0"
                    return f"{name} = {rhs};"
            return f"/* this[+0x{store_offset:X}] — likely inherited field */ = 0;"
        param_name = "f32Param" if store_kind == "float" else "param"
        for _, name, moff, _ in members:
            if moff == store_offset:
                return f"{name} = {param_name};"
        for type_str, name, moff, msize in members:
            if moff <= store_offset < moff + msize:
                rel = store_offset - moff
                bare_type = re.sub(r"\b(?:class|struct|const)\b", "", type_str).replace("*", "").strip()
                try:
                    nested_result = run_capture(
                        python_tool("lookup.py", GC_DWARF, "struct", bare_type)
                    )
                    nested_re = re.compile(r"^\s+.+?\s+(\w+)\s*;.*//\s*offset\s+(0x[0-9A-Fa-f]+)")
                    for nline in nested_result.stdout.splitlines():
                        nmobj = nested_re.match(nline)
                        if nmobj and int(nmobj.group(2), 16) == rel:
                            return f"{name}.{nmobj.group(1)} = {param_name};"
                    return f"/* {name}.? (+0x{rel:X} within {bare_type}) */ = {param_name};"
                except WorkflowError:
                    return f"/* {name}.? (+0x{rel:X}) */ = {param_name};"
        return f"/* this[+0x{store_offset:X}] — likely inherited field */ = {param_name};"

    offset, kind = info

    # Pass 1: direct offset match
    for type_str, name, moff, _ in members:
        if moff == offset:
            return f"return &{name};" if kind == "addr" else f"return {name};"

    # Pass 2: offset falls inside a composite member — resolve one level deeper
    for type_str, name, moff, msize in members:
        if moff <= offset < moff + msize:
            rel = offset - moff
            # Extract bare type name (strip class/struct keyword and pointer markers)
            bare_type = re.sub(r"\b(?:class|struct|const)\b", "", type_str).replace("*", "").strip()
            try:
                nested_result = run_capture(
                    python_tool("lookup.py", GC_DWARF, "struct", bare_type)
                )
                nested_re = re.compile(r"^\s+.+?\s+(\w+)\s*;.*//\s*offset\s+(0x[0-9A-Fa-f]+)")
                for nline in nested_result.stdout.splitlines():
                    nmobj = nested_re.match(nline)
                    if nmobj and int(nmobj.group(2), 16) == rel:
                        nested_name = nmobj.group(1)
                        if kind == "addr":
                            return f"return &{name}.{nested_name};"
                        return f"return {name}.{nested_name};"
                # Type found but field not at that relative offset
                if kind == "addr":
                    return f"return /* &{name}.? (+0x{rel:X} within {bare_type}) */;"
                return f"return /* {name}.? (+0x{rel:X} within {bare_type}) */;"
            except WorkflowError:
                return f"return /* {name}.? (+0x{rel:X}) */;"

    # Pass 3: truly unknown offset (base class field not reflected in struct output)
    if kind == "addr":
        return f"return /* &this[+0x{offset:X}] — likely inherited field */;"
    if kind == "float":
        return f"return /* float this[+0x{offset:X}] — likely inherited field */;"
    return f"return /* this[+0x{offset:X}] — likely inherited field */;"


def _parse_size12_asm_hint(sym_line: str, struct_output: str) -> Optional[str]:
    """Parse a 12-byte MIPS function body for the two-hop pointer dereference pattern.

    Handles:  return m_pcPtr->field;

    Assembly layout (3 instructions; instr[2] is the jr-ra delay slot):
        [0] lw   v0, ptrOffset(a0)    load pointer member from 'this'
        [1] jr   ra
        [2] lw   v0, fieldOffset(v0)  delay slot: load field through pointer

    Also handles lwc1 in position 2 for float fields through a pointer.
    Falls back to a generic offset comment if the field cannot be resolved.
    """
    import struct as _struct

    addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
    m = addr_re.search(sym_line)
    if not m:
        return None

    raw = _read_raw_bytes("0x" + m.group(1), 12)
    if not raw:
        return None

    instr0 = _struct.unpack("<I", bytes(raw[0:4]))[0]
    instr1 = _struct.unpack("<I", bytes(raw[4:8]))[0]
    instr2 = _struct.unpack("<I", bytes(raw[8:12]))[0]

    JR_RA = 0x03E00008
    if instr1 != JR_RA:
        return None

    # Pattern: lui v0, HI / jr ra / lw v0, LO(v0) — global variable / singleton return
    # Reconstruct the global address from the lui+lw immediate pair, look it up in
    # symbol_addrs.txt, and emit the variable name.
    _op0 = (instr0 >> 26) & 0x3F
    _rt0 = (instr0 >> 16) & 0x1F
    _op2 = (instr2 >> 26) & 0x3F
    _rs2 = (instr2 >> 21) & 0x1F
    _rt2 = (instr2 >> 16) & 0x1F
    if _op0 == 0x0F and _rt0 == 2 and _op2 == 0x23 and _rs2 == 2 and _rt2 == 2:
        hi = instr0 & 0xFFFF
        lo = instr2 & 0xFFFF
        if lo >= 0x8000:
            lo -= 0x10000
        global_addr = ((hi << 16) + lo) & 0xFFFFFFFF
        # Search symbol_addrs.txt for a symbol at this address
        _sym_name: Optional[str] = None
        if os.path.exists(_SR2_SYMBOLS):
            _addr_pat = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
            with open(_SR2_SYMBOLS) as _sf:
                for _line in _sf:
                    _lm = _addr_pat.search(_line)
                    if _lm and int(_lm.group(1), 16) == global_addr:
                        _sym_name = _line.split("=")[0].strip()
                        break
        if _sym_name:
            _demangled = _demangle_symbol(_sym_name)
            # Use bare variable name (last :: segment) for a clean hint
            if _demangled and "::" in _demangled:
                _bare = _demangled.rsplit("::", 1)[-1]
            elif _demangled:
                _bare = _demangled
            else:
                _bare = _sym_name
            return f"return {_bare};"
        return f"return /* global @ 0x{global_addr:08X} */;"

    def _lw_v0_from_a0(instr: int) -> Optional[int]:
        opcode = (instr >> 26) & 0x3F
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000:
            imm -= 0x10000
        if opcode == 0x23 and rs == 4 and rt == 2:
            return imm
        return None

    def _load_from_v0(instr: int) -> Optional[Tuple[int, str]]:
        opcode = (instr >> 26) & 0x3F
        rs = (instr >> 21) & 0x1F
        rt = (instr >> 16) & 0x1F
        imm = instr & 0xFFFF
        if imm >= 0x8000:
            imm -= 0x10000
        if rs != 2:
            return None
        if opcode == 0x23 and rt == 2:
            return (imm, "word")
        if opcode == 0x31:
            return (imm, "float")
        if opcode == 0x25 and rt == 2:
            return (imm, "word")
        if opcode == 0x24 and rt == 2:
            return (imm, "word")
        return None

    ptr_offset = _lw_v0_from_a0(instr0)
    if ptr_offset is None:
        return None

    field_info = _load_from_v0(instr2)
    if field_info is None:
        return None

    field_offset, kind = field_info

    member_re = re.compile(
        r"^\s+(.+?)\s+(\w+)\s*;.*//\s*offset\s+(0x[0-9A-Fa-f]+),\s*size\s+(0x[0-9A-Fa-f]+)"
    )
    ptr_member_name: Optional[str] = None
    ptr_member_type: Optional[str] = None
    for line in struct_output.splitlines():
        mobj = member_re.match(line)
        if mobj and int(mobj.group(3), 16) == ptr_offset:
            ptr_member_type = mobj.group(1).strip()
            ptr_member_name = mobj.group(2)
            break

    if ptr_member_name is None:
        kind_prefix = "float " if kind == "float" else ""
        return (
            f"return /* {kind_prefix}this[+0x{ptr_offset:X}]->? "
            f"(+0x{field_offset:X}) — ptr not in struct */;"
        )

    is_ref = "&" in (ptr_member_type or "")
    access_op = "." if is_ref else "->"
    pointed_type = (
        re.sub(r"\b(?:class|struct|const)\b", "", ptr_member_type or "")
        .replace("*", "")
        .replace("&", "")
        .strip()
    )
    try:
        nested_result = run_capture(python_tool("lookup.py", GC_DWARF, "struct", pointed_type))
        nested_re = re.compile(r"^\s+.+?\s+(\w+)\s*;.*//\s*offset\s+(0x[0-9A-Fa-f]+)")
        for nline in nested_result.stdout.splitlines():
            nmobj = nested_re.match(nline)
            if nmobj and int(nmobj.group(2), 16) == field_offset:
                return f"return {ptr_member_name}{access_op}{nmobj.group(1)};"
        return f"return /* {ptr_member_name}{access_op}? (+0x{field_offset:X} within {pointed_type}) */;"
    except WorkflowError:
        return f"return /* {ptr_member_name}{access_op}? (+0x{field_offset:X}) */;"


def _parse_size16_asm_hint(sym_line: str, struct_output: str) -> Optional[str]:
    """Parse a 16-byte MIPS function body (4 instructions) and return a C++ hint.

    Recognised patterns (all with jr ra as instr[2], delay slot as instr[3]):

    A — Equality boolean:
        load  v0, off(a0)          rs=4, rt=2
        xori  v0, v0, N            opcode=0x0E rs=2 rt=2        (or xor v0,v0,zero for N=0)
        jr    ra
        sltiu v0, v0, 1            opcode=0x0B rs=2 rt=2 imm=1
      → return m_field == N;

    B — Flag-test boolean:
        load  v0, off(a0)          rs=4, rt=2
        and   v0, v0, a1           opcode=0 func=0x24 rd=2 rs=2 rt=5
        jr    ra
        sltu  v0, zero, v0         opcode=0 func=0x2B rd=2 rs=0 rt=2
      → return (m_field & param) != 0;

    C — Increment-store:
        lbu/lhu/lw  v1, off(a0)    rs=4, rt=3
        addiu       v1, v1, 1      opcode=0x09 rs=3 rt=3 imm=1
        jr          ra
        sb/sh/sw    v1, off(a0)    same offset as load, rt=3
      → m_field++;
    """
    import struct as _struct

    addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
    m = addr_re.search(sym_line)
    if not m:
        return None
    raw = _read_raw_bytes("0x" + m.group(1), 16)
    if not raw:
        return None

    w = [_struct.unpack("<I", bytes(raw[i : i + 4]))[0] for i in range(0, 16, 4)]
    JR_RA = 0x03E00008
    if w[2] != JR_RA:
        return None

    def _op(instr): return (instr >> 26) & 0x3F
    def _rs(instr): return (instr >> 21) & 0x1F
    def _rt(instr): return (instr >> 16) & 0x1F
    def _rd(instr): return (instr >> 11) & 0x1F
    def _func(instr): return instr & 0x3F

    def _simm(instr):
        v = instr & 0xFFFF
        return v - 0x10000 if v >= 0x8000 else v

    # Member lookup helper (shared with size:8)
    member_re = re.compile(
        r"^\s+(.+?)\s+(\w+)\s*;.*//\s*offset\s+(0x[0-9A-Fa-f]+),\s*size\s+(0x[0-9A-Fa-f]+)"
    )
    members = [
        (mobj.group(1).strip(), mobj.group(2), int(mobj.group(3), 16), int(mobj.group(4), 16))
        for line in struct_output.splitlines()
        for mobj in [member_re.match(line)]
        if mobj
    ]

    def _resolve_offset(offset):
        for _, name, moff, _ in members:
            if moff == offset:
                return name
        return None

    # Pattern A — equality boolean
    # instr[0]: load v0, off(a0)  (rs=4, rt=2, any load opcode)
    # instr[1]: xori v0,v0,N  OR  xor v0,v0,zero
    # instr[3]: sltiu v0, v0, 1
    _LOAD_OPCODES = {0x23, 0x25, 0x24, 0x21, 0x20}
    if (
        _op(w[0]) in _LOAD_OPCODES and _rs(w[0]) == 4 and _rt(w[0]) == 2
        and _op(w[3]) == 0x0B and _rs(w[3]) == 2 and _rt(w[3]) == 2 and (w[3] & 0xFFFF) == 1
    ):
        xor_val: Optional[int] = None
        if _op(w[1]) == 0x0E and _rs(w[1]) == 2 and _rt(w[1]) == 2:   # xori
            xor_val = w[1] & 0xFFFF
        elif w[1] == 0x00401026:  # xor v0, v0, zero  (exact encoding)
            xor_val = 0
        if xor_val is not None:
            offset = _simm(w[0])
            name = _resolve_offset(offset)
            field = name if name else f"/* this[+0x{offset:X}] */"
            return f"return {field} == {xor_val};"

    # Pattern B — flag-test boolean
    # instr[0]: load v0, off(a0)  (rs=4, rt=2)
    # instr[1]: and v0, v0, a1   opcode=0 func=0x24 rd=2 rs=2 rt=5
    # instr[3]: sltu v0, zero, v0  opcode=0 func=0x2B rd=2 rs=0 rt=2
    _AND_V0_V0_A1 = (0 << 26) | (2 << 21) | (5 << 16) | (2 << 11) | 0x24
    _SLTU_V0_0_V0 = (0 << 26) | (0 << 21) | (2 << 16) | (2 << 11) | 0x2B
    if (
        _op(w[0]) in _LOAD_OPCODES and _rs(w[0]) == 4 and _rt(w[0]) == 2
        and w[1] == _AND_V0_V0_A1
        and w[3] == _SLTU_V0_0_V0
    ):
        offset = _simm(w[0])
        name = _resolve_offset(offset)
        field = name if name else f"/* this[+0x{offset:X}] */"
        return f"return ({field} & param) != 0;"

    # Pattern C — increment/decrement-store  (rt=3 = v1 throughout)
    # instr[0]: lbu/lhu/lw v1, off(a0)   rs=4, rt=3
    # instr[1]: addiu v1, v1, ±1          opcode=0x09 rs=3 rt=3 imm=±1
    # instr[3]: sb/sh/sw v1, off(a0)     rs=4, rt=3, same offset
    _LOAD_STORE_PAIRS = {0x24: 0x28, 0x25: 0x29, 0x23: 0x2B}
    if (
        _op(w[0]) in _LOAD_STORE_PAIRS and _rs(w[0]) == 4 and _rt(w[0]) == 3
        and _op(w[1]) == 0x09 and _rs(w[1]) == 3 and _rt(w[1]) == 3
        and abs(_simm(w[1])) == 1
        and _op(w[3]) == _LOAD_STORE_PAIRS[_op(w[0])] and _rs(w[3]) == 4 and _rt(w[3]) == 3
        and _simm(w[0]) == _simm(w[3])
    ):
        offset = _simm(w[0])
        name = _resolve_offset(offset)
        field = name if name else f"/* this[+0x{offset:X}] */"
        op = "++" if _simm(w[1]) == 1 else "--"
        return f"{field}{op};"

    # Pattern D — or-setter / Pattern E — and-clear setter  (rt=3 = v1 throughout)
    # instr[0]: lbu/lhu/lw v1, off(a0)   rs=4, rt=3
    # instr[1]: or/and v1, v1, a1         opcode=0 func=0x25/0x24 rd=3 rs=3 rt=5
    # instr[3]: sb/sh/sw v1, off(a0)      same offset, rt=3
    if (
        _op(w[0]) in _LOAD_STORE_PAIRS and _rs(w[0]) == 4 and _rt(w[0]) == 3
        and _op(w[1]) == 0 and _rd(w[1]) == 3 and _rs(w[1]) == 3 and _rt(w[1]) == 5
        and _func(w[1]) in (0x24, 0x25)
        and _op(w[3]) == _LOAD_STORE_PAIRS[_op(w[0])] and _rs(w[3]) == 4 and _rt(w[3]) == 3
        and _simm(w[0]) == _simm(w[3])
    ):
        offset = _simm(w[0])
        name = _resolve_offset(offset)
        field = name if name else f"/* this[+0x{offset:X}] */"
        op_str = "|=" if _func(w[1]) == 0x25 else "&="
        return f"{field} {op_str} param;"

    # Pattern F — float constant return
    # instr[0]: lui v0, HI(float_bits)   opcode=0x0F rt=2
    # instr[1]: mtc1 v0, f0              COP1/MT: opcode=0x11 rs=4 rt=2 rd=0
    # instr[3]: nop
    if (
        _op(w[0]) == 0x0F and _rt(w[0]) == 2
        and (w[1] >> 26) & 0x3F == 0x11 and (w[1] >> 21) & 0x1F == 4
        and w[3] == 0
    ):
        hi_bits = (w[0] & 0xFFFF) << 16
        val = _struct.unpack("<f", _struct.pack("<I", hi_bits))[0]
        return f"return {_format_float_literal(val)};"

    return None


def _parse_size20_asm_hint(sym_line: str, struct_output: str) -> Optional[str]:
    """Parse a 20-byte MIPS function body (5 instructions) and return a C++ hint.

    Recognised patterns (jr ra at instr[3], delay slot at instr[4]):

    A — Read-add-write with parameter:
        lbu/lhu/lw  v1, off(a0)     rs=4, rt=3
        [andi a1, a1, mask]          optional — opcode=0x0C rs=5 rt=5
        addu        v1, v1, a1      opcode=0 func=0x21 rd=3 rs=3 rt=5
        jr          ra
        sb/sh/sw    v1, off(a0)     same offset as load, rt=3
      → m_field += param;

    B — Read-sub-write with parameter:
        same but subu (func=0x23) instead of addu
      → m_field -= param;
    """
    import struct as _struct

    addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
    m = addr_re.search(sym_line)
    if not m:
        return None
    raw = _read_raw_bytes("0x" + m.group(1), 20)
    if not raw:
        return None

    w = [_struct.unpack("<I", bytes(raw[i : i + 4]))[0] for i in range(0, 20, 4)]
    JR_RA = 0x03E00008

    def _op(instr): return (instr >> 26) & 0x3F
    def _rs(instr): return (instr >> 21) & 0x1F
    def _rt(instr): return (instr >> 16) & 0x1F
    def _rd(instr): return (instr >> 11) & 0x1F
    def _func(instr): return instr & 0x3F

    def _simm(instr):
        v = instr & 0xFFFF
        return v - 0x10000 if v >= 0x8000 else v

    member_re = re.compile(
        r"^\s+(.+?)\s+(\w+)\s*;.*//\s*offset\s+(0x[0-9A-Fa-f]+),\s*size\s+(0x[0-9A-Fa-f]+)"
    )
    members = [
        (mobj.group(1).strip(), mobj.group(2), int(mobj.group(3), 16), int(mobj.group(4), 16))
        for line in struct_output.splitlines()
        for mobj in [member_re.match(line)]
        if mobj
    ]

    def _resolve_offset(offset):
        for _, name, moff, _ in members:
            if moff == offset:
                return name
        return None

    _LOAD_STORE_PAIRS = {0x24: 0x28, 0x25: 0x29, 0x23: 0x2B}

    # Pattern A/B variant 1: load(rt=3), [andi a1,a1,mask], addu/subu(rd=3,rs=3,rt=5), jr, store(rt=3)
    for skip_andi in (False, True):
        if skip_andi:
            # Layout: load, andi, addu/subu, jr, store
            if w[3] != JR_RA:
                continue
            i_load, i_op, i_store = 0, 2, 4
            if not (_op(w[1]) == 0x0C and _rs(w[1]) == 5 and _rt(w[1]) == 5):
                continue
        else:
            # Layout: load, addu/subu, jr, store, (nop)
            if w[2] != JR_RA:
                continue
            i_load, i_op, i_store = 0, 1, 3

        load_instr = w[i_load]
        op_instr = w[i_op]
        store_instr = w[i_store]

        if not (_op(load_instr) in _LOAD_STORE_PAIRS and _rs(load_instr) == 4 and _rt(load_instr) == 3):
            continue
        if not (_op(store_instr) == _LOAD_STORE_PAIRS[_op(load_instr)] and _rs(store_instr) == 4 and _rt(store_instr) == 3):
            continue
        if _simm(load_instr) != _simm(store_instr):
            continue

        is_add = _op(op_instr) == 0 and _func(op_instr) == 0x21 and _rd(op_instr) == 3 and _rs(op_instr) == 3 and _rt(op_instr) == 5
        is_sub = _op(op_instr) == 0 and _func(op_instr) == 0x23 and _rd(op_instr) == 3 and _rs(op_instr) == 3 and _rt(op_instr) == 5
        if not (is_add or is_sub):
            continue

        offset = _simm(load_instr)
        name = _resolve_offset(offset)
        field = name if name else f"/* this[+0x{offset:X}] */"
        op_str = "+=" if is_add else "-="
        return f"{field} {op_str} param;"

    # Pattern B variant 2 (sub with reversed regs): andi(v1,a1,mask), load(a1,off(a0)), subu(v1,a1,v1), jr, store(v1,off(a0))
    # e.g. subMode(Ui): andi v1,a1,0xFF / lbu a1,off(a0) / subu v1,a1,v1 / jr ra / sb v1,off(a0)
    if (
        w[3] == JR_RA
        and _op(w[0]) == 0x0C and _rs(w[0]) == 5 and _rt(w[0]) == 3        # andi v1, a1, mask
        and _op(w[1]) in _LOAD_STORE_PAIRS and _rs(w[1]) == 4 and _rt(w[1]) == 5  # load a1, off(a0)
        and _op(w[2]) == 0 and _func(w[2]) == 0x23 and _rd(w[2]) == 3 and _rs(w[2]) == 5 and _rt(w[2]) == 3  # subu v1, a1, v1
        and _op(w[4]) == _LOAD_STORE_PAIRS[_op(w[1])] and _rs(w[4]) == 4 and _rt(w[4]) == 3  # store v1, off(a0)
        and _simm(w[1]) == _simm(w[4])
    ):
        offset = _simm(w[1])
        name = _resolve_offset(offset)
        field = name if name else f"/* this[+0x{offset:X}] */"
        return f"{field} -= param;"

    return None


def _has_vtable_symbol(class_name: str) -> bool:
    """Fast check: does __vt__N{class_name} exist in symbol_addrs.txt?

    Does NOT call elf_lookup.py / require elftools — safe to call from any
    Python environment.  Used for the section 2 vtable banner and the weak
    destructor stub hint.
    """
    sym = f"__vt__{len(class_name)}{class_name}"
    if not os.path.exists(_SR2_SYMBOLS):
        return False
    with open(_SR2_SYMBOLS) as f:
        for line in f:
            if sym in line.split("=")[0]:
                return True
    return False


def _get_vtable_slots(class_name: str) -> Optional[List[Tuple[int, Optional[str], Optional[str]]]]:
    """Read the vtable for class_name from the ELF and resolve each slot.

    Returns a list of (slot_index, mangled_name_or_None, demangled_or_None),
    or None if no vtable symbol is found or elf_lookup.py fails.
    Each MWCC PS2 vtable starts with two null words (RTTI offset + type_info ptr)
    before the first actual virtual function pointer.
    """
    vtable_sym = f"__vt__{len(class_name)}{class_name}"
    addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
    size_re = re.compile(r"size:(\d+)")

    vtable_addr: Optional[str] = None
    vtable_size: int = 0
    if not os.path.exists(_SR2_SYMBOLS):
        return None
    with open(_SR2_SYMBOLS) as f:
        for line in f:
            if vtable_sym in line.split("=")[0]:
                m_addr = addr_re.search(line)
                m_size = size_re.search(line)
                if m_addr:
                    vtable_addr = "0x" + m_addr.group(1)
                if m_size:
                    vtable_size = int(m_size.group(1))
                break
    if not vtable_addr or vtable_size < 4:
        return None

    result = subprocess.run(
        python_tool("elf_lookup.py", vtable_addr, "--mode", "bytes", "--length", str(vtable_size)),
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return None

    # Parse the hex dump: lines like "  +0x0000: XX XX XX XX ..."
    hex_re = re.compile(r"\+0x[0-9A-Fa-f]+:\s+((?:[0-9A-Fa-f]{2}\s*)+)")
    raw_bytes: List[int] = []
    for line in result.stdout.splitlines():
        m = hex_re.search(line)
        if m:
            raw_bytes.extend(int(b, 16) for b in m.group(1).split())

    # Build address->mangled lookup; normalise addresses to lowercase hex no leading zeros
    def _norm_addr(hex_str: str) -> str:
        return "0x" + (hex_str.lstrip("0").lower() or "0")

    addr_to_sym: Dict[str, str] = {}
    with open(_SR2_SYMBOLS) as f:
        for line in f:
            if "=" not in line:
                continue
            mangled = line.split("=")[0].strip()
            m = addr_re.search(line)
            if m:
                addr_to_sym[_norm_addr(m.group(1))] = mangled

    slots: List[Tuple[int, Optional[str], Optional[str]]] = []
    num_slots = len(raw_bytes) // 4
    for i in range(num_slots):
        word = (
            raw_bytes[i * 4]
            | (raw_bytes[i * 4 + 1] << 8)
            | (raw_bytes[i * 4 + 2] << 16)
            | (raw_bytes[i * 4 + 3] << 24)
        )
        if word == 0:
            slots.append((i, None, None))
        else:
            key = _norm_addr(hex(word)[2:])
            mangled = addr_to_sym.get(key)
            demangled = _demangle_symbol(mangled) if mangled else None
            slots.append((i, mangled, demangled))
    return slots


def _resolve_deps_deep(initial_types: List[str], origin_class: str) -> None:
    """Iteratively resolve class/struct dependencies not found in the codebase."""
    resolved: set = {origin_class}
    queue = list(initial_types)
    type_re = re.compile(r"\b(?:class|struct)\s+(\w+)")
    while queue:
        t = queue.pop(0)
        if t in resolved:
            continue
        resolved.add(t)
        print(f"\n  [{t}]")
        find_result = subprocess.run(
            python_tool("find-symbol.py", t),
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
        )
        if "Safe to declare" in find_result.stdout:
            placeholder = _find_empty_placeholder(t)
            if placeholder:
                print(f'    ⚠ PLACEHOLDER — scaffold {t} first (empty header: {placeholder})')
                continue
            print("    NOT FOUND — looking up in DWARF")
            try:
                dwarf_result = run_capture(
                    python_tool("lookup.py", GC_DWARF, "struct", t)
                )
                print(dwarf_result.stdout.rstrip())
                for m in type_re.finditer(dwarf_result.stdout):
                    dep = m.group(1)
                    if dep not in resolved:
                        queue.append(dep)
            except WorkflowError:
                print("    (not in DWARF — forward declare or add manually)")
        else:
            first_line = (
                find_result.stdout.strip().splitlines()[0]
                if find_result.stdout.strip()
                else "(no output)"
            )
            print(f"    FOUND: {first_line}")
            inc = _extract_include_path(find_result.stdout)
            if inc:
                if _is_placeholder_header(inc, t):
                    print(f'    → #include "{inc}"  ⚠ PLACEHOLDER — scaffold this class first')
                else:
                    print(f'    → #include "{inc}"')


_KNOWN_SHARED_TYPES: Dict[str, str] = {
    "NNS_VECTOR":     "usr/local/sega/nn/src/Matrix/nnvector.h",
    "NNS_VECTORFAST": "usr/local/sega/nn/src/Matrix/nnvector.h",
    "NNS_MATRIX":     "usr/local/sega/nn/src/Matrix/nnvector.h",
    "NNS_MATFAST":    "usr/local/sega/nn/src/Matrix/nnvector.h",
    "NNS_QUATERNION": "usr/local/sega/nn/src/Matrix/nnvector.h",
}


def _is_placeholder_header(inc_path: str, type_name: str) -> bool:
    """Return True if the header does NOT contain the class/struct definition for type_name.

    Uses content-based detection instead of file size: scans for
    'class/struct TypeName' followed by ':' (inheritance) or '{' (body start).
    """
    full = os.path.join(ROOT_DIR, "include", inc_path)
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # Match: class/struct TypeName followed by : (inheritance) or { (body start)
        # Accounts for potential alignas() macros between class keyword and name
        pattern = (
            r"\b(?:class|struct)\s+(?:alignas\([^)]+\)\s+)?"
            + re.escape(type_name)
            + r"\b\s*(?::|\{)"
        )
        return not re.search(pattern, content)
    except OSError:
        return False


def _find_empty_placeholder(type_name: str) -> Optional[str]:
    """Search for a placeholder header for type_name that lacks the class definition.

    Tries several filename variants because the project strips the cls/stc prefix
    and common suffixes (_Task, _Obj) when naming header files.
    Returns the include-relative path if the file exists but does NOT contain the
    class/struct definition, else None.
    """
    candidates = [type_name]
    # Strip cls/stc prefix (clsPlayerKey → PlayerKey)
    for prefix in ("cls", "stc"):
        if type_name.lower().startswith(prefix):
            stripped = type_name[len(prefix):]
            candidates.append(stripped)
            # Also strip common _Task / _Obj suffixes (clsAdvertiseMgr_Task → AdvertiseMgr)
            for suffix in ("_Task", "_Obj", "_task", "_obj"):
                if stripped.endswith(suffix):
                    candidates.append(stripped[: -len(suffix)])
    targets = {c + ".hpp" for c in candidates}
    include_dir = os.path.join(ROOT_DIR, "include")
    # Pre-compile the regex for performance during the OS walk
    pattern = re.compile(
        r"\b(?:class|struct)\s+(?:alignas\([^)]+\)\s+)?"
        + re.escape(type_name)
        + r"\b\s*(?::|\{)"
    )
    for dirpath, _dirs, files in os.walk(include_dir):
        for fname in files:
            if fname in targets:
                full = os.path.join(dirpath, fname)
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if not pattern.search(content):
                        return os.path.relpath(full, include_dir).replace("\\", "/")
                except OSError:
                    pass
    return None


def _find_base_class_header_by_line_info(base_class: str, struct_output: str) -> Optional[str]:
    """Use a base class function address + line info to find the base class header path.

    Looks up the first function address for base_class from symbol_addrs.txt,
    then uses line info to find the source file. Returns the include-relative
    .hpp path if found, else None.
    """
    # Find first function address for the base class from symbol_addrs.txt
    sym_pat = re.compile(r"__(\d+)" + re.escape(base_class) + r"Fv?")
    _sym_addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
    first_addr = None
    if os.path.exists(_SR2_SYMBOLS):
        with open(_SR2_SYMBOLS, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("//"):
                    continue
                if base_class in stripped:
                    m = sym_pat.search(stripped)
                    if m:
                        am = _sym_addr_re.search(stripped)
                        if am:
                            first_addr = int(am.group(1), 16)
                            break
    if first_addr is None:
        return None
    filepath = _addr_to_filepath(first_addr)
    if not filepath:
        return None
    # Convert Windows path to include-relative .hpp path
    # e.g. "C:\Develop\Projects\SR2\pgm\src\Object\Gimmick\Stage\Stage08\St08RoadCarBase.cpp"
    #      → "Develop/Projects/SR2/pgm/src/Object/Gimmick/Stage/Stage08/St08RoadCarBase.hpp"
    src_prefix = "C:\\Develop\\Projects\\SR2\\pgm\\src\\"
    if filepath.startswith(src_prefix):
        rel = filepath[len(src_prefix):]
        rel = os.path.splitext(rel)[0]  # remove .cpp
        return os.path.join("Develop", "Projects", "SR2", "pgm", "src", rel).replace("\\", "/") + ".hpp"
    return None


def _get_function_dwarf_info(addr_str: str) -> Tuple[Optional[str], List[Tuple[str, str]]]:
    """Look up DWARF info for a function at the given hex address.

    Returns (return_type, dwarf_params) where dwarf_params is a list of
    (type_str, name) for each DWARF-annotated parameter.  MWCC sometimes
    only annotates a subset of params, so the list may be shorter than the
    actual parameter count.  _inject_param_names uses type-matching to place
    names at the correct positions when counts differ.
    """
    _range_re = re.compile(r"^// Range:\s*(0x[0-9A-Fa-f]+)")
    _skip_kw = {
        'class', 'struct', 'const', 'volatile', 'void', 'unsigned', 'signed',
        'short', 'long', 'int', 'float', 'double', 'char', 'bool',
    }

    def _extract_type_name(chunk: str) -> Tuple[str, Optional[str]]:
        """Return (type_str, name) from a param chunk like 'class Foo * bar'."""
        chunk = re.sub(r'\s*\[[^\]]*\]\s*', '', chunk).strip()
        tokens = re.findall(r'\b([A-Za-z_]\w*)\b', chunk)
        name = None
        for tok in reversed(tokens):
            if tok not in _skip_kw:
                name = tok
                break
        if name is None:
            return chunk, None
        m = re.search(r'\b' + re.escape(name) + r'\b', chunk)
        type_str = chunk[:m.start()].strip() if m else chunk
        return type_str, name

    try:
        result = run_capture(
            python_tool("lookup.py", GC_DWARF, "function", addr_str)
        )
        lines = result.stdout.splitlines()
        addr_int = int(addr_str, 16)
        for line in lines:
            m_r = _range_re.match(line.strip())
            if m_r:
                if int(m_r.group(1), 16) != addr_int:
                    return None, []
                break
        for line in lines:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            m_ret = re.match(r"^(.*?)\s+(?:~?[A-Za-z_]\w*(?::~?[A-Za-z_]\w*)*)\s*\(", line)
            ret_type: Optional[str] = None
            if m_ret:
                ret = m_ret.group(1).strip()
                ret_type = ret if ret else "(ctor/dtor)"

            dwarf_params: List[Tuple[str, str]] = []
            inner_m = re.search(r'\((.+)\)\s*(?:\{)?\s*$', line)
            if inner_m:
                raw = inner_m.group(1)
                chunks = re.split(r'/\*[^*]+\*/', raw)
                for chunk in chunks[:-1]:
                    chunk = chunk.strip().lstrip(',').strip()
                    if not chunk:
                        continue
                    sub = _split_param_types(chunk)
                    # Only the last sub-part has the annotation; collect only it.
                    type_str, name = _extract_type_name(sub[-1])
                    if name:
                        dwarf_params.append((type_str, name))

            return ret_type, dwarf_params
    except WorkflowError:
        pass
    return None, []


def _split_param_types(params_str: str) -> List[str]:
    """Split a demangled parameter type list on ',' respecting <> and () nesting."""
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in params_str:
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


def _hungarian_name(type_str: str, n: int) -> str:
    """Return a Hungarian-prefixed ParamN name for an unnamed parameter of the given C++ type."""
    t = type_str.strip()
    if t.endswith('&'):
        return f"rParam{n}"
    if '*' in t:
        base = t.replace('*', '').replace('const', '').strip()
        if 'char' in base.lower():
            return f"pcParam{n}"
        if 'void' in base.lower():
            return f"pvParam{n}"
        return f"pParam{n}"
    tl = t.lower()
    if tl == 'float':
        return f"f32Param{n}"
    if tl == 'double':
        return f"f64Param{n}"
    if tl in ('int', 'signed int', 'long', 'signed long'):
        return f"s32Param{n}"
    if tl in ('unsigned int', 'unsigned long'):
        return f"u32Param{n}"
    if tl in ('short', 'signed short'):
        return f"s16Param{n}"
    if tl == 'unsigned short':
        return f"u16Param{n}"
    if tl in ('char', 'signed char'):
        return f"s8Param{n}"
    if tl == 'unsigned char':
        return f"u8Param{n}"
    if tl in ('bool', '_bool'):
        return f"bParam{n}"
    if t == 'enm' or t.endswith('::enm'):
        return f"eParam{n}"
    return f"sParam{n}"


def _norm_type(t: str) -> str:
    """Normalize a C++ type string for comparison.

    Strips C++ qualifiers (class/struct/enum/signed/unsigned/const/volatile),
    all whitespace, and namespace prefixes so that 'enum enm' matches
    'nspPackId::enm' and 'signed int' matches 'int'.
    """
    t = re.sub(r'\b(class|struct|enum|const|volatile|signed|unsigned)\b', '', t)
    t = re.sub(r'\s+', '', t)
    t = re.sub(r'(?:\w+::)+', '', t)   # strip namespace prefix
    return t


def _inject_param_names(demangled: str, pos_map: Dict[int, str]) -> str:
    """Inject parameter names into a demangled type-only signature.

    pos_map is {0-based position: name} from get_dwarf_params() — exact
    MWCC register annotations, position-correct even when only some params
    are annotated (e.g. {0: 's32xI', 1: 's32yI', 2: 's32ActiveNoI'} with a
    4th unannotated param → 4th slot falls back to Hungarian convention).
    """
    open_p = demangled.find('(')
    close_p = demangled.rfind(')')
    if open_p < 0 or close_p <= open_p:
        return demangled
    params_str = demangled[open_p + 1:close_p]
    if not params_str.strip():
        return demangled
    types = _split_param_types(params_str)
    if not types or types == ['void']:
        return demangled

    names = [
        pos_map.get(i, _hungarian_name(t, i + 1))
        for i, t in enumerate(types)
    ]
    # Fix function pointer syntax: dtk outputs 'type(*)[N][M]' but C/C++
    # requires 'type (*name)[N][M]' when a name is present.
    parts = []
    for t, n in zip(types, names):
        fixed = re.sub(r'(\w+)\(\*\)((?:\[[\d]+\])+)\s*$', r'\1 (*' + n + r')\2', t)
        if fixed != t:
            # Function pointer: name already injected into the type syntax.
            parts.append(fixed)
        else:
            # Normal parameter: append name after the type.
            parts.append(f"{t} {n}")
    merged = ', '.join(parts)
    return demangled[:open_p + 1] + merged + demangled[close_p:]


def _extract_forwarding_names(display_sig: str) -> List[str]:
    """Extract the parameter names from a display_sig produced by _inject_param_names.

    display_sig looks like 'ClassName::method(u32 nameA, s32 nameB, Foo* nameC)'.
    Returns ['nameA', 'nameB', 'nameC'] for use in a base-class forwarding init.
    Falls back to an empty list when no parentheses are found.
    """
    open_p = display_sig.find('(')
    close_p = display_sig.rfind(')')
    if open_p < 0 or close_p <= open_p:
        return []
    params_str = display_sig[open_p + 1:close_p].strip()
    if not params_str or params_str == 'void':
        return []
    parts = _split_param_types(params_str)
    names: List[str] = []
    for part in parts:
        tokens = part.split()
        if tokens:
            last = tokens[-1].lstrip('*&')
            if last and (last[0].isalpha() or last[0] == '_'):
                names.append(last)
            else:
                names.append(f'/* {part.strip()} */')
    return names



def _parse_q2_types_from_mangled(mangled: str) -> List[Tuple[str, str]]:
    """Parse all Q2<N>outer<M>inner occurrences from a mangled symbol name.

    Returns list of (outer_name, inner_name) pairs.
    """
    results: List[Tuple[str, str]] = []
    idx = 0
    while idx < len(mangled):
        pos = mangled.find("Q2", idx)
        if pos < 0:
            break
        p = pos + 2
        # Parse outer name length (digits)
        start = p
        while p < len(mangled) and mangled[p].isdigit():
            p += 1
        if p == start:
            idx = pos + 1
            continue
        outer_n = int(mangled[start:p])
        if p + outer_n > len(mangled):
            idx = pos + 1
            continue
        outer_name = mangled[p : p + outer_n]
        p += outer_n
        # Parse inner name length (digits)
        start = p
        while p < len(mangled) and mangled[p].isdigit():
            p += 1
        if p == start:
            idx = pos + 1
            continue
        inner_n = int(mangled[start:p])
        if p + inner_n > len(mangled):
            idx = pos + 1
            continue
        inner_name = mangled[p : p + inner_n]
        if outer_name.isidentifier() and inner_name.isidentifier():
            results.append((outer_name, inner_name))
        idx = pos + 1
    return results


def _collect_q2_types_from_symbols(
    non_weak: List[str], weak: List[str]
) -> List[Tuple[str, str]]:
    """Return unique (outer_name, inner_name) Q2 type pairs from all symbol lines."""
    seen: set = set()
    results: List[Tuple[str, str]] = []
    for line in non_weak + weak:
        sym_name = line.split("=")[0].strip()
        for pair in _parse_q2_types_from_mangled(sym_name):
            if pair not in seen:
                seen.add(pair)
                results.append(pair)
    return results


def _find_type_at_global_scope(type_name: str, include_dir: str) -> Optional[str]:
    """Return 'rel/path.hpp:lineno' if type_name has a global-scope declaration, else None."""
    pat = re.compile(
        r"^(?:class|struct|namespace|enum)\s+" + re.escape(type_name) + r"\b"
    )
    for dirpath, _dirs, files in os.walk(include_dir):
        for fname in files:
            if not fname.endswith(".hpp"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if pat.match(line):
                            rel = os.path.relpath(fpath, include_dir).replace("\\", "/")
                            return f"{rel}:{lineno}"
            except OSError:
                pass
    return None


def _find_enum_in_headers(
    enum_name: str, include_dir: str
) -> Optional[Tuple[str, int, str]]:
    """Return (rel_path, lineno, first_value_hint) if enum_name is declared in headers, else None."""
    pat = re.compile(r"(?:^|\s)enum\s+" + re.escape(enum_name) + r"\s*[\{;]")
    for dirpath, _dirs, files in os.walk(include_dir):
        for fname in files:
            if not fname.endswith(".hpp"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
                    for lineno, line in enumerate(lines, 1):
                        if pat.search(line):
                            first_val = ""
                            for nline in lines[lineno : lineno + 4]:
                                s = nline.strip()
                                if s and not s.startswith("//") and s not in ("{", "}"):
                                    first_val = s.split(",")[0].split("=")[0].strip()
                                    break
                            rel = os.path.relpath(fpath, include_dir).replace("\\", "/")
                            return (rel, lineno, first_val)
            except OSError:
                pass
    return None


def _extract_tu_from_line_lookup(output: str) -> Optional[str]:
    """Extract TU relative path from line_lookup.py output.

    Primary: use the ' >>> ' marker line (the closest-address match).  This is
    the definitive owner of the function and is immune to large neighbouring TUs
    drowning it out by frequency.

    Fallback: most-frequently appearing path across the whole window, used only
    when no ' >>> ' marker is present in the output.
    """
    path_re = re.compile(r"pgm[/\\]src[/\\](.*\.(?:cpp|h|hpp))", re.IGNORECASE)

    # Primary: the >>> marker is placed by line_lookup.py on the line whose
    # address == matched_addr (exact hit or closest-address hit).
    for line in output.splitlines():
        if " >>> " in line:
            m = path_re.search(line)
            if m:
                return m.group(1).replace("\\", "/")

    # Fallback: frequency heuristic (kept for robustness if marker is absent).
    counts: Dict[str, int] = {}
    for line in output.splitlines():
        m = path_re.search(line)
        if m:
            p = m.group(1).replace("\\", "/")
            counts[p] = counts.get(p, 0) + 1
    if not counts:
        return None
    return max(counts, key=lambda k: counts[k])


def _extract_tu_from_source_path(path: str) -> Optional[str]:
    """Return path relative to Develop/Projects/SR2/pgm/src from a debug path."""
    m = re.search(r"pgm[/\\]src[/\\](.*\.(?:cpp|h|hpp))", path, re.IGNORECASE)
    if not m:
        return None
    return m.group(1).replace("\\", "/")


def _get_sonic_yaml_entries_by_path(tu_path: str) -> List[str]:
    """Search sonic.yaml for entries matching a TU file path (e.g. 'Debug/DebugDetail.cpp').

    Uses the full path fragment (directory + filename stem) so that 'Debug/Debug'
    does not accidentally match 'Debug/DebugDetail'.
    """
    if not tu_path or not os.path.exists(SONIC_YAML):
        return []
    # Use the full path without extension: 'Debug/DebugDetail.cpp' → 'Debug/DebugDetail'
    no_ext = os.path.splitext(tu_path)[0].replace("\\", "/")
    segment_re = re.compile(r"\b(asmtu|src|\.h)\b")
    # sonic.yaml array entries end with ']' right after the path, so check for that boundary.
    # This prevents 'Debug/Debug' from matching 'Debug/DebugDetail]'.
    path_end_re = re.compile(
        re.escape(no_ext) + r"(?=[^A-Za-z0-9_]|$)"
    )
    entries: List[str] = []
    seen: set = set()
    with open(SONIC_YAML) as f:
        for line in f:
            stripped = line.rstrip()
            if stripped in seen:
                continue
            if not segment_re.search(stripped):
                continue
            normalized = stripped.replace("\\", "/")
            if path_end_re.search(normalized):
                seen.add(stripped)
                entries.append(stripped)
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gather all context needed to scaffold a new class header and .cpp stub."
    )
    parser.add_argument(
        "-c",
        "--class",
        dest="class_name",
        required=True,
        help="Class name to scaffold (e.g. clsMotion)",
    )
    parser.add_argument(
        "--brief",
        action="store_true",
        help="Skip the next-steps section and reduce output verbosity",
    )
    parser.add_argument(
        "--no-line-lookup",
        dest="no_line_lookup",
        action="store_true",
        help="Skip the line_lookup step (can be slow on the first run)",
    )
    parser.add_argument(
        "--deps-deep",
        dest="deps_deep",
        action="store_true",
        help="Recursively resolve dependency types not found in the codebase",
    )
    parser.add_argument(
        "--enum",
        dest="extra_enum",
        metavar="ENUMNAME",
        help="Also look up an additional enum by name",
    )
    parser.add_argument(
        "--sections",
        dest="sections",
        metavar="N[,N...]",
        default=None,
        help="Only print the specified section numbers (e.g. --sections 1,3,5,7)",
    )
    args = parser.parse_args()

    _requested_sections: Optional[set] = None
    if args.sections:
        try:
            _requested_sections = {int(s.strip()) for s in args.sections.split(",") if s.strip()}
        except ValueError:
            import sys as _sys
            _sys.exit(f"--sections: invalid value '{args.sections}' — expected comma-separated integers")

    class_name = args.class_name
    brief = args.brief

    struct_output = ""
    _struct_error = ""
    try:
        result = run_capture(python_tool("lookup.py", GC_DWARF, "struct", class_name))
        struct_output = result.stdout
    except WorkflowError as e:
        _struct_error = str(e)

    base_classes = _parse_base_classes(struct_output) if struct_output else []
    base_vtables: Dict[str, Optional[List]] = {}
    if not brief:
        for _base in base_classes:
            base_vtables[_base] = _get_vtable_slots(_base)

    def _sec(n: int) -> bool:
        """Return True if section n should be printed."""
        return _requested_sections is None or n in _requested_sections

    print_section(f"Scaffold Context: {class_name}")

    # 1. Codebase search
    if _sec(1):
        print_section("1. Codebase Search")
        if not struct_output:
            print("⚠ NO DWARF STRUCT — class layout unknown; scaffolding not possible without manual ASM analysis")
        run_stream(python_tool("find-symbol.py", class_name))

    # Symbol data — always computed (needed by sections 5, 6)
    non_weak, weak = _grep_symbol_addrs(class_name)
    template_non_weak, template_weak = _grep_template_symbol_addrs(class_name)
    non_weak = _dedupe_template_symbol_lines(_merge_symbol_lines(non_weak, template_non_weak), class_name)
    weak = _dedupe_template_symbol_lines(_merge_symbol_lines(weak, template_weak), class_name)

    non_weak_funcs = []
    non_weak_statics = []
    _thunk_re = re.compile(r"^@")
    for sym_line in non_weak:
        mangled = sym_line.split("=")[0].strip()
        if mangled.startswith("__vt__"):
            continue
        if _thunk_re.match(mangled):
            continue
        demangled = _demangle_symbol(mangled) or mangled
        if "(" in demangled:
            non_weak_funcs.append((sym_line, mangled, demangled))
        else:
            non_weak_statics.append((sym_line, mangled, demangled))

    weak_funcs = [
        s for s in weak
        if not s.split("=")[0].strip().startswith("__vt__")
        and not _thunk_re.match(s.split("=")[0].strip())
    ]

    # Sort both function lists by source line number (preserves relative order for unknowns).
    # Skipped when --no-line-lookup is set, since the user wants to avoid the file parse.
    if not args.no_line_lookup:
        non_weak_funcs.sort(key=lambda t: _sym_lineno(t[0]))
        weak_funcs.sort(key=_sym_lineno)

    # Fast vtable presence check for section 2 banner and dtor stub hint.
    # Uses symbol_addrs.txt directly — no elftools required, works from any Python.
    # Section 7 uses _get_vtable_slots (requires elftools) for the full slot listing.
    _class_has_vtable = _has_vtable_symbol(class_name)

    # Detect if this class (transitively) inherits clsTask — those ctors need an
    # explicit base-class initializer or MWCC will fail with "cannot construct base class".
    # Hoisted out of the non_weak_funcs block so the weak loop can use it too.
    _needs_task_init = any(b == "clsTask" or b.endswith("_Task") for b in base_classes)

    # 2. Symbol list
    if _sec(2):
        _addr_re2 = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
        print_section("2. Symbol List")
        # ── Vtable status banner ──────────────────────────────────────────────────
        # Shown before any function entry so the model knows whether to write
        # 'virtual' BEFORE it starts drafting the header.  Section 3b shows the
        # BASE class's virtual slot count; do NOT confuse that with this class.
        if not _class_has_vtable:
            print("  ⚠ NO VTABLE: This class has no virtual functions —"
                  " do NOT add 'virtual' to any declaration.\n")
        else:
            print("  ✓ Vtable found — see section 7 for slot order"
                  " (overrides need 'virtual'; inherited-only slots do not).\n")
        if non_weak_funcs:
            print(f"Functions non-weak ({len(non_weak_funcs)}) — define in .cpp:")
            for sym_line, _, demangled in non_weak_funcs:
                m_a = _addr_re2.search(sym_line)
                ret_type = ""
                pos_map: Dict[int, str] = {}
                if m_a:
                    addr_str = "0x" + m_a.group(1)
                    # Return type from DWARF function record.
                    rt, _ = _get_function_dwarf_info(addr_str)
                    ret_type = f"  →  {rt}" if rt else "  →  (unknown)"
                    # Param names: position-keyed map from MWCC register annotations.
                    # Correctly handles partial annotation (e.g. 3 of 4 params named)
                    # without type-matching guesses — unannotated slots get Hungarian names.
                    pos_map = _get_dwarf_params(addr_str)
                display_sig = _inject_param_names(demangled, pos_map)
                print(f"  {display_sig}{ret_type}")
                print(f"    {sym_line}")
                # Emit ready-to-use stub for clsTask-chain constructors.
                if _needs_task_init and re.search(
                    r"__ct__\d+\w+F", sym_line.split("=")[0]
                ):
                    base = base_classes[0] if base_classes else "BaseClass"
                    if base == "clsTask":
                        base_init_args = "0, 0"
                    else:
                        # Forward derived params to base; add extra base-only params if needed.
                        _fwd = _extract_forwarding_names(display_sig)
                        base_init_args = ", ".join(_fwd) if _fwd else "/* TODO */"
                    print(
                        f"    // stub (.cpp): {display_sig} : {base}({base_init_args}) {{}}"
                        "  [verify base constructor params]"
                    )
        else:
            print("No non-weak functions found.")
        print()

        if weak_funcs:
            print(f"Functions weak/allow_duplicated ({len(weak_funcs)}) — define inline in header:")
            for sym_line in weak_funcs:
                mangled = sym_line.split("=")[0].strip()
                demangled = _demangle_symbol(mangled)
                if demangled:
                    print(f"  {demangled}")
                    print(f"    {sym_line}")
                    # Emit ready-to-use inline stub for clsTask-chain weak constructors.
                    if not brief and _needs_task_init and re.search(
                        r"__ct__\d+\w+F", mangled
                    ):
                        base = base_classes[0] if base_classes else "BaseClass"
                        # Strip "ClassName::" qualifier → inline header form
                        _inline_sig = re.sub(r"^\w+::", "", demangled)
                        if base == "clsTask":
                            base_init_args = "0, 0"
                        else:
                            _fwd = _extract_forwarding_names(_inline_sig)
                            base_init_args = ", ".join(_fwd) if _fwd else "/* TODO */"
                        print(
                            f"    // stub (header): {_inline_sig} : {base}({base_init_args}) {{}}"
                            "  [verify base constructor params]"
                        )
                    # Emit stub hint for weak destructors — same placement rule as
                    # ctors (inline in header), but no base-init needed.
                    # Include 'virtual' when the class has a vtable symbol.
                    if not brief and re.search(r"__dt__\d+\w+F", mangled):
                        _dtor_virt = "virtual " if _class_has_vtable else ""
                        print(f"    // stub (header): {_dtor_virt}~{class_name}() {{}}")
                    if not brief and "size:8" in sym_line:
                        hint = _parse_size8_asm_hint(sym_line, struct_output)
                        if hint:
                            print(f"    // likely: {hint}  [ASM-derived guess — verify]")
                    if not brief and "size:12" in sym_line:
                        hint = _parse_size12_asm_hint(sym_line, struct_output)
                        if hint:
                            print(f"    // likely: {hint}  [ASM-derived guess — verify]")
                    if not brief and "size:16" in sym_line:
                        hint = _parse_size16_asm_hint(sym_line, struct_output)
                        if hint:
                            print(f"    // likely: {hint}  [ASM-derived guess — verify]")
                    if not brief and "size:20" in sym_line:
                        hint = _parse_size20_asm_hint(sym_line, struct_output)
                        if hint:
                            print(f"    // likely: {hint}  [ASM-derived guess — verify]")
                else:
                    print(f"  {sym_line}")
        else:
            print("No weak/inline functions found.")
        print()

    if _sec(2) and non_weak_statics:
        print(f"Statics/globals ({len(non_weak_statics)}) — declare static in header, define in .cpp:")
        _addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
        _size_re = re.compile(r"size:(\d+)")
        for sym_line, mangled, demangled in non_weak_statics:
            bare = demangled.split("::")[-1] if "::" in demangled else demangled
            dwarf_type = ""
            try:
                gresult = run_capture(python_tool("lookup.py", GC_DWARF, "global", bare))
                dwarf_type = gresult.stdout.strip()
            except WorkflowError:
                pass
            print(f"  {demangled}")
            if dwarf_type:
                print(f"    type: {dwarf_type}")
            m_addr = _addr_re.search(sym_line)
            m_size = _size_re.search(sym_line)
            if m_addr and m_size and dwarf_type:
                addr = "0x" + m_addr.group(1)
                size = int(m_size.group(1))
                if re.search(r"\bdouble\b", dwarf_type):
                    doubles = _decode_double_values(addr, size)
                    if doubles:
                        if len(doubles) == 1:
                            print(f"    value: {_format_double_literal(doubles[0])}")
                        else:
                            print(f"    values: {{{', '.join(_format_double_literal(v) for v in doubles)}}}")
                elif re.search(r"\bfloat\b", dwarf_type):
                    floats = _decode_float_values(addr, size)
                    if floats:
                        if len(floats) == 1:
                            code, raw_comment = _scaffold_float_display(floats[0])
                            suffix = f"  // raw: {raw_comment}" if raw_comment else ""
                            print(f"    value: {code}{suffix}")
                        else:
                            parts = []
                            for v in floats:
                                code, raw_comment = _scaffold_float_display(v)
                                parts.append(f"{code}  // raw: {raw_comment}" if raw_comment else code)
                            print(f"    values: {{{', '.join(parts)}}}")
                else:
                    _int_dispatch = [
                        (r"\bunsigned int\b",   4, False, False),
                        (r"\bint\b",            4, True,  False),
                        (r"\bunsigned short\b", 2, False, False),
                        (r"\bshort\b",          2, True,  False),
                        (r"\bunsigned char\b",  1, False, False),
                        (r"\bchar\b",           1, True,  False),
                        (r"\bbool\b",           1, False, True),
                    ]
                    for _pat, _esz, _sgn, _bool in _int_dispatch:
                        if re.search(_pat, dwarf_type):
                            ints = _decode_int_values(addr, size, _esz, _sgn, _bool)
                            if ints:
                                if len(ints) == 1:
                                    print(f"    value: {_format_int_value(ints[0])}")
                                else:
                                    print(f"    values: {{{', '.join(_format_int_value(v) for v in ints)}}}")
                            break
                    else:
                        _cm = re.search(r"\b(?:class|struct)\s+(\w+)", dwarf_type)
                        if _cm:
                            _bare = _cm.group(1)
                            try:
                                _nres = run_capture(
                                    python_tool("lookup.py", GC_DWARF, "struct", _bare)
                                )
                                _nmre = re.compile(
                                    r"^\s+(.+?)\s+(\w+)\s*;"
                                    r".*//\s*offset\s+(0x[0-9A-Fa-f]+),\s*size\s+(0x[0-9A-Fa-f]+)"
                                )
                                _fields = []
                                for _nl in _nres.stdout.splitlines():
                                    if _nl.strip() == "};":
                                        break
                                    _nm = _nmre.match(_nl)
                                    if _nm:
                                        _fields.append((
                                            _nm.group(1).strip(),
                                            _nm.group(2),
                                            int(_nm.group(3), 16),
                                            int(_nm.group(4), 16),
                                        ))
                                if _fields:
                                    _base_addr = int(addr, 16)
                                    _field_lines = []
                                    for _ft, _fn, _fo, _fs in _fields:
                                        _faddr = hex(_base_addr + _fo)
                                        if re.search(r"\bfloat\b", _ft) and _fs == 4:
                                            _fv = _decode_float_values(_faddr, _fs)
                                            if _fv:
                                                _fc, _ = _scaffold_float_display(_fv[0])
                                                _field_lines.append(
                                                    f"      {_fn} = {_fc}  (offset 0x{_fo:X})"
                                                )
                                        elif re.search(r"\bdouble\b", _ft) and _fs == 8:
                                            _dv = _decode_double_values(_faddr, _fs)
                                            if _dv:
                                                _field_lines.append(
                                                    f"      {_fn} = {_format_double_literal(_dv[0])}  (offset 0x{_fo:X})"
                                                )
                                        else:
                                            _int_field_dispatch = [
                                                (r"\bunsigned int\b",   4, False, False),
                                                (r"\bint\b",            4, True,  False),
                                                (r"\bunsigned short\b", 2, False, False),
                                                (r"\bshort\b",          2, True,  False),
                                                (r"\bunsigned char\b",  1, False, False),
                                                (r"\bchar\b",           1, True,  False),
                                                (r"\bbool\b",           1, False, True),
                                            ]
                                            for _ip, _iesz, _isgn, _ibool in _int_field_dispatch:
                                                if re.search(_ip, _ft) and _fs == _iesz:
                                                    _iv = _decode_int_values(
                                                        _faddr, _fs, _iesz, _isgn, _ibool
                                                    )
                                                    if _iv:
                                                        _field_lines.append(
                                                            f"      {_fn} = {_format_int_value(_iv[0])}  (offset 0x{_fo:X})"
                                                        )
                                                    break
                                    if _field_lines:
                                        print(f"    fields ({_bare}):")
                                        for _fl in _field_lines:
                                            print(_fl)
                            except WorkflowError:
                                pass
            # Warn when DWARF reports an incomplete array type (size 0x0) but the
            # symbol table has a non-zero size — derive the entry count so the
            # agent knows what size to use for the definition in .cpp.
            if m_size and dwarf_type and re.search(r"\[\s*\]", dwarf_type):
                sym_size = int(m_size.group(1))
                if sym_size > 0:
                    ptr_count = sym_size // 4  # 4 bytes per pointer on PS2 MIPS
                    print(
                        f"    // ⚠ incomplete array: symbol size={sym_size} bytes"
                        f" → define as void *<name>[{ptr_count}]; in .cpp"
                    )
            print(f"    {sym_line}")
    elif _sec(2):
        print("No static/global members found.")

    # 3. DWARF struct
    if _sec(3):
        print_section("3. DWARF Struct")
        if struct_output:
            print(struct_output)
        else:
            print(f"(DWARF struct not found: {_struct_error})")

    # 3b. Base class auto-lookup
    if _sec(3) and struct_output and not brief:
        if base_classes:
            print_section("3b. Base Class Summary")
            for base_class in base_classes:
                print(f"\n  Base class: {base_class}")
                try:
                    base_result = run_capture(
                        python_tool("lookup.py", GC_DWARF, "struct", base_class)
                    )
                    base_text = base_result.stdout
                    size_match = re.search(
                        r"//\s*total size:\s*(0x[0-9A-Fa-f]+)", base_text
                    ) or re.search(r"\{\s*//\s*(0x[0-9A-Fa-f]+)", base_text)
                    size_str = size_match.group(1) if size_match else "?"
                    member_count = len(re.findall(r"//\s*offset\s+0x", base_text))
                    base_vtable = base_vtables.get(base_class)
                    virtual_count = (
                        sum(1 for _, m, _ in base_vtable if m is not None)
                        if base_vtable
                        else 0
                    )
                    # "in base vtable" — clarifies these are the BASE class's slots,
                    # NOT the current class's. Models have confused this with the
                    # current class having virtual functions.
                    vtable_str = f", {virtual_count} slot(s) in base vtable" if virtual_count else ""
                    print(f"    size: {size_str}, {member_count} field(s){vtable_str}")
                    # Show grandparent if the base class itself inherits
                    grandparents = _parse_base_classes(base_text)
                    if grandparents:
                        print(f"    inherits: {', '.join(grandparents)}")
                    # Try line info first (most reliable), then filename-based detection
                    header_path = _find_base_class_header_by_line_info(base_class, struct_output)
                    placeholder = None
                    if header_path:
                        if _is_placeholder_header(header_path, base_class):
                            placeholder = header_path
                    if not placeholder:
                        placeholder = _find_empty_placeholder(base_class)
                    if placeholder:
                        print(f"    ⛔ BLOCKED — cannot inherit from unscaffolded class!")
                        print(f"       Scaffold {base_class} FIRST (empty header: {placeholder})")
                        print(f"       Run: python tools/decomp-workflow.py scaffold -c {base_class}")
                        print(f"       DO NOT proceed to scaffold this class until the base class is done.")
                except WorkflowError:
                    # Try line info first, then filename-based detection
                    header_path = _find_base_class_header_by_line_info(base_class, struct_output)
                    placeholder = None
                    if header_path:
                        if _is_placeholder_header(header_path, base_class):
                            placeholder = header_path
                    if not placeholder:
                        placeholder = _find_empty_placeholder(base_class)
                    if placeholder:
                        print(f"    ⛔ BLOCKED — cannot inherit from unscaffolded class!")
                        print(f"       Scaffold {base_class} FIRST (empty header: {placeholder})")
                        print(f"       Run: python tools/decomp-workflow.py scaffold -c {base_class}")
                        print(f"       DO NOT proceed to scaffold this class until the base class is done.")
                    else:
                        print("    (not found in DWARF — forward declare if needed)")

    # 4. Nested enum lookup
    enum_names: List[str] = []
    if struct_output:
        seen_enums: set = set()
        for line in struct_output.splitlines():
            m = re.search(r"\benum\s+(\w+)\b", line)
            if m:
                name = m.group(1)
                if name not in seen_enums:
                    seen_enums.add(name)
                    enum_names.append(name)

    if args.extra_enum and args.extra_enum not in enum_names:
        enum_names.append(args.extra_enum)

    if enum_names and _sec(4):
        print_section("4. Enum Ownership + Lookup")
        _include_dir = os.path.join(ROOT_DIR, "include")
        for enum_name in enum_names:
            owners = _find_enum_owners(enum_name)

            if class_name in owners:
                ownership_label = f"NESTED inside {class_name} (declare inside the class body)"
            elif owners:
                parts = []
                for owner, syms in sorted(owners.items()):
                    kind = "namespace" if owner.startswith("nsp") else "class"
                    parts.append(f"{owner} ({kind}, {len(syms)} ref(s))")
                ownership_label = "owned by: " + ", ".join(parts)
            else:
                ownership_label = "no Q2 mangling found — likely truly global"

            print(f"\n  {enum_name}")
            print(f"  Ownership: {ownership_label}")

            raw_body = _find_enum_body_for_class(class_name, enum_name)
            raw_fp = _enum_value_fingerprint(raw_body) if raw_body else None

            nested_key = f"{class_name}::{enum_name}"
            try:
                result = run_capture(
                    python_tool("lookup.py", GC_DWARF, "enum", nested_key)
                )
                print(result.stdout)
            except WorkflowError:
                try:
                    result = run_capture(
                        python_tool("lookup.py", GC_DWARF, "enum", enum_name)
                    )
                    raw_text = result.stdout.rstrip()
                    blocks = re.split(r"\n(?=enum\s)", raw_text)
                    for block in blocks:
                        block = block.rstrip()
                        if not block:
                            continue
                        if raw_fp is not None and _enum_value_fingerprint(block) == raw_fp:
                            print(f"  [v USE THIS — matches {class_name} member type in raw DWARF]")
                        print(block)
                        print()
                    if not owners:
                        print(
                            "  NOTE: DWARF stores this at global scope (MWCC flattens nested enums).\n"
                            "  No Q2 mangling found — double-check ownership manually."
                        )
                except WorkflowError as e2:
                    print(f"  (not found in DWARF: {e2})")

            # Item 10: flag enum name collisions with existing headers
            collision = _find_enum_in_headers(enum_name, _include_dir)
            if collision:
                col_path, col_line, col_hint = collision
                hint_str = f" (first value: {col_hint})" if col_hint else ""
                print(
                    f"  ⚠ {enum_name} — name collision: already declared in\n"
                    f"    {col_path}:{col_line}{hint_str}\n"
                    f"  If the values differ from the DWARF body above, nest this enum inside\n"
                    f"  the class body and add a // TODO noting the ambiguity."
                )

    # 5. Dependency check
    if struct_output and _sec(5):
        _include_dir5 = os.path.join(ROOT_DIR, "include")
        dep_types: List[str] = []
        seen_types: set = set()
        type_re = re.compile(r"\b(?:class|struct)\s+(\w+)")
        for m in type_re.finditer(struct_output):
            t = m.group(1)
            if t != class_name and t not in seen_types:
                seen_types.add(t)
                dep_types.append(t)

        if dep_types:
            if args.deps_deep:
                print_section("5. Deep Dependency Check")
                _resolve_deps_deep(dep_types, class_name)
            else:
                print_section("5. Dependency Check")
                for t in dep_types:
                    print(f"\n  {t}")
                    # Item 6: flag known shared types
                    if t in _KNOWN_SHARED_TYPES:
                        print(
                            f"    ⚠ already defined in {_KNOWN_SHARED_TYPES[t]} — do NOT redefine;\n"
                            f'    include that header instead'
                        )
                        continue
                    find_result = subprocess.run(
                        python_tool("find-symbol.py", t),
                        cwd=ROOT_DIR,
                        text=True,
                        capture_output=True,
                    )
                    if "Safe to declare" in find_result.stdout:
                        placeholder = _find_empty_placeholder(t)
                        if placeholder:
                            print(f'    ⚠ PLACEHOLDER — scaffold {t} first (empty header: {placeholder})')
                        else:
                            print("    NOT FOUND — needs to be added or declared")
                    else:
                        for dep_line in find_result.stdout.strip().splitlines():
                            print(f"    {dep_line}")
                        inc = _extract_include_path(find_result.stdout)
                        if inc:
                            if _is_placeholder_header(inc, t):
                                print(f'    → #include "{inc}"  ⚠ PLACEHOLDER — scaffold this class first')
                            else:
                                print(f'    → #include "{inc}"')
                if not brief:
                    print(
                        "\nHint: re-run with --deps-deep to recursively resolve unknown types."
                    )
        else:
            print_section("5. Dependency Check")
            print("No class/struct dependencies detected in DWARF output.")

        # Items 5, 11, 15: report Q2-qualified types from function signatures
        q2_types = _collect_q2_types_from_symbols(non_weak, weak)
        if q2_types:
            print("\n  Q2-qualified types in function signatures:")
            for outer_name, inner_name in q2_types:
                qualified = f"{outer_name}::{inner_name}"
                # Item 15: inner name exists at global scope → MWCC scoping mismatch
                global_decl = _find_type_at_global_scope(inner_name, _include_dir5)
                if global_decl:
                    print(
                        f"\n  {qualified}  — MWCC scoping mismatch:\n"
                        f"    {inner_name} is declared at GLOBAL scope in {global_decl}\n"
                        f"    but mangled as if nested inside {outer_name}.\n"
                        f"    Use the existing global declaration and accept the mangling difference.\n"
                        f"    Verify during implementation by checking the ASM."
                    )
                    continue
                # Item 5 / 11: outer name — determine kind from naming convention
                outer_lower = outer_name.lower()
                if outer_lower.startswith("cls") or outer_lower.startswith("stc"):
                    outer_kind = "class" if outer_lower.startswith("cls") else "struct"
                    # Check if inner_name also has a standalone DWARF entry — if so it may
                    # be a global class that MWCC scoped to outer in the mangling (not truly
                    # nested), and should be scaffolded independently before deciding.
                    inner_probe = subprocess.run(
                        python_tool("lookup.py", GC_DWARF, "struct", inner_name),
                        cwd=ROOT_DIR, text=True, capture_output=True,
                    )
                    if inner_probe.returncode == 0 and inner_probe.stdout.strip():
                        print(
                            f"\n  {qualified}  — AMBIGUOUS: inner type '{inner_name}' also exists as a standalone DWARF struct.\n"
                            f"    This may be a MWCC scoping mismatch (global class mangled as nested) rather than a true nested type.\n"
                            f"    Run: python tools/decomp-workflow.py scaffold -c {inner_name}\n"
                            f"    If it has its own methods/fields → scaffold it as a global class first, then use the global declaration here.\n"
                            f"    If DWARF only shows it under {outer_name} → declare it nested inside {outer_name}."
                        )
                    else:
                        print(
                            f"\n  {qualified}  — nested {outer_kind} (owner {outer_name} is a {outer_kind}, NOT a namespace)\n"
                            f"    forward-declare as: {outer_kind} {outer_name};\n"
                            f"    (then use {qualified} in signatures)"
                        )
                elif outer_lower.startswith("nsp"):
                    # Check if outer is in DWARF to confirm it's really a namespace
                    print(
                        f"\n  {qualified}  — owner '{outer_name}' has 'nsp' prefix → treat as namespace\n"
                        f"    declare as: namespace {outer_name} {{ /* {inner_name} forward-decl here */ }}"
                    )
                else:
                    # Unknown kind — check DWARF
                    probe = subprocess.run(
                        python_tool("lookup.py", GC_DWARF, "struct", outer_name),
                        cwd=ROOT_DIR, text=True, capture_output=True,
                    )
                    if probe.returncode == 0 and probe.stdout.strip():
                        print(
                            f"\n  {qualified}  — nested type (owner {outer_name} found in DWARF as class/struct)\n"
                            f"    forward-declare as: class {outer_name};  (or struct if no visibility modifiers)"
                        )
                    else:
                        # Item 11: not in DWARF at all
                        print(
                            f"\n  {qualified}  — NOT IN DWARF; appears only in mangled names\n"
                            f"    Declare as: namespace {outer_name} {{ enum {inner_name}; }}  (forward decl, no values)\n"
                            f"    Values can only be recovered by reading the ASM for functions that use this type."
                        )

    # 6. Line ownership
    _line_tu_path: Optional[str] = None  # captured for section 8 fallback
    if _sec(6):
        print_section("6. Line Ownership")
    if _sec(6) or _sec(8):
        # Always run line lookup when section 8 is active so the sonic.yaml section can use
        # the real TU path.  --no-line-lookup only suppresses the section 6 display.
        owned_non_weak = [
            line for line in non_weak
            if _parse_owner_from_mangled(line.split("=", 1)[0].strip()) == class_name
        ]
        owned_weak = [
            line for line in weak
            if _parse_owner_from_mangled(line.split("=", 1)[0].strip()) == class_name
        ]
        first_symbol = _extract_first_symbol(owned_non_weak) or _extract_first_symbol(owned_weak)
        first_addr = f"0x{first_symbol[1]:08X}" if first_symbol else None
        if first_addr:
            if first_symbol:
                owner_file = _source_file_for_function_label(first_symbol[1], first_symbol[0], class_name)
                if owner_file:
                    _line_tu_path = _extract_tu_from_source_path(owner_file)
            try:
                line_result = run_capture(python_tool("line_lookup.py", DEBUG_LINES, first_addr))
                if not _line_tu_path:
                    _line_tu_path = _extract_tu_from_line_lookup(line_result.stdout)
                if _sec(6) and not args.no_line_lookup:
                    print(line_result.stdout, end="")
            except WorkflowError as e:
                if _sec(6) and not args.no_line_lookup:
                    print(f"(line lookup failed: {e})")
        else:
            if _sec(6) and not args.no_line_lookup:
                print("(no function address found in symbol_addrs.txt)")
        if _sec(6) and args.no_line_lookup:
            print("(skipped via --no-line-lookup)")
        # Always show the resolved TU source file prominently — this is the most important
        # output of section 6.  Shown even with --no-line-lookup so the agent always knows.
        if _sec(6) and _line_tu_path:
            _line_ext = os.path.splitext(_line_tu_path)[1].lower()
            cpp_rel = f"src/Develop/Projects/SR2/pgm/src/{_line_tu_path}" if _line_ext == ".cpp" else ""
            hpp_rel = f"include/Develop/Projects/SR2/pgm/src/{os.path.splitext(_line_tu_path)[0]}.hpp"
            print("\nTU source file (DWARF line info):")
            if cpp_rel:
                print(f"  .cpp  →  {cpp_rel}")
            print(f"  .hpp  →  {hpp_rel}")

    # 7. Vtable
    if _sec(7):
        print_section("7. Vtable")
        vtable_slots = _get_vtable_slots(class_name)
        if vtable_slots is None:
            print(f"(no vtable found — {class_name} has no virtual functions)")
            print(f"  → If this class should have a vtable, run: ghidra start")
        else:
            vtable_sym = f"__vt__{len(class_name)}{class_name}"
            print(f"  {vtable_sym}  ({len(vtable_slots)} slots)")
            base_slot_lookup: Dict[int, Tuple[str, str]] = {}
            if not brief:
                for _base, _bvt in base_vtables.items():
                    if _bvt:
                        for _bidx, _bmangled, _ in _bvt:
                            if _bmangled is not None and _bidx not in base_slot_lookup:
                                base_slot_lookup[_bidx] = (_bmangled, _base)
            for idx, mangled, demangled in vtable_slots:
                if mangled is None:
                    print(f"  [{idx}] null  (RTTI/offset word)")
                else:
                    label = demangled or mangled
                    tag = ""
                    if not brief and base_slot_lookup:
                        if idx in base_slot_lookup:
                            base_mangled, _base_cls = base_slot_lookup[idx]
                            if base_mangled != mangled:
                                base_dem = _demangle_symbol(base_mangled) or base_mangled
                                tag = f"  [override of {base_dem}]"
                        else:
                            tag = "  [new]"
                    print(f"  [{idx}] virtual {label}{tag}")

    # 8. sonic.yaml entry
    _asmtu_re = re.compile(r"\[\s*0x[0-9A-Fa-f]+,\s*asmtu,\s*([^\]]+)\]")
    _build_asm = os.path.join(ROOT_DIR, "build", "SLUS-21642-PROTO-070901", "asm")

    def _print_yaml_entries_with_asm(entries: List[str]) -> None:
        for entry in entries:
            print(entry)
            m = _asmtu_re.search(entry)
            if m:
                tu_path = m.group(1).strip()
                asm_path = os.path.join(_build_asm, tu_path + ".s")
                rel = os.path.relpath(asm_path, ROOT_DIR).replace("\\", "/")
                exists = "✓" if os.path.exists(asm_path) else "✗ (not yet built)"
                print(f"      → ASM: {rel}  {exists}")

    # Derive concrete file paths from sonic.yaml or line info for display in sections 8
    # and Next Steps.  Prefer the yaml asmtu path (build-system canonical); fall back to
    # the line-info path (DWARF canonical).
    _tu_yaml_stem: Optional[str] = None  # e.g. "Develop/Projects/SR2/pgm/src/Object/..."
    _tu_cpp: Optional[str] = None        # e.g. "src/Develop/.../St08Road.cpp"
    _tu_hpp: Optional[str] = None        # e.g. "include/Develop/.../St08Road.hpp"
    _tu_obj: Optional[str] = None        # e.g. "build/.../St08Road.o"
    _tu_asm: Optional[str] = None        # e.g. "build/.../asm/.../St08Road.s"

    if _sec(8):
        print_section("8. sonic.yaml Entry")
        # Prefer line ownership (exact TU path) over name heuristic (unreliable when the
        # file name doesn't match the class name, e.g. clsRoad_Obj lives in St08Road).
        line_entries: List[str] = []
        if _line_tu_path:
            line_entries = _get_sonic_yaml_entries_by_path(_line_tu_path)
        if line_entries:
            _print_yaml_entries_with_asm(line_entries)
            # Extract the canonical TU path from the first active asmtu entry.
            for _e in line_entries:
                _m = _asmtu_re.search(_e)
                if _m:
                    _tu_yaml_stem = _m.group(1).strip()
                    break
        else:
            # Fall back to name heuristic — catches cases where line lookup had no data.
            heuristic_entries = _get_sonic_yaml_entries(class_name)
            if heuristic_entries:
                print("  (found via name heuristic — verify TU path is correct):")
                _print_yaml_entries_with_asm(heuristic_entries)
                for _e in heuristic_entries:
                    _m = _asmtu_re.search(_e)
                    if _m:
                        _tu_yaml_stem = _m.group(1).strip()
                        break
            else:
                print(f"(no entry found for '{class_name}' in sonic.yaml)")

        # Resolve file paths: sonic.yaml stem takes priority; line-info path as fallback.
        if _tu_yaml_stem:
            _tu_cpp = f"src/{_tu_yaml_stem}.cpp"
            _tu_hpp = f"include/{_tu_yaml_stem}.hpp"
            _tu_obj = f"build/SLUS-21642-PROTO-070901/src/{_tu_yaml_stem}.o"
            _tu_asm = f"build/SLUS-21642-PROTO-070901/asm/{_tu_yaml_stem}.s"
        elif _line_tu_path:
            _pfx = "Develop/Projects/SR2/pgm/src/"
            _tu_hpp = f"include/{_pfx}{os.path.splitext(_line_tu_path)[0]}.hpp"
            if os.path.splitext(_line_tu_path)[1].lower() == ".cpp":
                _tu_cpp = f"src/{_pfx}{_line_tu_path}"
                _tu_obj = f"build/SLUS-21642-PROTO-070901/src/{_pfx}{os.path.splitext(_line_tu_path)[0]}.o"
                _tu_asm = f"build/SLUS-21642-PROTO-070901/asm/{_pfx}{os.path.splitext(_line_tu_path)[0]}.s"

        if _tu_hpp or _tu_cpp:
            asm_exists = "✓" if (_tu_asm and os.path.exists(os.path.join(ROOT_DIR, _tu_asm))) else "✗ (not yet built)"
            print("\n  Write these files:")
            if _tu_hpp:
                print(f"    {_tu_hpp}")
            if _tu_cpp:
                print(f"    {_tu_cpp}")
            if _tu_asm:
                print(f"  ASM reference:  {_tu_asm}  {asm_exists}")

    if not brief:
        print_section("Next Steps")
        hpp_hint = _tu_hpp or "include/<path>/<ClassName>.hpp"
        cpp_hint = _tu_cpp or "src/<path>/<ClassName>.cpp"
        obj_hint = _tu_obj or "build/SLUS-21642-PROTO-070901/src/<path>/<ClassName>.o"
        unit_hint = os.path.basename(_tu_cpp) if _tu_cpp else "<unit>.cpp"
        if _tu_cpp:
            print(
                f"1. Write {hpp_hint} from the DWARF struct above\n"
                f"2. Write {cpp_hint} with empty function stubs\n"
                "3. Add #include for the new header in dependent .cpp files\n"
                "4. If this TU is missing from sonic.yaml (check section 8 above),\n"
                "   do NOT edit sonic.yaml — append the TU path to notes/pending-sonic-yaml.md\n"
                "   for human review instead\n"
                f"5. Build: ninja {obj_hint}\n"
                f"6. Check: python tools/decomp-workflow.py unit -u {unit_hint}"
            )
        else:
            print(
                f"1. Write {hpp_hint} from the DWARF struct above\n"
                "2. Add #include for the new header in dependent .cpp files\n"
                "3. Build a dependent unit that includes this header"
            )


if __name__ == "__main__":
    try:
        main()
    except WorkflowError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
