#!/usr/bin/env python3

import bisect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

_SR2_SYMBOLS = os.path.join(ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "symbol_addrs.txt")
_EXE = ".exe" if sys.platform == "win32" else ""
DTK = os.path.join(ROOT_DIR, "build", "tools", "dtk" + _EXE)
BUILD_NINJA = os.path.join(ROOT_DIR, "build.ninja")
OBJDIFF_JSON = os.path.join(ROOT_DIR, "objdiff.json")
OBJDIFF_DEFAULT_CONFIG_ARGS = [
    "-c",
    "functionRelocDiffs=none",
    "-c",
    "ppc.calculatePoolRelocations=false",
]
RELOC_DIFF_CHOICES = ("none", "function", "data", "all")


class ToolError(RuntimeError):
    pass


class WorkflowError(RuntimeError):
    pass


TOOLS_DIR = os.path.join(ROOT_DIR, "tools")


def tool_path(name: str) -> str:
    return os.path.join(TOOLS_DIR, name)


def python_tool(name: str, *args: str) -> List[str]:
    return [sys.executable, tool_path(name), *args]


def print_section(title: str) -> None:
    print(flush=True)
    print("=" * 60, flush=True)
    print(f"  {title}", flush=True)
    print("=" * 60, flush=True)


def run_capture(cmd: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    result = subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True)
    if result.returncode != 0:
        raise WorkflowError(
            format_subprocess_error(cmd, result.returncode, result.stdout, result.stderr)
        )
    return result


def run_stream(cmd: Sequence[str]) -> None:
    sys.stdout.flush()
    sys.stderr.flush()
    result = subprocess.run(cmd, cwd=ROOT_DIR, text=True)
    if result.returncode != 0:
        raise WorkflowError(format_subprocess_error(cmd, result.returncode))



def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def format_subprocess_error(
    cmd: Sequence[str], returncode: int, stdout: str = "", stderr: str = ""
) -> str:
    message = [f"Command failed (exit {returncode}): {' '.join(cmd)}"]
    stdout = stdout.strip()
    stderr = stderr.strip()
    if stdout:
        message.append(f"stdout:\n{stdout}")
    if stderr:
        message.append(f"stderr:\n{stderr}")
    return "\n".join(message)


def ensure_exists(path: str, hint: str) -> None:
    if not os.path.exists(path):
        raise ToolError(f"Missing {path}\nHint: {hint}")


def ensure_project_prereqs(require_build_ninja: bool = False) -> None:
    ensure_exists(OBJDIFF_JSON, "Run: python configure.py")
    if require_build_ninja:
        ensure_exists(BUILD_NINJA, "Run: python configure.py")


def build_objdiff_config_args(reloc_diffs: str = "none") -> List[str]:
    if reloc_diffs not in RELOC_DIFF_CHOICES:
        raise ToolError(
            f"Invalid relocation diff mode: {reloc_diffs} "
            f"(expected one of {', '.join(RELOC_DIFF_CHOICES)})"
        )
    return ["-c", f"functionRelocDiffs={reloc_diffs}", *OBJDIFF_DEFAULT_CONFIG_ARGS]


def load_json_file(path: str, description: str) -> Any:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        raise ToolError(f"Missing {description}: {path}")
    except json.JSONDecodeError as e:
        raise ToolError(f"Failed to parse {description}: {e}")


def load_objdiff_config() -> Dict[str, Any]:
    ensure_project_prereqs()
    data = load_json_file(OBJDIFF_JSON, "objdiff.json")
    if not isinstance(data, dict):
        raise ToolError("objdiff.json does not contain a JSON object")
    return data


def find_objdiff_unit(config: Dict[str, Any], unit_name: str) -> Optional[Dict[str, Any]]:
    for unit in config.get("units", []):
        if unit.get("name") == unit_name:
            return unit
    return None


def make_abs(path: Optional[str], base: str = ROOT_DIR) -> Optional[str]:
    if path is None:
        return None
    if os.path.isabs(str(path)):
        return str(path)
    return os.path.abspath(os.path.join(base, str(path)))


def apply_base_obj_override(
    config: Dict[str, Any], unit_name: str, base_obj: str, root_dir: str = ROOT_DIR
) -> bool:
    found = False
    for unit in config.get("units", []):
        target_path = make_abs(unit.get("target_path"), root_dir)
        if target_path is not None:
            unit["target_path"] = target_path

        if unit.get("name") == unit_name:
            unit["base_path"] = os.path.abspath(base_obj)
            found = True
        else:
            base_path = make_abs(unit.get("base_path"), root_dir)
            if base_path is not None:
                unit["base_path"] = base_path

        metadata = unit.get("metadata") or {}
        source_path = make_abs(metadata.get("source_path"), root_dir)
        if source_path is not None:
            metadata["source_path"] = source_path

        scratch = unit.get("scratch") or {}
        ctx_path = make_abs(scratch.get("ctx_path"), root_dir)
        if ctx_path is not None:
            scratch["ctx_path"] = ctx_path

    return found


def classify_objdiff_symbol(sym: Dict[str, Any]) -> str:
    """Classify an objdiff symbol as 'function', 'object', or 'section'."""
    kind = sym.get("kind", "")
    if kind == "SYMBOL_FUNCTION":
        return "function"
    if kind == "SYMBOL_OBJECT":
        return "object"
    if kind == "SYMBOL_SECTION":
        return "section"
    if "instructions" in sym:
        return "function"
    if "data_diff" in sym:
        return "object"
    return "unknown"


def objdiff_symbol_section(sym: Dict[str, Any], sections: List[Dict[str, Any]]) -> str:
    """Determine which section a symbol belongs to."""
    name = sym.get("name", "")
    if name.startswith("[."):
        return name[1:].split("-")[0].rstrip("]")
    if classify_objdiff_symbol(sym) == "function":
        return ".text"
    for sec in sections:
        kind = sec.get("kind", "")
        if kind in ("SECTION_DATA", "SECTION_BSS"):
            return sec["name"]
    return ".data"


def estimate_unmatched_bytes(
    size: int, match_percent: Optional[float], status: str
) -> int:
    """Estimate remaining unmatched bytes for a symbol."""
    size = max(int(size), 0)
    if size == 0:
        return 0
    if status in ("missing", "extra", "no_target", "no_source"):
        return size
    if status in ("match", "matching", "complete"):
        return 0
    if match_percent is None:
        return size

    clamped = max(0.0, min(float(match_percent), 100.0))
    if clamped >= 100.0:
        return 0

    unmatched = int(round(size * (100.0 - clamped) / 100.0))
    unmatched = max(1, unmatched)
    return min(size, unmatched)


def build_objdiff_symbol_rows(diff_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build normalized overview rows from objdiff JSON for both left and right symbols."""
    left_syms = diff_data.get("left", {}).get("symbols", [])
    right_syms = diff_data.get("right", {}).get("symbols", [])
    left_sections = diff_data.get("left", {}).get("sections", [])
    right_sections = diff_data.get("right", {}).get("sections", [])

    rows: List[Dict[str, Any]] = []

    for sym in left_syms:
        sym_type = classify_objdiff_symbol(sym)
        if sym_type in ("section", "unknown"):
            continue

        size = int(sym.get("size", "0"))
        if size == 0:
            continue

        name = sym.get("demangled_name", sym.get("name", "?"))
        section = objdiff_symbol_section(sym, left_sections)
        target_symbol = sym.get("target_symbol")
        match_percent = sym.get("match_percent")

        if target_symbol is None:
            status = "missing"
        elif match_percent is not None and match_percent >= 100.0:
            status = "match"
        elif match_percent is not None:
            status = "nonmatching"
        else:
            status = "missing"

        rows.append(
            {
                "status": status,
                "match_percent": match_percent,
                "size": size,
                "unmatched_bytes_est": estimate_unmatched_bytes(
                    size, match_percent, status
                ),
                "section": section,
                "type": sym_type,
                "name": name,
                "symbol_name": sym.get("name", "?"),
                "side": "left",
                "left_symbol": sym,
                "right_symbol": right_syms[target_symbol]
                if target_symbol is not None and target_symbol < len(right_syms)
                else None,
            }
        )

    for sym in right_syms:
        if sym.get("target_symbol") is not None:
            continue

        sym_type = classify_objdiff_symbol(sym)
        if sym_type in ("section", "unknown"):
            continue

        size = int(sym.get("size", "0"))
        if size == 0:
            continue

        name = sym.get("demangled_name", sym.get("name", "?"))
        section = objdiff_symbol_section(sym, right_sections)
        rows.append(
            {
                "status": "extra",
                "match_percent": None,
                "size": size,
                "unmatched_bytes_est": estimate_unmatched_bytes(size, None, "extra"),
                "section": section,
                "type": sym_type,
                "name": name,
                "symbol_name": sym.get("name", "?"),
                "side": "right",
                "left_symbol": None,
                "right_symbol": sym,
            }
        )

    return rows


def run_objdiff_json(
    objdiff_cli: str,
    unit_name: str,
    *,
    base_obj: Optional[str] = None,
    extra_args: Optional[Sequence[str]] = None,
    reloc_diffs: str = "none",
    root_dir: str = ROOT_DIR,
) -> Dict[str, Any]:
    ensure_project_prereqs()

    cmd = [objdiff_cli, "diff"]
    cmd.extend(OBJDIFF_DEFAULT_CONFIG_ARGS)
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(["-u", unit_name, "-o", "-", "--format", "json"])

    cwd = root_dir
    tmpdir = None
    if base_obj is not None:
        config = load_objdiff_config()
        if not apply_base_obj_override(config, unit_name, base_obj, root_dir=root_dir):
            raise ToolError(f"Unit not found in objdiff.json: {unit_name}")

        tmpdir = tempfile.mkdtemp(prefix="sr2_objdiff_")
        tmp_config = os.path.join(tmpdir, "objdiff.json")
        with open(tmp_config, "w") as f:
            json.dump(config, f)
        cwd = tmpdir

    try:
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                text=True,
                capture_output=True,
            )
        except FileNotFoundError:
            raise ToolError(
                f"Missing objdiff-cli: {objdiff_cli}\n"
                "Hint: ensure build/tools is populated in this worktree "
                "(for example via the shared worktree assets setup)."
            )
        if result.returncode != 0:
            stderr = result.stderr
            hint_lines = []
            missing_path = None

            if "No such file or directory" in stderr:
                match = re.search(r"Failed:\s+Loading\s+(.+)", stderr)
                if match:
                    missing_path = match.group(1).strip()

            if missing_path is not None:
                if base_obj is not None:
                    hint_lines.extend(
                        [
                            f"Hint: the requested base object is missing: {missing_path}",
                            "Rebuild that object or point --base-obj at an existing file.",
                        ]
                    )
                else:
                    hint_lines.extend(
                        [
                            f"Hint: the shared build output for {unit_name} is missing: {missing_path}",
                            "Fastest fixes:",
                            f"  python tools/decomp-workflow.py build -u {unit_name}",
                            "Wrapper flows for inspection after rebuilding:",
                            f"  python tools/decomp-workflow.py unit -u {unit_name}",
                            f"  python tools/decomp-workflow.py diff -u {unit_name} ...",
                            "Or rebuild shared outputs with: ninja all_source",
                        ]
                    )

            message = format_subprocess_error(
                cmd, result.returncode, result.stdout, result.stderr
            )
            if hint_lines:
                message += "\n" + "\n".join(hint_lines)
            raise ToolError(
                message
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ToolError(f"objdiff-cli returned invalid JSON: {e}")
    finally:
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Symbol-addr helpers shared between decomp-scaffold.py and stub_guard.py
# ---------------------------------------------------------------------------

def grep_symbol_addrs(class_name: str) -> Tuple[List[str], List[str]]:
    """Return (non_weak_lines, weak_lines) for symbols OWNED by class_name.

    Uses the MWCC owner tag '__N<classname>' to avoid matching symbols from
    other classes that merely reference class_name as a parameter type.
    """
    non_weak: List[str] = []
    weak: List[str] = []
    if not os.path.exists(_SR2_SYMBOLS):
        return non_weak, weak
    owner_tag = f"__{len(class_name)}{class_name}"
    with open(_SR2_SYMBOLS) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            sym_name = stripped.split("=")[0].strip()
            if sym_name.startswith("@STRING@"):
                continue
            if owner_tag not in sym_name:
                continue
            if "visibility:weak" in stripped and "allow_duplicated:true" in stripped:
                weak.append(stripped)
            else:
                non_weak.append(stripped)
    return non_weak, weak


def demangle_symbol(mangled: str) -> Optional[str]:
    """Run dtk demangle on a mangled symbol name; return the demangled string."""
    if not os.path.exists(DTK):
        return None
    result = subprocess.run(
        [DTK, "demangle", mangled],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    text = result.stdout.strip() or None
    if text is None:
        return None
    # Fix function pointer parameter syntax: dtk outputs
    # 'type(*)[N][M] name' but C/C++ requires 'type (*name)[N][M]'
    text = re.sub(
        r'(\w+)\(\*\)(\[[\d]+\])*\s+(\w+)',
        r'\1 (*\3)\2',
        text,
    )
    return text


# ---------------------------------------------------------------------------
# Line-info helpers — shared between stub_guard, c_guard, and decomp-scaffold
# ---------------------------------------------------------------------------

_DEBUG_LINES = os.path.join(ROOT_DIR, "symbols", "sr2_line_info.nothpp")
_LINE_INFO_CACHE: Optional[List[Tuple[int, int]]] = None
_ADDR_RE_SYM = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")


def load_line_info() -> List[Tuple[int, int]]:
    """Parse sr2_line_info.nothpp once into a sorted [(addr, lineno)] list."""
    global _LINE_INFO_CACHE
    if _LINE_INFO_CACHE is not None:
        return _LINE_INFO_CACHE
    entries: List[Tuple[int, int]] = []
    if not os.path.exists(_DEBUG_LINES):
        _LINE_INFO_CACHE = entries
        return entries
    re_insn = re.compile(r'^\s+([0-9A-Fa-f]{5,})\s*:\t')
    re_src = re.compile(r'^\S[^\r\n]*:(\d+)\s*$')
    pending: Optional[int] = None
    with open(_DEBUG_LINES, 'r', errors='replace') as fh:
        for raw in fh:
            line = raw.rstrip('\n')
            m = re_src.match(line)
            if m:
                pending = int(m.group(1))
                continue
            m = re_insn.match(line)
            if m and pending is not None:
                entries.append((int(m.group(1), 16), pending))
                pending = None
    _LINE_INFO_CACHE = entries
    return entries


def sym_lineno(sym_line: str) -> int:
    """Return source line number for a symbol_addrs line, or maxint if unknown."""
    m = _ADDR_RE_SYM.search(sym_line)
    if not m:
        return 2**31
    addr = int(m.group(1), 16)
    entries = load_line_info()
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
    if abs(entries[best][0] - addr) > 4:
        return 2**31
    return entries[best][1]


def find_c_sym_line(func_name: str) -> Optional[str]:
    """Find the symbol_addrs.txt entry for a plain C function by name.

    MWCC mangles C functions as 'funcname__Fparams', so we look for lines
    whose symbol starts with 'funcname__' or is exactly 'funcname'.
    """
    if not os.path.exists(_SR2_SYMBOLS):
        return None
    prefix = func_name + "__"
    with open(_SR2_SYMBOLS) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            sym_name = stripped.split("=")[0].strip()
            if sym_name == func_name or sym_name.startswith(prefix):
                return stripped
    return None


def get_non_weak_funcs(class_name: str) -> List[Tuple[str, str, str]]:
    """Return (sym_line, mangled, demangled) for non-weak functions of class_name.

    Skips vtable symbols. Uses the same classification logic as decomp-scaffold.py
    so stub_guard.py and scaffold always agree on which functions must be defined.
    """
    non_weak, _ = grep_symbol_addrs(class_name)
    result: List[Tuple[str, str, str]] = []
    for sym_line in non_weak:
        mangled = sym_line.split("=")[0].strip()
        if mangled.startswith("__vt__"):
            continue
        demangled = demangle_symbol(mangled) or mangled
        if "(" in demangled:
            result.append((sym_line, mangled, demangled))
    return result


_DWARF_RANGE_RE = re.compile(r"^// Range:\s*(0x[0-9A-Fa-f]+)")
_DWARF_SKIP_KW = frozenset([
    'class', 'struct', 'const', 'volatile', 'void', 'unsigned', 'signed',
    'short', 'long', 'int', 'float', 'double', 'char', 'bool',
])


def _dwarf_split_commas(s: str) -> List[str]:
    """Split s on top-level commas (not inside <> or ())."""
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


def _extract_dwarf_name(chunk: str) -> Optional[str]:
    """Extract the parameter name from a DWARF param chunk (type + optional name)."""
    chunk = re.sub(r'\s*\[[^\]]*\]\s*', '', chunk).strip()
    chunk = re.sub(r'[()[\]*&]+$', '', chunk).strip()
    tokens = re.findall(r'\b([A-Za-z_]\w*)\b', chunk)
    for tok in reversed(tokens):
        if tok not in _DWARF_SKIP_KW:
            return tok
    return None


def get_dwarf_params(addr_str: str) -> Dict[int, str]:
    """Return {0-based position: name} for DWARF-annotated params, or {} if unknown.

    Extracts names from MWCC DWARF register annotations (/* r16 */ etc.).
    Correctly handles partial annotation: when only some params have register
    comments, the returned dict maps each annotated param to its true position.
    """
    dwarf_dir = os.path.join(ROOT_DIR, "symbols", "Dwarf")
    try:
        result = subprocess.run(
            [sys.executable, tool_path("lookup.py"), dwarf_dir, "function", addr_str],
            cwd=ROOT_DIR, text=True, capture_output=True,
        )
        if result.returncode != 0:
            return {}
        lines = result.stdout.splitlines()
        try:
            addr_int = int(addr_str, 16)
        except ValueError:
            return {}
        # Verify the returned block's Range start matches the requested address.
        for line in lines:
            m = _DWARF_RANGE_RE.match(line.strip())
            if m:
                if int(m.group(1), 16) != addr_int:
                    return {}
                break
        for line in lines:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            inner_m = re.search(r'\((.+)\)\s*(?:\{)?\s*$', line)
            if not inner_m:
                continue
            raw = inner_m.group(1)
            # Each chunk is the text before a /* rN */ annotation.
            # It may contain multiple unannotated params followed by the annotated one.
            chunks = re.split(r'/\*[^*]+\*/', raw)
            param_map: Dict[int, str] = {}
            position = 0
            for chunk in chunks[:-1]:
                chunk = chunk.strip().lstrip(',').strip()
                if not chunk:
                    position += 1
                    continue
                sub = _dwarf_split_commas(chunk)
                # All sub-parts except the last are unannotated (advance position only).
                position += len(sub) - 1
                # Last sub-part is the annotated param.
                name = _extract_dwarf_name(sub[-1]) if sub else None
                if name:
                    param_map[position] = name
                position += 1
            return param_map
    except Exception:
        pass
    return {}
