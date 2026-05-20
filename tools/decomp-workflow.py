#!/usr/bin/env python3

"""
Wrapper for common decomp workflows.

This script keeps the existing tools as the source of truth and orchestrates the
most common agent flows:

  python tools/decomp-workflow.py scaffold -c clsMotion
  python tools/decomp-workflow.py scaffold -c clsMotion --brief
  python tools/decomp-workflow.py scaffold -c clsMotion --deps-deep
  python tools/decomp-workflow.py scaffold -c clsMotion --no-line-lookup --enum enmStatus
  python tools/decomp-workflow.py health
  python tools/decomp-workflow.py health --smoke-build Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp
  python tools/decomp-workflow.py function -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
  python tools/decomp-workflow.py function -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup" --brief
  python tools/decomp-workflow.py function -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup" --ghidra-version gc
  python tools/decomp-workflow.py function -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup" --lookup-mode full
  python tools/decomp-workflow.py function -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup" --no-lookup
  python tools/decomp-workflow.py function -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup" --no-source
  python tools/decomp-workflow.py diff -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -d "clsPrfm::setup" --reloc-diffs all
  python tools/decomp-workflow.py dwarf -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
  python tools/decomp-workflow.py dwarf -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setMaxAgp(float)" --full-diff
  python tools/decomp-workflow.py verify -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
  python tools/decomp-workflow.py unit -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp
  python tools/decomp-workflow.py validate Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp
"""

import argparse
import json
import re
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
from _common import (
    BUILD_NINJA,
    OBJDIFF_JSON,
    RELOC_DIFF_CHOICES,
    ROOT_DIR,
    TOOLS_DIR,
    ToolError,
    WorkflowError,
    build_objdiff_symbol_rows,
    ensure_exists,
    find_objdiff_unit,
    format_subprocess_error,
    load_objdiff_config,
    make_abs,
    print_section,
    python_tool,
    run_capture,
    run_objdiff_json,
    run_stream,
    # tool_path,
)


_SR2_SYMBOLS = os.path.join(ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "symbol_addrs.txt")
_EXE = ".exe" if sys.platform == "win32" else ""
DTK = os.path.join(ROOT_DIR, "build", "tools", "dtk" + _EXE)
OBJDIFF_CLI = os.path.join(ROOT_DIR, "build", "tools", "objdiff-cli" + _EXE)
GC_SYMBOLS = _SR2_SYMBOLS
PS2_SYMBOLS = _SR2_SYMBOLS
GC_DWARF = os.path.join(ROOT_DIR, "symbols", "Dwarf")
DEBUG_LINES = os.path.join(ROOT_DIR, "symbols", "sr2_line_info.nothpp")

DEFAULT_SMOKE_UNIT = "Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp"
DEBUG_SYMBOL_PROBE_MANGLED = "setMaxAgp__7clsPrfmFf"
DEBUG_SYMBOL_PROBE_DEMANGLED = "clsPrfm::setMaxAgp(float)"
DEBUG_SYMBOL_PROBE_GC_ADDR = "0x001E1410"
DEBUG_LINES_PROBE_ADDR = "0x001E1414"
REBUILT_DEBUG_LINE_RE = re.compile(r"^\s*([0-9A-Fa-f]+)\s*:")
LOW_MATCH_PRIORITY_THRESHOLD = 60.0
VERY_LOW_MATCH_PRIORITY_THRESHOLD = 40.0
HIGH_MATCH_CLEANUP_THRESHOLD = 85.0
VERY_HIGH_MATCH_CLEANUP_THRESHOLD = 95.0

SHARED_ASSET_REQUIREMENTS = [
    (os.path.join("build", "tools"), "downloaded tooling"),
    (os.path.join("orig", "SLUS-21642-PROTO-070901", "SLUS_216.42"), "PS2 original ELF"),
    (os.path.join("symbols", "Dwarf"), "DWARF dump"),
]


def ensure_decomp_prereqs() -> None:
    try:
        ensure_exists(BUILD_NINJA, "Run: python configure.py")
        ensure_exists(OBJDIFF_JSON, "Run: python configure.py")
    except ToolError as e:
        raise WorkflowError(str(e))


def get_unit_build_target(unit_name: str) -> str:
    config = load_objdiff_config()
    unit = find_objdiff_unit(config, unit_name)
    if unit is None:
        raise WorkflowError(f"Unit not found in objdiff.json: {unit_name}")

    target = unit.get("base_path") or unit.get("target_path")
    if not target:
        raise WorkflowError(f"Unit has no build target in objdiff.json: {unit_name}")
    return str(target)


def get_unit_build_output(unit_name: str) -> str:
    target = get_unit_build_target(unit_name)
    return make_abs(target) or target


def build_shared_unit(unit_name: str, quiet: bool = False) -> str:
    ensure_decomp_prereqs()
    target = get_unit_build_target(unit_name)
    if quiet:
        cmd = ["ninja", target]
        result = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            raise WorkflowError(
                format_subprocess_error(cmd, result.returncode, result.stdout, result.stderr)
            )
    else:
        _ninja_errors = os.path.join(TOOLS_DIR, "ninja-errors.py")
        result = subprocess.run(
            [sys.executable, _ninja_errors, target],
            cwd=ROOT_DIR,
            text=True,
        )
        if result.returncode != 0:
            # ninja-errors.py already printed the filtered error blocks; raise
            # a blank WorkflowError so the exit code propagates without noise.
            raise WorkflowError("")
    return get_unit_build_output(unit_name)


def ensure_shared_unit_output(unit_name: str) -> str:
    output_path = get_unit_build_output(unit_name)
    if os.path.exists(output_path):
        return output_path

    print(f"Shared build missing for {unit_name}; rebuilding...", flush=True)
    try:
        output_path = build_shared_unit(unit_name, quiet=True)
    except WorkflowError as e:
        raise WorkflowError(
            f"Auto-build failed while preparing shared output for {unit_name}\n{e}"
        )
    print(f"Shared build ready: {output_path}", flush=True)
    return output_path


def maybe_remove(path: Optional[str]) -> None:
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as e:
        print(f"Warning: failed to remove temporary file {path}: {e}", file=sys.stderr)


def dtk_dwarf_dump(obj_path: str) -> str:
    fd, output_path = tempfile.mkstemp(prefix="sr2_dtk_", suffix=".nothpp")
    os.close(fd)
    maybe_remove(output_path)

    result = subprocess.run(
        [DTK, "dwarf", "dump", obj_path, "-o", output_path],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        maybe_remove(output_path)
        raise WorkflowError(
            format_subprocess_error([DTK, "dwarf", "dump", obj_path, "-o", output_path], result.returncode, result.stdout, result.stderr)
        )

    tool_output = "\n".join(
        part.strip() for part in [result.stdout, result.stderr] if part.strip()
    )
    if "ERROR " in tool_output or tool_output.startswith("ERROR"):
        maybe_remove(output_path)
        raise WorkflowError(f"dtk reported an error while dumping DWARF:\n{tool_output}")

    if not os.path.exists(output_path):
        raise WorkflowError("dtk dwarf dump succeeded but did not write an output file")

    return output_path


def describe_path(path: str) -> str:
    if os.path.islink(path):
        return "shared-symlink"
    return "present"


def _resolve_unit_path(unit_name: str) -> str:
    """Resolve a short unit name to its canonical src/-relative path.

    Accepts:
      - Filename only:        'Foo.cpp'
      - Partial suffix:       'Object/Player/Key/Foo.cpp'
      - Full canonical form:  'Develop/Projects/SR2/pgm/src/.../Foo.cpp'

    Returns the canonical path (relative to src/). Raises WorkflowError if
    not found or if the name is ambiguous.
    """
    src_dir = os.path.join(ROOT_DIR, "src")
    norm = unit_name.replace("\\", "/")

    # Fast path: exact match
    if os.path.exists(os.path.join(src_dir, norm)):
        return norm

    # Suffix search across all .cpp files under src/
    matches: List[str] = []
    for dirpath, _dirs, files in os.walk(src_dir):
        for fname in files:
            if not fname.endswith(".cpp"):
                continue
            full = os.path.join(dirpath, fname).replace("\\", "/")
            rel = os.path.relpath(full, src_dir).replace("\\", "/")
            if rel == norm or rel.endswith("/" + norm):
                matches.append(rel)

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise WorkflowError(
            f"Ambiguous unit '{unit_name}' — {len(matches)} matches:\n"
            + "\n".join(f"  -u {m}" for m in sorted(matches))
        )
    raise WorkflowError(
        f"No source file found matching '{unit_name}'\n"
        "This unit has no .cpp yet — scaffold the class first:\n"
        "  python tools/decomp-workflow.py scaffold -c <ClassName>\n"
        "Then create the stub .cpp and run: python configure.py"
    )


def _check_source_exists(unit_name: str) -> str:
    """Validate unit exists and return its canonical src/-relative path."""
    return _resolve_unit_path(unit_name)


def fuzzy_match(pattern: str, name: str) -> bool:
    return pattern.lower() in name.lower()


def strip_template_args(name: str) -> str:
    """Remove C++ template argument lists from a demangled symbol name."""
    out: List[str] = []
    depth = 0
    for ch in name:
        if ch == "<":
            depth += 1
            continue
        if ch == ">" and depth > 0:
            depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def find_objdiff_rows_for_function(
    unit_name: str, function_name: str, reloc_diffs: str = "none"
) -> List[Dict[str, Any]]:
    data = run_objdiff_json(
        OBJDIFF_CLI,
        unit_name,
        reloc_diffs=reloc_diffs,
        root_dir=ROOT_DIR,
    )
    rows = [
        row
        for row in build_objdiff_symbol_rows(data)
        if row["type"] == "function"
    ]

    exact_matches = [
        row
        for row in rows
        if function_name in row["name"] or function_name in row["symbol_name"]
    ]
    if exact_matches:
        return exact_matches

    stripped_function_name = strip_template_args(function_name)
    stripped_matches = [
        row
        for row in rows
        if stripped_function_name in strip_template_args(row["name"])
        or stripped_function_name in strip_template_args(row["symbol_name"])
    ]
    if stripped_matches:
        return stripped_matches

    return [
        row
        for row in rows
        if fuzzy_match(function_name, row["name"])
        or fuzzy_match(function_name, row["symbol_name"])
    ]


def choose_objdiff_row(unit_name: str, function_name: str, reloc_diffs: str = "none") -> Dict[str, Any]:
    matches = find_objdiff_rows_for_function(unit_name, function_name, reloc_diffs=reloc_diffs)
    if not matches:
        raise WorkflowError(
            f"objdiff: function '{function_name}' not found in {unit_name}.\n"
            "Hint: run `python tools/decomp-workflow.py unit -u "
            f"{unit_name} --search {shlex.quote(function_name)}` to inspect nearby symbols."
        )

    if len(matches) > 1:
        preview = "\n".join(f"  - {row['name']}" for row in matches[:8])
        extra = ""
        if len(matches) > 8:
            extra = f"\n  ... {len(matches) - 8} more"
        raise WorkflowError(
            f"objdiff: function query '{function_name}' matched multiple symbols in {unit_name}.\n"
            f"Use a more specific function name.\n{preview}{extra}"
        )
    return matches[0]


def load_dwarf_report(
    unit_name: str,
    function_name: str,
    rebuilt_dwarf_file: Optional[str] = None,
) -> Dict[str, Any]:
    cmd: List[str] = python_tool("dwarf-compare.py", "-u", unit_name, "-f", function_name, "--json")
    if rebuilt_dwarf_file:
        cmd.extend(["--rebuilt-dwarf-file", rebuilt_dwarf_file])
    result = run_capture(cmd)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise WorkflowError(f"dwarf-compare.py returned invalid JSON: {e}")


def lookup_symbol_address(symbols_file: str, mangled_name: str) -> Optional[str]:
    if not os.path.exists(symbols_file):
        return None

    pattern = re.compile(
        r"^" + re.escape(mangled_name) + r"\s*=\s*(?:\.(\w+):)?0x([0-9A-Fa-f]+)"
    )
    with open(symbols_file) as f:
        for line in f:
            match = pattern.match(line.strip())
            if match:
                return "0x" + match.group(2)
    return None


def command_health(args: argparse.Namespace) -> None:
    failures = 0
    timings: List[Tuple[str, float]] = []
    build_cache: Dict[str, str] = {}

    smoke_build_unit = args.smoke_build or args.full
    smoke_dtk_unit = args.smoke_dtk or args.full

    print_section("Worktree Health")
    print(f"Root: {ROOT_DIR}")

    def report(ok: bool, label: str, detail: str) -> None:
        nonlocal failures
        status = "OK  " if ok else "FAIL"
        print(f"{status} {label}: {detail}", flush=True)
        if not ok:
            failures += 1

    def timed(label: str, func):
        start = time.monotonic()
        try:
            return func()
        finally:
            timings.append((label, time.monotonic() - start))

    def build_shared_unit_cached(unit: str) -> str:
        if unit in build_cache:
            return build_cache[unit]
        output_path = timed(f"build {unit}", lambda: build_shared_unit(unit))
        build_cache[unit] = output_path
        return output_path

    report(
        os.path.exists(BUILD_NINJA),
        "build.ninja",
        BUILD_NINJA
        if os.path.exists(BUILD_NINJA)
        else "missing (run: python tools/share_worktree_assets.py bootstrap)",
    )
    report(
        os.path.exists(OBJDIFF_JSON),
        "objdiff.json",
        OBJDIFF_JSON
        if os.path.exists(OBJDIFF_JSON)
        else "missing (run: python tools/share_worktree_assets.py bootstrap)",
    )

    print_section("Shared Assets")
    for rel_path, label in SHARED_ASSET_REQUIREMENTS:
        abs_path = os.path.join(ROOT_DIR, rel_path)
        report(
            os.path.exists(abs_path),
            label,
            describe_path(abs_path) if os.path.exists(abs_path) else f"missing ({rel_path})",
        )

    print_section("Tool Checks")
    report(
        os.path.exists(OBJDIFF_CLI),
        "objdiff-cli",
        OBJDIFF_CLI if os.path.exists(OBJDIFF_CLI) else "missing (seed build/tools in this worktree)",
    )
    report(
        os.path.exists(DTK),
        "dtk",
        DTK if os.path.exists(DTK) else "missing (seed build/tools in this worktree)",
    )
    try:
        timed("ghidra-check", lambda: run_capture(python_tool("decomp-context.py", "--ghidra-check")))
        report(True, "ghidra", "Wii + PS2 programs available")
    except WorkflowError as e:
        report(False, "ghidra", str(e))

    print_section("Debug Symbol Checks")
    try:
        gc_addr = lookup_symbol_address(GC_SYMBOLS, DEBUG_SYMBOL_PROBE_MANGLED)
        report(
            gc_addr == DEBUG_SYMBOL_PROBE_GC_ADDR,
            "gc-symbols",
            gc_addr or f"missing ({DEBUG_SYMBOL_PROBE_MANGLED})",
        )
    except Exception as e:
        report(False, "gc-symbols", str(e))

    try:
        ps2_addr = lookup_symbol_address(PS2_SYMBOLS, DEBUG_SYMBOL_PROBE_MANGLED)
        report(
            ps2_addr is not None,
            "ps2-symbols",
            ps2_addr or f"missing ({DEBUG_SYMBOL_PROBE_MANGLED})",
        )
    except Exception as e:
        report(False, "ps2-symbols", str(e))

    try:
        run_capture(
            python_tool("lookup.py", GC_DWARF, "function", DEBUG_SYMBOL_PROBE_DEMANGLED)
        )
        report(True, "gc-dwarf", f"{DEBUG_SYMBOL_PROBE_DEMANGLED} found")
    except WorkflowError as e:
        report(False, "gc-dwarf", str(e))

    try:
        run_capture(python_tool("lookup.py", GC_DWARF, "struct", "clsPrfm"))
        report(True, "dwarf-struct", "clsPrfm found in DWARF dump")
    except WorkflowError as e:
        report(False, "dwarf-struct", str(e))

    try:
        result = run_capture(
            python_tool("line_lookup.py", DEBUG_LINES, DEBUG_LINES_PROBE_ADDR)
        )
        ok = "Exact match found" in result.stdout and "Performance" in result.stdout
        detail = "Performance.cpp exact match" if ok else "unexpected line lookup output"
        report(ok, "debug-lines", detail)
    except WorkflowError as e:
        report(False, "debug-lines", str(e))

    if smoke_build_unit:
        print_section("Build Smoke Test")
        try:
            output_path = build_shared_unit_cached(smoke_build_unit)
            report(True, "build", output_path)
        except WorkflowError as e:
            detail = str(e)
            if "objdiff.json" in detail or "build.ninja" in detail:
                detail += "\nHint: Run: python tools/share_worktree_assets.py bootstrap"
            report(False, "build", detail)

    if smoke_dtk_unit:
        print_section("DTK Smoke Test")
        dump_path = None
        debug_lines_dir = None
        try:
            obj_path = build_shared_unit_cached(smoke_dtk_unit)
            dump_path = timed(f"dtk dump {smoke_dtk_unit}", lambda: dtk_dwarf_dump(obj_path))
            report(True, "dtk", dump_path)
        except WorkflowError as e:
            report(False, "dtk", str(e))
        else:
            try:
                debug_lines_dir = tempfile.mkdtemp(prefix="sr2_health_debug_lines_")
                timed(
                    f"debug-line export {smoke_dtk_unit}",
                    lambda: run_capture(
                        python_tool("dwarf1_gcc_line_info.py", obj_path, debug_lines_dir)
                    ),
                )
                rebuilt_debug_lines = os.path.join(debug_lines_dir, "debug_lines.txt")
                if not os.path.exists(rebuilt_debug_lines):
                    raise WorkflowError(
                        "rebuilt debug-line export did not produce debug_lines.txt"
                    )
                first_address = None
                with open(rebuilt_debug_lines) as f:
                    for raw_line in f:
                        match = REBUILT_DEBUG_LINE_RE.match(raw_line)
                        if match is not None:
                            first_address = match.group(1)
                            break
                if first_address is None:
                    raise WorkflowError(
                        "rebuilt debug-line export produced no address entries"
                    )
                result = timed(
                    f"rebuilt line lookup {smoke_dtk_unit}",
                    lambda: run_capture(
                        python_tool("line_lookup.py", rebuilt_debug_lines, first_address)
                    ),
                )
                ok = "Exact match found" in result.stdout
                detail = (
                    f"rebuilt line export ok ({first_address})"
                    if ok
                    else "rebuilt line lookup output did not contain an exact match"
                )
                report(ok, "rebuilt-debug-lines", detail)
            except WorkflowError as e:
                report(False, "rebuilt-debug-lines", str(e))
        finally:
            maybe_remove(dump_path)
            if debug_lines_dir is not None:
                shutil.rmtree(debug_lines_dir, ignore_errors=True)

    if args.timings and timings:
        print_section("Timings")
        for label, elapsed in timings:
            print(f"{elapsed:7.2f}s  {label}")

    if failures:
        raise WorkflowError(f"Health check failed with {failures} issue(s)")


def build_next_candidates(
    status_data: Dict[str, Any], strategy: str
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    for category, entries in status_data.items():
        for entry in entries:
            unit_name = entry.get("name", "")
            display_unit = unit_name.replace("main/", "")
            has_source = bool(entry.get("has_source"))

            for func in entry.get("top_unmatched_functions", []):
                function_name = func.get("name", "?")
                unmatched = int(func.get("unmatched_bytes_est", 0))
                match_percent = func.get("match_percent")
                status = func.get("status", "?")
                size = int(func.get("size", 0))
                is_static_init = function_name.startswith(
                    "__static_initialization_and_destruction_0"
                )
                is_initializer = "InitializeTables" in function_name or is_static_init
                reason = "largest remaining byte win"
                score = float(unmatched)

                if strategy == "balanced":
                    if status == "missing":
                        score *= 1.15
                        reason = "whole implementation still missing; high remaining gain"
                    elif status == "nonmatching":
                        score *= 1.05
                        reason = "large remaining win"

                    if match_percent is not None:
                        if match_percent >= VERY_HIGH_MATCH_CLEANUP_THRESHOLD:
                            score *= 0.2
                            reason = (
                                "near-finished cleanup deprioritized in favor of larger remaining gains"
                            )
                        elif match_percent >= HIGH_MATCH_CLEANUP_THRESHOLD:
                            score *= 0.45
                            reason = (
                                "high-match cleanup deprioritized in favor of larger remaining gains"
                            )
                        elif match_percent <= VERY_LOW_MATCH_PRIORITY_THRESHOLD:
                            score *= 1.25
                            reason = "low match % leaves a large amount of work and upside"
                        elif match_percent <= LOW_MATCH_PRIORITY_THRESHOLD:
                            score *= 1.1
                            reason = "plenty of unmatched work remains here"

                    if has_source:
                        score *= 1.08
                        if "source available" not in reason and "deprioritized" not in reason:
                            reason += " with source available"
                    if is_initializer:
                        score *= 0.3
                        reason = (
                            "large remaining win, but likely lower-priority init/setup work"
                        )
                elif strategy == "quick-wins":
                    score = min(float(unmatched), 1024.0)
                    if status == "missing":
                        score *= 1.05
                        reason = "whole implementation missing; early progress should come quickly"
                    elif status == "nonmatching":
                        score *= 1.1
                        reason = "partial implementation exists, but this is still early-progress work"

                    if match_percent is None:
                        score *= 1.35
                        reason = "0% function; early implementation progress is usually fastest"
                    elif match_percent <= VERY_LOW_MATCH_PRIORITY_THRESHOLD:
                        score *= 1.35
                        reason = "very low match % leaves fast early-progress gains"
                    elif match_percent <= LOW_MATCH_PRIORITY_THRESHOLD:
                        score *= 1.2
                        reason = "low match % usually moves faster than cleanup"
                    elif match_percent >= VERY_HIGH_MATCH_CLEANUP_THRESHOLD:
                        score *= 0.12
                        reason = "near-finished cleanup is slower than fresh early-progress work"
                    elif match_percent >= HIGH_MATCH_CLEANUP_THRESHOLD:
                        score *= 0.35
                        reason = "high-match cleanup deprioritized; quicker gains exist earlier"
                    elif match_percent >= 70.0:
                        score *= 0.75
                        reason = "mid/high-match work is less likely to be a quick win"
                    if has_source:
                        score *= 1.05
                        if "source" not in reason:
                            reason += " with source available"
                    if is_initializer:
                        score *= 0.1
                        reason = (
                            "deprioritized init/setup work; likely not the fastest useful win"
                        )

                candidates.append(
                    {
                        "category": category,
                        "unit": unit_name,
                        "display_unit": display_unit,
                        "function": function_name,
                        "status": status,
                        "size": size,
                        "match_percent": match_percent,
                        "unmatched_bytes_est": unmatched,
                        "score": score,
                        "reason": reason,
                    }
                )

    candidates.sort(
        key=lambda c: (
            -c["score"],
            c["match_percent"] if c["match_percent"] is not None else -1.0,
            -c["unmatched_bytes_est"],
            -c["size"],
            c["function"].lower(),
        )
    )
    return candidates


def command_scaffold_next(args: argparse.Namespace) -> None:
    # Step 1: collect known class/struct/namespace names from all .hpp and .h files under
    # include/.  Scanning .h files ensures SDK types (NNS_VECTOR*, allocator, hk*, …) that
    # live in usr/local SDK headers are recognised as already-declared and not treated as
    # missing dependencies.
    # Only count lines that open a definition body ({) — bare forward declarations like
    # "class clsFoo;" must not mark a class as scaffolded, because its canonical header
    # may still be an empty placeholder even when another header forward-declares it.
    include_dir = os.path.join(ROOT_DIR, "include")
    known_classes: set = set()
    cls_pat = re.compile(r"(?:class|struct|namespace)\s+(\w+)")
    for dirpath, _dirs, files in os.walk(include_dir):
        for fname in files:
            if not fname.endswith((".hpp", ".h")):
                continue
            try:
                with open(os.path.join(dirpath, fname), encoding="utf-8", errors="replace") as fh:
                    # Track the last seen class/struct name without a matching '{'.
                    # Handles 2-line AND 3-line (template) definitions, e.g.:
                    #   class clsFoo                        ← name line
                    #       : public clsTemplate<A, B,      ← continuation
                    #                            C> {        ← {-line, no name
                    pending_class: Optional[str] = None
                    for line in fh:
                        stripped = line.strip()

                        # Skip comments immediately to avoid false positives
                        # from class names in documentation/notes.
                        if stripped.startswith(("//", "*")):
                            continue

                        if "{" in line:
                            found = False
                            for m in cls_pat.finditer(line):
                                # Only add if there is no semicolon before the brace
                                # (distinguishes 'class Foo;' from 'class Foo {')
                                if ";" not in line[: line.find("{")]:
                                    known_classes.add(m.group(1))
                                    found = True

                            # If no name on the {-line, use the pending name from
                            # a previous line (handles template/inheritance blocks)
                            if not found and pending_class:
                                known_classes.add(pending_class)

                            pending_class = None
                        else:
                            # Update pending state based on new declarations
                            m = cls_pat.search(line)
                            if m:
                                # If the line ends with a semicolon, it's a forward decl
                                if stripped.endswith(";"):
                                    pending_class = None
                                else:
                                    pending_class = m.group(1)
                            elif stripped and not stripped.startswith(("//", "*", ":")):
                                # If it's a new top-level line (not a continuation), reset
                                if not line[0:1].isspace():
                                    pending_class = None
            except OSError:
                pass

    # Step 2: parse symbol_addrs.txt
    # MWCC mangled method: <name>__<N><classname>F  (N = digit(s) = len of classname)
    sym_pat = re.compile(r"__(\d+)(\w+)F")
    size_pat = re.compile(r"size:(\d+)")
    weak_pat = re.compile(r"visibility:weak|allow_duplicated:true")
    vtable_pat = re.compile(r"__vt__")
    thunk_pat = re.compile(r"^@")

    class_stats: Dict[str, Dict[str, int]] = {}

    if not os.path.exists(_SR2_SYMBOLS):
        raise WorkflowError(f"Symbol file not found: {_SR2_SYMBOLS}")

    with open(_SR2_SYMBOLS, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            # Extract the symbol name (before '=')
            eq_idx = stripped.find("=")
            if eq_idx < 0:
                continue
            sym_name = stripped[:eq_idx].strip()

            # Skip vtable and MI thunks
            if vtable_pat.search(sym_name):
                continue
            if thunk_pat.match(sym_name):
                continue

            # Skip weak / allow_duplicated symbols (inline bodies)
            comment_part = stripped[eq_idx:]
            if weak_pat.search(comment_part):
                continue

            # Must be a method: match __N<classname>F
            m = sym_pat.search(sym_name)
            if not m:
                continue
            n = int(m.group(1))
            class_name = m.group(2)[:n]
            if len(class_name) != n:
                continue

            # Skip templates and qualified names
            if "<" in class_name or "Q2" in sym_name[:sym_name.find("__")]:
                continue

            # Get size
            sm = size_pat.search(comment_part)
            size = int(sm.group(1)) if sm else 0

            if class_name not in class_stats:
                class_stats[class_name] = {"func_count": 0, "total_bytes": 0}
            class_stats[class_name]["func_count"] += 1
            class_stats[class_name]["total_bytes"] += size

    # Load explicit skip list (docs/scaffold-skip.txt by default)
    skip_list_path = getattr(args, "skip_list", None) or os.path.join(
        ROOT_DIR, "docs", "scaffold-skip.txt"
    )
    skip_listed: set = set()
    if os.path.exists(skip_list_path):
        with open(skip_list_path, encoding="utf-8", errors="replace") as _sf:
            for _line in _sf:
                _entry = _line.strip()
                # Strip inline comments (e.g. "clsFoo   # blocked as of 2026-05-03")
                _comment_idx = _entry.find("#")
                if _comment_idx >= 0:
                    _entry = _entry[:_comment_idx].strip()
                if _entry:
                    skip_listed.add(_entry)
        if skip_listed:
            known_classes.update(skip_listed)

    # Step 3: filter out already-scaffolded classes and zero-func classes
    candidates = [
        (name, stats["func_count"], stats["total_bytes"])
        for name, stats in class_stats.items()
        if name not in known_classes and stats["func_count"] > 0
    ]

    # Apply optional prefix filter
    prefixes: tuple = ()
    if args.skip_prefixes:
        prefixes = tuple(p for p in args.skip_prefixes.split(",") if p)
        candidates = [
            (name, fc, tb) for name, fc, tb in candidates
            if not any(name.startswith(p) for p in prefixes)
        ]

    # Stats snapshot (before any limit is applied)
    _all_with_funcs = [
        name for name, stats in class_stats.items()
        if stats["func_count"] > 0
        and not any(name.startswith(p) for p in prefixes)
    ]
    _total = len(_all_with_funcs)
    _remaining = len(candidates)
    _scaffolded = _total - _remaining

    # Step 4: initial rank by total_bytes desc, then func_count desc
    # (used to bound the DWARF probe loop — we probe the biggest classes first)
    candidates.sort(key=lambda x: (-x[2], -x[1], x[0].lower()))

    limit = args.limit if args.limit is not None else 20

    # Step 5: probe DWARF for each candidate.
    # Collect struct output, filter no-DWARF classes, score dependency readiness.
    # dep_score = number of class/struct names referenced in DWARF that are NOT
    # yet in known_classes.  Lower = fewer missing deps = more ready to scaffold.
    # Match: 'class/struct Name' OR 'public/private/protected Name'
    _dep_type_re = re.compile(
        r"\b(?:class|struct)\s+(\w+)" r"|\b(?:public|private|protected)\s+(\w+)"
    )
    # Types with these prefixes are external/SDK — never count as "missing" deps
    # regardless of whether they appear in known_classes.
    _BUILTIN_DEP_SKIP = ("NNS_", "NN_", "PF_", "__")
    dwarf_dir = os.path.join(ROOT_DIR, "symbols", "Dwarf")

    # --search: bypass the scoring loop entirely — do one targeted probe per match
    search_needle = getattr(args, "search", None)
    if search_needle:
        needle = search_needle.lower()
        sym_matches = [n for n in class_stats if needle in n.lower()]
        found_rows: List[Tuple[str, int, int, int, set]] = []
        diagnostics: List[Tuple[str, str]] = []
        if not sym_matches:
            print(f"  '{search_needle}': not found — no non-weak symbols in symbol_addrs.txt")
        else:
            for name in sym_matches:
                if name in skip_listed:
                    diagnostics.append((name, "skip-listed in docs/scaffold-skip.txt"))
                elif name in known_classes:
                    diagnostics.append((name, "already scaffolded (full definition found in headers)"))
                elif prefixes and any(name.startswith(p) for p in prefixes):
                    diagnostics.append((name, f"filtered by --skip-prefixes ({', '.join(prefixes)})"))
                else:
                    probe = subprocess.run(
                        python_tool("lookup.py", dwarf_dir, "struct", name),
                        cwd=ROOT_DIR, text=True, capture_output=True,
                    )
                    if probe.returncode == 0 and probe.stdout.strip():
                        dep_refs = set()
                        for m in _dep_type_re.finditer(probe.stdout):
                            dep_name = m.group(1) or m.group(2)
                            if dep_name and dep_name != name:
                                dep_refs.add(dep_name)
                        missing_dep_names = {
                            t for t in dep_refs
                            if t not in known_classes
                            and not any(t.startswith(p) for p in prefixes)
                            and not any(t.startswith(p) for p in _BUILTIN_DEP_SKIP)
                        }
                        fc = class_stats[name]["func_count"]
                        tb = class_stats[name]["total_bytes"]
                        found_rows.append((name, fc, tb, len(missing_dep_names), missing_dep_names))
                    else:
                        diagnostics.append((name, "no DWARF struct found"))
        if found_rows:
            if args.command_only:
                for name, _fc, _tb, _md, _mdn in found_rows:
                    print(f"python tools/decomp-workflow.py scaffold -c {name}")
            else:
                print_section(f"Scaffold Next — search: {search_needle}")
                print(f"  {'FUNCS':>5}  {'BYTES':>7}  {'MISS_DEPS':>9}  CLASS")
                print("-" * 72)
                for name, fc, tb, missing_deps, missing_dep_names in found_rows:
                    dep_tag = f" +{missing_deps}unscaffolded" if missing_deps else ""
                    print(f"  {fc:>5}  {tb:>7}  {missing_deps:>9}  {name}{dep_tag}")
                    print(f"          next: python tools/decomp-workflow.py scaffold -c {name}")
                    if missing_deps and missing_dep_names:
                        dep_list = ", ".join(sorted(missing_dep_names)[:5])
                        print(f"          ⛔ scaffold these blocking deps first: {dep_list}")
        for name, reason in diagnostics:
            print(f"  {name}: {reason}")
        return

    # scored tuple: (name, fc, tb, missing_deps, missing_dep_names)
    scored: List[Tuple[str, int, int, int, set]] = []
    no_dwarf_candidates: List[Tuple[str, int, int]] = []
    if os.path.exists(dwarf_dir):
        for name, fc, tb in candidates:
            if len(scored) >= 100:
                break
            probe = subprocess.run(
                python_tool("lookup.py", dwarf_dir, "struct", name),
                cwd=ROOT_DIR,
                text=True,
                capture_output=True,
            )
            if probe.returncode == 0 and probe.stdout.strip():
                # Count deps not yet scaffolded (excluding the class itself)
                referenced = set()
                for m in _dep_type_re.finditer(probe.stdout):
                    dep_name = m.group(1) or m.group(2)
                    if dep_name and dep_name != name:
                        referenced.add(dep_name)
                missing_dep_names = {
                    t for t in referenced
                    if t not in known_classes
                    and not any(t.startswith(p) for p in prefixes)
                    and not any(t.startswith(p) for p in _BUILTIN_DEP_SKIP)
                }
                scored.append((name, fc, tb, len(missing_dep_names), missing_dep_names))
            else:
                no_dwarf_candidates.append((name, fc, tb))

        # Bubble up blocking deps that are not in class_stats (e.g. abstract base
        # classes with only virtual/weak symbols that never appear in symbol_addrs.txt).
        # Without this, scaffold-next would show the blocked child class forever with
        # no path forward for the agent.
        all_candidate_names = {n for n, _, _ in candidates}
        all_scored_names = {item[0] for item in scored}
        blocking_deps_to_probe: set = set()
        for _, _, _, _, _mdn in scored:
            for _dep in _mdn:
                if _dep not in all_scored_names and _dep not in all_candidate_names:
                    blocking_deps_to_probe.add(_dep)

        # Prefixes that are never SR2 game classes: NNS uppercase variants, C++ reserved
        # names, and common middleware/stdlib patterns that the --skip-prefixes Nn,hk,Pf
        # list doesn't catch because the naming convention differs.
        _BUILTIN_DEP_SKIP = ("NNS_", "NN_", "PF_", "__")
        for dep_name in sorted(blocking_deps_to_probe):
            if prefixes and any(dep_name.startswith(p) for p in prefixes):
                continue
            if any(dep_name.startswith(p) for p in _BUILTIN_DEP_SKIP):
                continue
            probe = subprocess.run(
                python_tool("lookup.py", dwarf_dir, "struct", dep_name),
                cwd=ROOT_DIR, text=True, capture_output=True,
            )
            if probe.returncode == 0 and probe.stdout.strip():
                dep_referenced = set()
                for m in _dep_type_re.finditer(probe.stdout):
                    n2 = m.group(1) or m.group(2)
                    if n2 and n2 != dep_name:
                        dep_referenced.add(n2)
                dep_missing_names = {
                    t for t in dep_referenced
                    if t not in known_classes
                    and not any(t.startswith(p) for p in prefixes)
                    and not any(t.startswith(p) for p in _BUILTIN_DEP_SKIP)
                }
                # fc=0, tb=0: this class has no non-weak symbols but is needed as a dep
                scored.append((dep_name, 0, 0, len(dep_missing_names), dep_missing_names))
                all_scored_names.add(dep_name)

        # Re-sort: by missing dep count (0 first), then by bytes/impact.
        # Default: biggest class first (highest code-coverage impact per TU).
        # --simple-first: fewest functions first (lowest context cost per TU).
        if getattr(args, "simple_first", False):
            scored.sort(key=lambda x: (x[3], x[1], x[2], x[0].lower()))
        else:
            scored.sort(key=lambda x: (x[3], -x[2], -x[1], x[0].lower()))
        candidates_scored = scored[:limit]

        if getattr(args, "show_no_dwarf", False) and no_dwarf_candidates:
            print("Classes with no DWARF struct (skipped):")
            for name, fc, tb in no_dwarf_candidates:
                print(f"  {fc:>5}  {tb:>7}  {name}  (no DWARF)")
            print()
    else:
        candidates_scored = [(n, fc, tb, 0, set()) for n, fc, tb in candidates[:limit]]

    pct = f"{100 * _scaffolded / _total:.1f}%" if _total else "n/a"
    skip_suffix = f"  |  {len(skip_listed)} skip-listed" if skip_listed else ""
    stats_line = (
        f"Progress: {_scaffolded}/{_total} scaffolded ({pct})  |  "
        f"{_remaining} remaining{skip_suffix}"
    )

    if getattr(args, "stats_only", False):
        print(stats_line)
        return

    if not candidates_scored:
        print("No unscaffolded classes found.")
        print(stats_line)
        return

    if args.command_only:
        for name, _fc, _tb, _md, _mdn in candidates_scored:
            print(f"python tools/decomp-workflow.py scaffold -c {name}")
        return

    print_section("Scaffold Next Targets")
    print(stats_line)
    print()
    print(f"  {'FUNCS':>5}  {'BYTES':>7}  {'MISS_DEPS':>9}  CLASS")
    print("-" * 72)
    for name, fc, tb, missing_deps, missing_dep_names in candidates_scored:
        dep_tag = f" +{missing_deps}unscaffolded" if missing_deps else ""
        print(f"  {fc:>5}  {tb:>7}  {missing_deps:>9}  {name}{dep_tag}")
        print(f"          next: python tools/decomp-workflow.py scaffold -c {name}")
        if missing_deps and missing_dep_names:
            dep_list = ", ".join(sorted(missing_dep_names)[:5])
            print(f"          ⛔ scaffold these blocking deps first: {dep_list}")


def command_scaffold_queue(args: argparse.Namespace) -> None:
    """Pre-compute ALL unscaffolded classes ranked by dep-readiness and write a markdown table."""
    import datetime

    def is_builtin_dep(name: str) -> bool:
        return name.startswith(("NNS_", "NN_", "PF_", "__"))

    def priority_key(name: str) -> Tuple[int, int, str]:
        stats = class_stats.get(name, {"func_count": 0, "total_bytes": 0})
        return (-stats["total_bytes"], -stats["func_count"], name.lower())

    def extract_full_layout_deps(text: str, owner: str) -> set:
        deps = set()
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue

            base_match = re.match(r"(?:class|struct)\s+\w+\s*:\s*(.*?)(?:\{|$)", line)
            if base_match:
                for dep in re.findall(r"\b(?:public|private|protected)\s+(\w+)", base_match.group(1)):
                    if dep != owner:
                        deps.add(dep)

            member_match = re.match(r"(?:class|struct)\s+(\w+)\s+(.+?);", line)
            if not member_match:
                continue
            dep_name, decl_tail = member_match.group(1), member_match.group(2)
            if dep_name == owner:
                continue
            # Pointers and references only need declarations, not a full scaffolded layout.
            if "*" in decl_tail or "&" in decl_tail:
                continue
            deps.add(dep_name)
        return deps

    def extract_signature_deps(line: str, owner: str) -> set:
        deps = set()
        signature = line.split("{", 1)[0]
        for match in re.finditer(r"\b(?:class|struct)\s+(\w+)", signature):
            dep_name = match.group(1)
            if dep_name == owner:
                continue
            tail = signature[match.end() :]
            # Pointer/reference signature types only require declarations.
            if re.match(r"\s*[*&]", tail):
                continue
            template_end = tail.find(">")
            comma_pos = tail.find(",")
            paren_pos = tail.find(")")
            stop_positions = [p for p in (comma_pos, paren_pos) if p >= 0]
            stop_pos = min(stop_positions) if stop_positions else len(tail)
            if template_end >= 0 and template_end < stop_pos and "&" in tail[:stop_pos]:
                continue
            deps.add(dep_name)
        return deps

    def load_function_signature_deps(dwarf_dir: str) -> Dict[str, set]:
        deps_by_class: Dict[str, set] = {}
        functions_path = os.path.join(dwarf_dir, "functions.nothpp")
        if not os.path.exists(functions_path):
            return deps_by_class
        with open(functions_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "::" not in line or "{" not in line:
                    continue
                owner_match = re.search(r"\b(\w+)::\w+", line)
                if not owner_match:
                    continue
                owner = owner_match.group(1)
                deps = extract_signature_deps(line, owner)
                if deps:
                    deps_by_class.setdefault(owner, set()).update(deps)
        return deps_by_class

    def lookup_struct_text(name: str, dwarf_dir: str, cache: Dict[str, Optional[str]]) -> Optional[str]:
        if name in cache:
            return cache[name]
        probe = subprocess.run(
            python_tool("lookup.py", dwarf_dir, "struct", name),
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
        )
        if probe.returncode == 0 and probe.stdout.strip():
            cache[name] = probe.stdout
        else:
            cache[name] = None
        return cache[name]

    include_dir = os.path.join(ROOT_DIR, "include")
    known_classes: set = set()
    cls_pat = re.compile(r"(?:class|struct|namespace)\s+(\w+)")
    for dirpath, _dirs, files in os.walk(include_dir):
        for fname in files:
            if not fname.endswith((".hpp", ".h")):
                continue
            try:
                with open(os.path.join(dirpath, fname), encoding="utf-8", errors="replace") as fh:
                    pending_class: Optional[str] = None
                    for line in fh:
                        stripped = line.strip()
                        if stripped.startswith(("//", "*")):
                            continue
                        if "{" in line:
                            found = False
                            for m in cls_pat.finditer(line):
                                if ";" not in line[: line.find("{")]:
                                    known_classes.add(m.group(1))
                                    found = True
                            if not found and pending_class:
                                known_classes.add(pending_class)
                            pending_class = None
                        else:
                            m = cls_pat.search(line)
                            if m:
                                if stripped.endswith(";"):
                                    pending_class = None
                                else:
                                    pending_class = m.group(1)
                            elif stripped and not stripped.startswith(("//", "*", ":")):
                                if not line[0:1].isspace():
                                    pending_class = None
            except OSError:
                pass

    sym_pat = re.compile(r"__(\d+)(\w+)F")
    size_pat = re.compile(r"size:(\d+)")
    weak_pat = re.compile(r"visibility:weak|allow_duplicated:true")
    vtable_pat = re.compile(r"__vt__")
    thunk_pat = re.compile(r"^@")
    class_stats: Dict[str, Dict[str, int]] = {}
    if not os.path.exists(_SR2_SYMBOLS):
        raise WorkflowError(f"Symbol file not found: {_SR2_SYMBOLS}")
    with open(_SR2_SYMBOLS, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            eq_idx = stripped.find("=")
            if eq_idx < 0:
                continue
            sym_name = stripped[:eq_idx].strip()
            if vtable_pat.search(sym_name):
                continue
            if thunk_pat.match(sym_name):
                continue
            comment_part = stripped[eq_idx:]
            if weak_pat.search(comment_part):
                continue
            m = sym_pat.search(sym_name)
            if not m:
                continue
            n = int(m.group(1))
            class_name = m.group(2)[:n]
            if len(class_name) != n:
                continue
            if "<" in class_name or "Q2" in sym_name[:sym_name.find("__")]:
                continue
            sm = size_pat.search(comment_part)
            size = int(sm.group(1)) if sm else 0
            if class_name not in class_stats:
                class_stats[class_name] = {"func_count": 0, "total_bytes": 0}
            class_stats[class_name]["func_count"] += 1
            class_stats[class_name]["total_bytes"] += size

    skip_list_path = getattr(args, "skip_list", None) or os.path.join(
        ROOT_DIR, "docs", "scaffold-skip.txt"
    )
    skip_listed: set = set()
    if os.path.exists(skip_list_path):
        with open(skip_list_path, encoding="utf-8", errors="replace") as _sf:
            for _line in _sf:
                _entry = _line.strip()
                _comment_idx = _entry.find("#")
                if _comment_idx >= 0:
                    _entry = _entry[:_comment_idx].strip()
                if _entry:
                    skip_listed.add(_entry)
        if skip_listed:
            known_classes.update(skip_listed)

    root_candidates = [
        (name, stats["func_count"], stats["total_bytes"])
        for name, stats in class_stats.items()
        if name not in known_classes and stats["func_count"] > 0
    ]
    prefixes: tuple = ()
    if args.skip_prefixes:
        prefixes = tuple(p for p in args.skip_prefixes.split(",") if p)
        root_candidates = [
            (name, fc, tb) for name, fc, tb in root_candidates
            if not any(name.startswith(p) for p in prefixes)
        ]
    _all_with_funcs = [
        name for name, stats in class_stats.items()
        if stats["func_count"] > 0
        and not any(name.startswith(p) for p in prefixes)
    ]
    _total = len(_all_with_funcs)
    _remaining = len(root_candidates)
    _scaffolded = _total - _remaining
    root_candidates.sort(key=lambda x: (-x[2], -x[1], x[0].lower()))

    dwarf_dir = os.path.join(ROOT_DIR, "symbols", "Dwarf")
    rows: Dict[str, Dict[str, Any]] = {}
    struct_cache: Dict[str, Optional[str]] = {}
    no_dwarf_count = 0

    if os.path.exists(dwarf_dir):
        print(f"Probing DWARF for {len(root_candidates)} root candidates...", flush=True)
        function_deps = load_function_signature_deps(dwarf_dir)

        def add_reachable(name: str, is_root: bool = False) -> bool:
            nonlocal no_dwarf_count
            if name in known_classes or is_builtin_dep(name):
                return False

            text = lookup_struct_text(name, dwarf_dir, struct_cache)
            if text is None:
                if is_root:
                    no_dwarf_count += 1
                return False

            if name not in rows:
                stats = class_stats.get(name, {"func_count": 0, "total_bytes": 0})
                rows[name] = {
                    "func_count": stats["func_count"],
                    "total_bytes": stats["total_bytes"],
                    "deps": set(),
                    "is_root": is_root,
                }
            elif is_root:
                rows[name]["is_root"] = True

            deps_to_probe = extract_full_layout_deps(text, name)
            deps_to_probe.update(function_deps.get(name, set()))
            for dep_name in sorted(deps_to_probe):
                if dep_name in known_classes or dep_name == name or is_builtin_dep(dep_name):
                    continue
                dep_text = lookup_struct_text(dep_name, dwarf_dir, struct_cache)
                if dep_text is None:
                    continue
                rows[name]["deps"].add(dep_name)
                add_reachable(dep_name)
            return True

        for idx, (name, _fc, _tb) in enumerate(root_candidates, 1):
            if idx % 50 == 0 or idx == len(root_candidates):
                print(f"  {idx}/{len(root_candidates)}", flush=True)
            add_reachable(name, is_root=True)

        ordered_names: List[str] = []
        visiting: set = set()
        visited: set = set()

        def visit(name: str) -> None:
            if name in visited:
                return
            if name in visiting:
                return
            visiting.add(name)
            for dep_name in sorted(rows[name]["deps"], key=priority_key):
                if dep_name in rows:
                    visit(dep_name)
            visiting.remove(name)
            visited.add(name)
            ordered_names.append(name)

        for name in sorted(rows, key=priority_key):
            visit(name)

        scored = [
            (
                name,
                rows[name]["func_count"],
                rows[name]["total_bytes"],
                len(rows[name]["deps"]),
                rows[name]["deps"],
            )
            for name in ordered_names
        ]
    else:
        scored = [(n, fc, tb, 0, set()) for n, fc, tb in root_candidates]

    pct = f"{100 * _scaffolded / _total:.1f}%" if _total else "n/a"
    today = datetime.date.today().isoformat()
    output_path = getattr(args, "output", None) or os.path.join(
        ROOT_DIR, "docs", "scaffold-queue.md"
    )
    regen_cmd = "python tools/decomp-workflow.py scaffold-queue"
    if args.skip_prefixes:
        regen_cmd += f" --skip-prefixes {args.skip_prefixes}"

    scaffold_cmd_base = "python tools/decomp-workflow.py scaffold -c"

    out_lines: List[str] = []
    out_lines.append("# Scaffold Queue\n")
    out_lines.append("\n")
    out_lines.append(
        f"Generated: {today}  |  Scaffolded: {_scaffolded}/{_total} ({pct})  |  Queued: {len(scored)}\n"
    )
    out_lines.append("\n")
    out_lines.append("## Agent Instructions\n")
    out_lines.append("\n")
    out_lines.append("1. Find the first `[ ]` row where `Deps = 0` — that is your next target.\n")
    out_lines.append("2. Run the full `Command` from that row.\n")
    out_lines.append("3. Update `progress.md` with the result.\n")
    out_lines.append("4. Change `Status` from `[ ]` to `[x]`.\n")
    out_lines.append("5. If the class just scaffolded appears in any **Blocking Deps** cell:\n")
    out_lines.append("   - Check whether all listed blocking deps for that row are now `[x]`.\n")
    out_lines.append("   - If so, change that row's Status from `[~]` to `[ ]` and set Deps to `0`.\n")
    out_lines.append("6. Repeat. After every ~20 scaffolds (or when no `[ ]` Deps=0 rows remain), regenerate:\n")
    out_lines.append("\n")
    out_lines.append(f"```sh\n{regen_cmd}\n```\n")
    out_lines.append("\n")
    out_lines.append("Regenerating resets Status columns, but already-scaffolded classes are automatically excluded.\n")
    out_lines.append("\n")
    out_lines.append("| Status meaning | |\n")
    out_lines.append("|---|---|\n")
    out_lines.append("| `[ ]` | Ready — scaffold this now (Deps = 0) |\n")
    out_lines.append("| `[~]` | Blocked — scaffold the listed Blocking Deps first |\n")
    out_lines.append("| `[x]` | Done |\n")
    out_lines.append("| `Funcs = 0` | Dep-only header — no `.cpp` needed, not tracked in objdiff |\n")
    out_lines.append("\n")
    out_lines.append("| Status | Class | Funcs | Bytes | Deps | Blocking Deps | Command |\n")
    out_lines.append("|--------|-------|------:|------:|:----:|---------------|--------|\n")
    for name, fc, tb, missing_deps, missing_dep_names in scored:
        status = "[ ]" if missing_deps == 0 else "[~]"
        dep_list = ", ".join(sorted(missing_dep_names)[:5]) if missing_dep_names else ""
        cmd = f"`{scaffold_cmd_base} {name}`"
        out_lines.append(
            f"| {status} | `{name}` | {fc} | {tb} | {missing_deps} | {dep_list} | {cmd} |\n"
        )

    with open(output_path, "w", encoding="utf-8") as out:
        out.writelines(out_lines)

    print(f"\nWrote {len(scored)} entries to {output_path}", flush=True)
    print(
        f"Stats: {_scaffolded}/{_total} scaffolded ({pct}), "
        f"{no_dwarf_count} candidates had no DWARF and are excluded",
        flush=True,
    )


def command_scaffold(args: argparse.Namespace) -> None:
    cmd = python_tool("decomp-scaffold.py", "-c", args.class_name)
    if args.brief:
        cmd.append("--brief")
    if args.no_line_lookup:
        cmd.append("--no-line-lookup")
    if args.deps_deep:
        cmd.append("--deps-deep")
    if args.extra_enum:
        cmd.extend(["--enum", args.extra_enum])
    if args.sections:
        cmd.extend(["--sections", args.sections])
    run_stream(cmd)


def command_scaffold_migration(args: argparse.Namespace) -> None:
    cmd = python_tool("scaffold-migration.py")
    if args.output:
        cmd.extend(["--output", args.output])
    run_stream(cmd)


def command_scaffold_audit(args: argparse.Namespace) -> None:
    cmd = python_tool("scaffold-audit.py")
    if args.output:
        cmd.extend(["--output", args.output])
    run_stream(cmd)


def command_scaffold_c_queue(args: argparse.Namespace) -> None:
    cmd = python_tool("scaffold-c-queue.py")
    if args.output:
        cmd.extend(["--output", args.output])
    run_stream(cmd)


def command_function(args: argparse.Namespace) -> None:
    ensure_decomp_prereqs()
    args.unit = _check_source_exists(args.unit)
    print_section(f"Function Workflow: {args.function}")
    ensure_shared_unit_output(args.unit)
    cmd = python_tool("decomp-context.py", "-u", args.unit, "-f", args.function)
    if args.no_source:
        cmd.append("--no-source")
    if args.no_lookup:
        cmd.append("--no-lookup")
    else:
        cmd.extend(["--lookup-mode", args.lookup_mode])
    if args.no_ghidra:
        cmd.append("--no-ghidra")
    else:
        cmd.extend(["--ghidra-version", args.ghidra_version])
    if args.brief:
        cmd.append("--brief")
    if args.reloc_diffs != "none":
        cmd.extend(["--reloc-diffs", args.reloc_diffs])
    run_stream(cmd)
    print(flush=True)
    print(
        "Required completion check: python tools/decomp-workflow.py verify "
        f"-u {shlex.quote(args.unit)} -f {shlex.quote(args.function)}",
        flush=True,
    )


def command_unit(args: argparse.Namespace) -> None:
    ensure_decomp_prereqs()
    args.unit = _check_source_exists(args.unit)
    print_section(f"Unit Status: {args.unit}")
    ensure_shared_unit_output(args.unit)
    top_unmatched_limit = args.limit if args.limit is not None else 5
    run_stream(
        python_tool(
            "decomp-status.py",
            "--unit",
            args.unit,
            "--top-unmatched",
            str(top_unmatched_limit),
        )
    )

    common_args: List[str] = ["-u", args.unit, "-t", "function"]
    if args.reloc_diffs != "none":
        common_args.extend(["--reloc-diffs", args.reloc_diffs])
    if args.search:
        common_args.extend(["--search", args.search])
    if args.limit is not None:
        common_args.extend(["--limit", str(args.limit)])
    common_args.extend(["--sort", "unmatched"])

    print_section("Missing Functions")
    run_stream(python_tool("decomp-diff.py", *common_args, "-s", "missing"))

    print_section("Nonmatching Functions")
    run_stream(python_tool("decomp-diff.py", *common_args, "-s", "nonmatching"))


def command_next(args: argparse.Namespace) -> None:
    ensure_decomp_prereqs()
    if args.unit:
        ensure_shared_unit_output(args.unit)

    cmd = python_tool("decomp-status.py", "--json")
    if args.category:
        cmd.extend(["--category", args.category])
    if args.unit:
        cmd.extend(["--unit", args.unit])

    result = run_capture(cmd)
    status_data = json.loads(result.stdout)
    candidates = build_next_candidates(status_data, args.strategy)
    if args.limit is not None:
        candidates = candidates[: args.limit]

    if not candidates:
        if args.unit:
            for entries in status_data.values():
                for entry in entries:
                    if entry.get("name") != args.unit:
                        continue
                    status = entry.get("status")
                    if status == "error":
                        raise WorkflowError(
                            f"Unable to rank {args.unit}: {entry.get('error_message', 'objdiff failed')}"
                        )
                    if status == "complete":
                        raise WorkflowError(f"{args.unit} is already complete.")
                    if status == "no_source":
                        raise WorkflowError(
                            f"{args.unit} has no decomp source configured in objdiff.json."
                        )
                    if status == "no_target":
                        raise WorkflowError(
                            f"{args.unit} has no target object configured in objdiff.json."
                        )
        raise WorkflowError("No unmatched function candidates found for the given filters.")

    if args.command_only:
        for candidate in candidates:
            print(
                "python tools/decomp-workflow.py function "
                f"-u {shlex.quote(candidate['unit'])} "
                f"-f {shlex.quote(candidate['function'])}"
            )
        return

    print_section("Next Targets")
    print(
        f"{'UNMATCH':>8}  {'MATCH':>7}  {'SIZE':>6}  {'UNIT':<34} {'FUNCTION'}"
    )
    print("-" * 120)
    for candidate in candidates:
        match_str = (
            f"{candidate['match_percent']:.1f}%"
            if candidate["match_percent"] is not None
            else "-"
        )
        print(
            f"{candidate['unmatched_bytes_est']:>7}B  {match_str:>7}  {candidate['size']:>5}B  "
            f"{candidate['display_unit']:<34} {candidate['function']}"
        )
        print(f"  why: {candidate['reason']}")
        print(
            "  next: python tools/decomp-workflow.py function "
            f"-u {shlex.quote(candidate['unit'])} "
            f"-f {shlex.quote(candidate['function'])}"
        )


def command_build(args: argparse.Namespace) -> None:
    args.unit = _resolve_unit_path(args.unit)
    print(build_shared_unit(args.unit), flush=True)


def command_validate(args: argparse.Namespace) -> None:
    cmd = python_tool("targeted-validate.py", *args.paths)
    if args.no_related:
        cmd.append("--no-related")
    run_stream(cmd)


def command_diff(args: argparse.Namespace) -> None:
    ensure_decomp_prereqs()
    args.unit = _check_source_exists(args.unit)
    title = f"Diff Workflow: {args.unit}"
    if args.diff:
        title += f" / {args.diff}"
    print_section(title)
    ensure_shared_unit_output(args.unit)

    cmd: List[str] = python_tool("decomp-diff.py", "-u", args.unit)
    if args.reloc_diffs != "none":
        cmd.extend(["--reloc-diffs", args.reloc_diffs])
    if args.diff:
        cmd.extend(["-d", args.diff])
        cmd.append("--unified")
    if args.type:
        cmd.extend(["-t", args.type])
    if args.status:
        cmd.extend(["-s", args.status])
    if args.section:
        cmd.extend(["--section", args.section])
    if args.search:
        cmd.extend(["--search", args.search])
    if args.limit is not None:
        cmd.extend(["--limit", str(args.limit)])
    if args.context is not None:
        cmd.extend(["-C", str(args.context)])
    if args.range:
        cmd.extend(["--range", args.range])
    if args.no_collapse:
        cmd.append("--no-collapse")
    if getattr(args, "full", False):
        cmd.append("--full")
    run_stream(cmd)


def command_dwarf(args: argparse.Namespace) -> None:
    ensure_decomp_prereqs()
    args.unit = _resolve_unit_path(args.unit)
    print_section(f"DWARF Workflow: {args.unit} / {args.function}")
    if not args.rebuilt_dwarf_file:
        ensure_shared_unit_output(args.unit)

    cmd: List[str] = python_tool("dwarf-compare.py", "-u", args.unit, "-f", args.function)
    if args.summary:
        cmd.append("--summary")
    if args.json:
        cmd.append("--json")
    if args.context is not None:
        cmd.extend(["-C", str(args.context)])
    if args.no_collapse:
        cmd.append("--no-collapse")
    if args.require_exact:
        cmd.append("--require-exact")
    if args.rebuilt_dwarf_file:
        cmd.extend(["--rebuilt-dwarf-file", args.rebuilt_dwarf_file])
    run_stream(cmd)


def command_verify(args: argparse.Namespace) -> None:
    ensure_decomp_prereqs()
    args.unit = _resolve_unit_path(args.unit)
    print_section(f"Verify Workflow: {args.unit} / {args.function}")
    ensure_shared_unit_output(args.unit)

    objdiff_row = choose_objdiff_row(args.unit, args.function, reloc_diffs=args.reloc_diffs)
    dwarf_report = load_dwarf_report(
        args.unit,
        args.function,
        rebuilt_dwarf_file=args.rebuilt_dwarf_file,
    )

    objdiff_exact = (
        objdiff_row["status"] == "match"
        and objdiff_row["match_percent"] is not None
        and float(objdiff_row["match_percent"]) >= 100.0
    )
    dwarf_exact = bool(dwarf_report["normalized_exact_match"])
    overall_ok = objdiff_exact and dwarf_exact

    objdiff_percent = (
        f"{float(objdiff_row['match_percent']):.1f}%"
        if objdiff_row["match_percent"] is not None
        else "-"
    )
    dwarf_percent = f"{float(dwarf_report['match_percent']):.1f}%"

    print(
        f"objdiff: {'PASS' if objdiff_exact else 'FAIL'} | "
        f"{objdiff_percent} | status={objdiff_row['status']} | "
        f"unmatched~{objdiff_row['unmatched_bytes_est']}B"
    )
    print(
        f"DWARF:  {'PASS' if dwarf_exact else 'FAIL'} | "
        f"{dwarf_percent} | normalized exact={'yes' if dwarf_exact else 'no'} | "
        f"change groups={dwarf_report['changed_groups']}"
    )
    print(f"Overall: {'PASS' if overall_ok else 'FAIL'}")
    print("Done means both objdiff and normalized DWARF are exact for the function.")

    if overall_ok:
        return

    print(flush=True)
    print("Follow-up commands:", flush=True)
    print(
        f"  python tools/decomp-workflow.py diff -u {shlex.quote(args.unit)} "
        f"-d {shlex.quote(args.function)}",
        flush=True,
    )
    print(
        f"  python tools/decomp-workflow.py dwarf -u {shlex.quote(args.unit)} "
        f"-f {shlex.quote(args.function)}",
        flush=True,
    )
    raise WorkflowError(
        "Verification failed: the function is not complete until both objdiff and DWARF match."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Wrapper for common decomp workflows built on top of the existing project tools."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    health = subparsers.add_parser(
        "health",
        help="Check whether the current worktree is ready for GC and PS2 decomp work",
    )
    health.add_argument(
        "--full",
        metavar="UNIT",
        nargs="?",
        const=DEFAULT_SMOKE_UNIT,
        help=(
            "Run the full smoke path for one unit: shared build, dtk dump, rebuilt "
            f"debug-line export, and rebuilt line lookup. If UNIT is omitted, uses {DEFAULT_SMOKE_UNIT}"
        ),
    )
    health.add_argument(
        "--smoke-build",
        metavar="UNIT",
        nargs="?",
        const=DEFAULT_SMOKE_UNIT,
        help=(
            "Also build the unit's shared output as a smoke test. If UNIT is omitted, uses "
            f"{DEFAULT_SMOKE_UNIT}"
        ),
    )
    health.add_argument(
        "--timings",
        action="store_true",
        help="Show wall-clock timings for the heavier health-check steps",
    )
    health.add_argument(
        "--smoke-dtk",
        metavar="UNIT",
        nargs="?",
        const=DEFAULT_SMOKE_UNIT,
        help=(
            "Also run a dtk dwarf dump smoke test. If UNIT is omitted, uses "
            f"{DEFAULT_SMOKE_UNIT}"
        ),
    )
    health.set_defaults(func=command_health)

    validate = subparsers.add_parser(
        "validate",
        help="Run focused guards/checks for named files without invoking Ninja",
    )
    validate.add_argument(
        "paths",
        nargs="+",
        help="Files or unique basenames to validate; direct counterparts are added by default",
    )
    validate.add_argument(
        "--no-related",
        action="store_true",
        help="Do not add direct source/header counterparts for the requested files",
    )
    validate.set_defaults(func=command_validate)

    function = subparsers.add_parser(
        "function",
        help="Run decomp-context.py for one function",
    )
    function.add_argument("-u", "--unit", required=True, help="Translation unit name")
    function.add_argument("-f", "--function", required=True, help="Function name to inspect")
    function.add_argument(
        "--no-source",
        action="store_true",
        help="Pass through to decomp-context.py",
    )
    function.add_argument(
        "--no-ghidra",
        action="store_true",
        help="Pass through to decomp-context.py",
    )
    function.add_argument(
        "--ghidra-version",
        choices=["both", "gc", "ps2"],
        default="ps2",
        help="Pass through to decomp-context.py (default: ps2)",
    )
    function.add_argument(
        "--no-lookup",
        action="store_true",
        help="Pass through to decomp-context.py",
    )
    function.add_argument(
        "--lookup-mode",
        choices=["signature", "full"],
        default="signature",
        help="Pass through to decomp-context.py (default: signature)",
    )
    function.add_argument(
        "--brief",
        action="store_true",
        help="Trim helper sections like related-source hints and suggested commands",
    )
    function.add_argument(
        "--reloc-diffs",
        choices=RELOC_DIFF_CHOICES,
        default="none",
        help="Pass through objdiff relocation diff mode to decomp-context.py",
    )
    function.set_defaults(func=command_function)

    unit = subparsers.add_parser(
        "unit",
        help="Show a compact unit workflow summary using decomp-status.py and decomp-diff.py",
    )
    unit.add_argument("-u", "--unit", required=True, help="Translation unit name")
    unit.add_argument("--search", help="Fuzzy search on demangled symbol name")
    unit.add_argument(
        "--limit",
        type=int,
        help="Limit each symbol list to the first N matching rows",
    )
    unit.add_argument(
        "--reloc-diffs",
        choices=RELOC_DIFF_CHOICES,
        default="none",
        help="Pass through objdiff relocation diff mode to decomp-diff.py",
    )
    unit.set_defaults(func=command_unit)

    next_cmd = subparsers.add_parser(
        "next",
        help="Recommend the highest-impact next functions to work on",
    )
    next_cmd.add_argument("--category", help="Filter by progress category")
    next_cmd.add_argument("--unit", help="Restrict recommendations to one unit")
    next_cmd.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Limit the number of suggested targets (default: 10)",
    )
    next_cmd.add_argument(
        "--strategy",
        choices=["impact", "balanced", "quick-wins"],
        default="balanced",
        help=(
            "Ranking strategy for recommendations (default: balanced; quick-wins favors "
            "low-match functions where early progress is fastest)"
        ),
    )
    next_cmd.add_argument(
        "--command-only",
        action="store_true",
        help="Print only follow-up commands, one per line",
    )
    next_cmd.set_defaults(func=command_next)

    build = subparsers.add_parser(
        "build",
        help="Build a unit's shared output with its configured ninja target",
    )
    build.add_argument("-u", "--unit", required=True, help="Translation unit name")
    build.set_defaults(func=command_build)

    diff = subparsers.add_parser(
        "diff",
        help="Run decomp-diff.py",
    )
    diff.add_argument("-u", "--unit", required=True, help="Translation unit name")
    diff.add_argument(
        "-d",
        "--diff",
        metavar="SYMBOL",
        help="Show diff for a specific symbol instead of overview mode",
    )
    diff.add_argument("-t", "--type", help="Filter by type: function, object")
    diff.add_argument(
        "-s",
        "--status",
        help="Filter by status: missing, matching, nonmatching, extra",
    )
    diff.add_argument("--section", help="Filter by section name")
    diff.add_argument("--search", help="Fuzzy search on demangled symbol name")
    diff.add_argument(
        "--limit",
        type=int,
        help="Limit overview output to the first N matching rows",
    )
    diff.add_argument(
        "-C",
        "--context",
        type=int,
        default=3,
        help="Context lines around mismatches (default: 3)",
    )
    diff.add_argument("--range", help="Instruction offset range (hex, e.g. 100-200)")
    diff.add_argument(
        "--no-collapse",
        action="store_true",
        help="Don't collapse matching instruction runs",
    )
    diff.add_argument(
        "--full",
        action="store_true",
        help="Show every instruction without collapsing or hunk windowing (passes --full to decomp-diff.py)",
    )
    diff.add_argument(
        "--reloc-diffs",
        choices=RELOC_DIFF_CHOICES,
        default="none",
        help="Pass through objdiff relocation diff mode to decomp-diff.py",
    )
    diff.set_defaults(func=command_diff)

    dwarf = subparsers.add_parser(
        "dwarf",
        help="Compare original vs rebuilt DWARF for one function",
    )
    dwarf.add_argument("-u", "--unit", required=True, help="Translation unit name")
    dwarf.add_argument("-f", "--function", required=True, help="Function name to compare")
    dwarf.add_argument(
        "--summary",
        action="store_true",
        help="Print only the DWARF summary without the diff view",
    )
    dwarf.add_argument(
        "--json",
        action="store_true",
        help="Print the DWARF comparison report as JSON",
    )
    dwarf.add_argument(
        "-C",
        "--context",
        type=int,
        default=3,
        help="Context lines around collapsed matching DWARF runs (default: 3)",
    )
    dwarf.add_argument(
        "--no-collapse",
        "--full-diff",
        dest="no_collapse",
        action="store_true",
        help="Show the whole normalized DWARF block with diff markers instead of collapsing matching runs",
    )
    dwarf.add_argument(
        "--rebuilt-dwarf-file",
        help="Use an existing rebuilt DWARF dump instead of dumping the unit object",
    )
    dwarf.add_argument(
        "--require-exact",
        action="store_true",
        help="Exit non-zero unless the normalized DWARF block matches exactly",
    )
    dwarf.set_defaults(func=command_dwarf)

    verify = subparsers.add_parser(
        "verify",
        help="Fail unless one function matches in both objdiff and DWARF",
    )
    verify.add_argument("-u", "--unit", required=True, help="Translation unit name")
    verify.add_argument("-f", "--function", required=True, help="Function name to verify")
    verify.add_argument(
        "--reloc-diffs",
        choices=RELOC_DIFF_CHOICES,
        default="none",
        help="Pass through objdiff relocation diff mode when checking instruction match",
    )
    verify.add_argument(
        "--rebuilt-dwarf-file",
        help="Use an existing rebuilt DWARF dump instead of dumping the unit object",
    )
    verify.set_defaults(func=command_verify)

    scaffold = subparsers.add_parser(
        "scaffold",
        help="Gather all context needed to scaffold a new class header and .cpp stub",
    )
    scaffold.add_argument(
        "-c",
        "--class",
        dest="class_name",
        required=True,
        help="Class name to scaffold (e.g. clsMotion)",
    )
    scaffold.add_argument(
        "--brief",
        action="store_true",
        help="Skip the next-steps section and reduce output verbosity",
    )
    scaffold.add_argument(
        "--no-line-lookup",
        dest="no_line_lookup",
        action="store_true",
        help="Skip the line_lookup step (can be slow on the first run)",
    )
    scaffold.add_argument(
        "--deps-deep",
        dest="deps_deep",
        action="store_true",
        help="Recursively resolve dependency types not found in the codebase",
    )
    scaffold.add_argument(
        "--enum",
        dest="extra_enum",
        metavar="ENUMNAME",
        help="Also look up an additional enum by name (in addition to any detected in the struct)",
    )
    scaffold.add_argument(
        "--sections",
        dest="sections",
        metavar="N[,N...]",
        default=None,
        help="Only print the specified section numbers (e.g. --sections 1,3,5)",
    )
    scaffold.set_defaults(func=command_scaffold)

    scaffold_next = subparsers.add_parser(
        "scaffold-next",
        help="Rank unscaffolded classes by total implementation bytes (biggest work first)",
    )
    scaffold_next.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of classes to show (default: 20)",
    )
    scaffold_next.add_argument(
        "--command-only",
        action="store_true",
        help="Print only scaffold commands, one per line",
    )
    scaffold_next.add_argument(
        "--skip-prefixes",
        metavar="PREFIXES",
        default="",
        help="Comma-separated list of class-name prefixes to exclude (e.g. hk,Nn,Pf)",
    )
    scaffold_next.add_argument(
        "--show-no-dwarf",
        dest="show_no_dwarf",
        action="store_true",
        help="Also print classes that were skipped because they have no DWARF struct",
    )
    scaffold_next.add_argument(
        "--simple-first",
        dest="simple_first",
        action="store_true",
        help=(
            "Among equal-dependency candidates, prefer fewest functions first "
            "(lower context cost per TU — recommended for automated agents)"
        ),
    )
    scaffold_next.add_argument(
        "--stats-only",
        dest="stats_only",
        action="store_true",
        help="Print only the scaffolding progress summary (scaffolded/total) and exit",
    )
    scaffold_next.add_argument(
        "--search",
        metavar="NAME",
        default=None,
        help=(
            "Check if a specific class appears in the candidate list (case-insensitive "
            "substring match). Prints the matching row or explains why the class is not "
            "available (already scaffolded / no symbols / no DWARF / prefix filtered)."
        ),
    )
    scaffold_next.add_argument(
        "--skip-list",
        metavar="FILE",
        default=None,
        help=(
            "Path to a text file of class names to skip (one per line, # for comments). "
            "Defaults to docs/scaffold-skip.txt when that file exists. "
            "Use this to permanently skip classes whose TU is fully commented-out in "
            "sonic.yaml without needing to create a placeholder header."
        ),
    )
    scaffold_next.set_defaults(func=command_scaffold_next)

    scaffold_queue = subparsers.add_parser(
        "scaffold-queue",
        help=(
            "Pre-compute ALL unscaffolded classes ranked by dep-readiness and write a "
            "markdown table to docs/scaffold-queue.md"
        ),
    )
    scaffold_queue.add_argument(
        "--skip-prefixes",
        metavar="PREFIXES",
        default="",
        help="Comma-separated list of class-name prefixes to exclude (e.g. hk,Nn,Pf)",
    )
    scaffold_queue.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Output path for the markdown table (default: docs/scaffold-queue.md)",
    )
    scaffold_queue.add_argument(
        "--skip-list",
        metavar="FILE",
        default=None,
        help=(
            "Path to a text file of class names to skip (one per line, # for comments). "
            "Defaults to docs/scaffold-skip.txt when that file exists."
        ),
    )
    scaffold_queue.set_defaults(func=command_scaffold_queue)

    scaffold_migration = subparsers.add_parser(
        "scaffold-migration",
        help=(
            "Audit scaffolded classes/functions whose current files differ from "
            "line-info ownership and write docs/scaffold-migration.md"
        ),
    )
    scaffold_migration.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Output path for the markdown report (default: docs/scaffold-migration.md)",
    )
    scaffold_migration.set_defaults(func=command_scaffold_migration)

    scaffold_audit = subparsers.add_parser(
        "scaffold-audit",
        help=(
            "Audit missing, empty, gap-only, and under-scaffolded class bodies "
            "and write docs/scaffold-audit.md"
        ),
    )
    scaffold_audit.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Output path for the markdown report (default: docs/scaffold-audit.md)",
    )
    scaffold_audit.set_defaults(func=command_scaffold_audit)

    scaffold_c_queue = subparsers.add_parser(
        "scaffold-c-queue",
        help=(
            "Generate the report-only pure-C SDK/library declaration queue "
            "at docs/scaffold-c-queue.md"
        ),
    )
    scaffold_c_queue.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Output path for the markdown report (default: docs/scaffold-c-queue.md)",
    )
    scaffold_c_queue.set_defaults(func=command_scaffold_c_queue)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except WorkflowError as e:
        if str(e):
            print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
