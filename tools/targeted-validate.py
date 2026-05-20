#!/usr/bin/env python3
"""Run focused validation checks without invoking Ninja.

This is intended for edit loops where changing guard/check tools would make Ninja
rerun many stale guard stamps. It validates only the files named on the command
line and, by default, their direct source/header counterparts.

Examples:
    python tools/targeted-validate.py src/Develop/Projects/SR2/pgm/lib/OO/nn/NNUtil_PS2.cpp
    python tools/targeted-validate.py NNUtil_PS2.cpp NNUtil_Union.cpp
    python tools/targeted-validate.py tools/stub_guard.py --no-related
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Sequence, Set


ROOT_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT_DIR / "tools"

CXX_SOURCE_EXTS = {".cpp", ".cc", ".cxx"}
CXX_HEADER_EXTS = {".hpp", ".hh", ".hxx"}
C_SOURCE_EXTS = {".c"}
C_HEADER_EXTS = {".h"}
PYTHON_EXTS = {".py"}


def relpath(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return path.as_posix()


def candidate_paths(raw: str) -> List[Path]:
    path = Path(raw)
    if path.exists():
        return [path]

    prefixed = [ROOT_DIR / raw, ROOT_DIR / "src" / raw, ROOT_DIR / "include" / raw]
    matches = [candidate for candidate in prefixed if candidate.exists()]
    if matches:
        return matches

    name = path.name
    if not name or name == raw and any(sep in raw for sep in ("/", "\\")):
        return []

    roots = [ROOT_DIR / "src", ROOT_DIR / "include", TOOLS_DIR]
    found: List[Path] = []
    for root in roots:
        if root.exists():
            found.extend(p for p in root.rglob(name) if p.is_file())
    return sorted(found, key=lambda p: relpath(p).lower())


def resolve_inputs(inputs: Sequence[str]) -> List[Path]:
    resolved: List[Path] = []
    seen: Set[Path] = set()
    errors: List[str] = []

    for raw in inputs:
        matches = candidate_paths(raw)
        if not matches:
            errors.append(f"not found: {raw}")
            continue
        if len(matches) > 1:
            choices = "\n".join(f"  {relpath(match)}" for match in matches[:20])
            suffix = "\n  ..." if len(matches) > 20 else ""
            errors.append(f"ambiguous path: {raw}\n{choices}{suffix}")
            continue
        path = matches[0].resolve()
        if path not in seen:
            resolved.append(path)
            seen.add(path)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        sys.exit(2)
    return resolved


def counterpart_paths(path: Path) -> Iterable[Path]:
    rel = relpath(path)
    if rel.startswith("src/"):
        base = ROOT_DIR / "include" / rel[4:]
        if path.suffix in CXX_SOURCE_EXTS:
            yield base.with_suffix(".hpp")
            yield base.with_suffix(".h")
        elif path.suffix in C_SOURCE_EXTS:
            yield base.with_suffix(".h")
    elif rel.startswith("include/"):
        base = ROOT_DIR / "src" / rel[8:]
        if path.suffix in CXX_HEADER_EXTS:
            yield base.with_suffix(".cpp")
            yield base.with_suffix(".cc")
        elif path.suffix in C_HEADER_EXTS:
            yield base.with_suffix(".c")


def expand_related(paths: Sequence[Path], include_related: bool) -> List[Path]:
    expanded: List[Path] = []
    seen: Set[Path] = set()

    def add(path: Path) -> None:
        if path.exists():
            resolved = path.resolve()
            if resolved not in seen:
                expanded.append(resolved)
                seen.add(resolved)

    for path in paths:
        add(path)
        if include_related:
            for counterpart in counterpart_paths(path):
                add(counterpart)
    return expanded


def run_command(label: str, cmd: Sequence[str]) -> int:
    print(f"\n==> {label}", flush=True)
    print(" ".join(cmd), flush=True)
    result = subprocess.run(cmd, cwd=ROOT_DIR, text=True)
    if result.returncode == 0:
        print(f"PASS: {label}", flush=True)
    else:
        print(f"FAIL: {label} (exit {result.returncode})", file=sys.stderr, flush=True)
    return result.returncode


def validate(paths: Sequence[Path]) -> int:
    py_files = [p for p in paths if p.suffix in PYTHON_EXTS]
    cxx_files = [p for p in paths if p.suffix in CXX_SOURCE_EXTS | CXX_HEADER_EXTS]
    cxx_sources = [p for p in paths if p.suffix in CXX_SOURCE_EXTS]
    c_sources = [p for p in paths if p.suffix in C_SOURCE_EXTS]
    hpp_headers = [p for p in paths if p.suffix == ".hpp"]

    failures = 0

    if py_files:
        failures += run_command(
            "python syntax",
            [sys.executable, "-m", "py_compile", *[relpath(p) for p in py_files]],
        ) != 0

    for header in hpp_headers:
        failures += run_command(
            f"source_guard {relpath(header)}",
            [sys.executable, "tools/source_guard.py", relpath(header)],
        ) != 0

    if cxx_files:
        failures += run_command(
            "clang_check C++ files",
            [sys.executable, "tools/clang_check.py", *[relpath(p) for p in cxx_files]],
        ) != 0

    for source in cxx_sources:
        failures += run_command(
            f"stub_guard {relpath(source)}",
            [sys.executable, "tools/stub_guard.py", relpath(source)],
        ) != 0

    for source in c_sources:
        failures += run_command(
            f"c_guard {relpath(source)}",
            [sys.executable, "tools/c_guard.py", relpath(source)],
        ) != 0

    if not any((py_files, cxx_files, c_sources, hpp_headers)):
        print("No targeted validators apply to the selected files.")

    return 1 if failures else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="Files or unique basenames to validate")
    parser.add_argument(
        "--no-related",
        action="store_true",
        help="Do not add direct source/header counterparts for the requested files",
    )
    args = parser.parse_args()

    paths = expand_related(resolve_inputs(args.paths), include_related=not args.no_related)
    print("Targeted validation files:")
    for path in paths:
        print(f"  {relpath(path)}")

    sys.exit(validate(paths))


if __name__ == "__main__":
    main()
