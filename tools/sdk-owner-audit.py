#!/usr/bin/env python3
"""Report SDK/library-style declarations that still live under Develop paths.

This is a read-only ownership aid for cleanup after scaffold-c work. It mirrors
the scaffold-c queue's DwarfByUnit/source-inventory idea, but reports symbols
already declared under Develop so they can be moved to canonical usr/local SDK
headers when ownership is clear.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_INDEX = os.path.join(ROOT_DIR, "symbols", "DwarfByUnit", "index.json")

DEVELOP_ROOTS = (
    os.path.join(ROOT_DIR, "include", "Develop"),
    os.path.join(ROOT_DIR, "src", "Develop"),
)
SDK_ROOTS = (
    os.path.join(ROOT_DIR, "include", "usr", "local"),
    os.path.join(ROOT_DIR, "src", "usr", "local"),
)
SDK_MARKERS = (
    "/usr/local/sega/",
    "/usr/local/cri/",
    "/usr/local/sce/",
    "/usr/local/metrowerks/",
)
SOURCE_EXTS = {".h", ".hpp", ".hh", ".c", ".cpp", ".cc"}
SDK_PREFIXES = (
    "NNS_",
    "_NNS_",
    "NJS_",
    "PXS_",
    "PXE_",
    "sce",
    "tGS_",
    "Mws",
    "MWS",
    "ADX",
    "Cri",
)


@dataclass
class SourceDecl:
    kind: str
    name: str
    path: str
    line: int
    text: str
    is_definition: bool


@dataclass
class ReportRow:
    name: str
    develop_decls: List[SourceDecl] = field(default_factory=list)
    sdk_decls: List[SourceDecl] = field(default_factory=list)
    unit_paths: Set[str] = field(default_factory=set)
    dwarf_displays: Set[str] = field(default_factory=set)


def relpath(path: str) -> str:
    return os.path.relpath(path, ROOT_DIR).replace("\\", "/")


def iter_files(roots: Sequence[str]) -> Iterable[str]:
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                if os.path.splitext(filename)[1].lower() in SOURCE_EXTS:
                    yield os.path.join(dirpath, filename)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def is_sdk_name(name: str) -> bool:
    if not name.startswith(SDK_PREFIXES):
        return False
    # Project/game classes can contain Cri in their name; keep the SDK-style CRI
    # rows focused on CRI middleware spellings.
    if name.startswith("Cri") and not name.startswith("Cri"):
        return False
    return True


def parse_decls(path: str) -> List[SourceDecl]:
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []

    text = strip_comments(raw)
    decl_re = re.compile(
        r"\b(?P<kind>class|struct|enum)\s+(?:class\s+)?(?P<name>[A-Za-z_]\w*)\s*(?P<tail>[{;:])"
    )
    decls: List[SourceDecl] = []
    line_starts = [0]
    for match in re.finditer("\n", text):
        line_starts.append(match.end())
    for match in decl_re.finditer(text):
        name = match.group("name")
        if not is_sdk_name(name):
            continue
        line = 1
        for idx, start in enumerate(line_starts):
            if start > match.start():
                break
            line = idx + 1
        source_line = raw.splitlines()[line - 1].strip() if line - 1 < len(raw.splitlines()) else match.group(0)
        decls.append(SourceDecl(match.group("kind"), name, relpath(path), line, source_line, match.group("tail") != ";"))
    return decls


def load_dwarf_index(index_path: str) -> Dict[str, List[dict]]:
    try:
        data = json.load(open(index_path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    by_name: Dict[str, List[dict]] = {}
    for record in data.get("symbols", []):
        name = record.get("name")
        if isinstance(name, str):
            by_name.setdefault(name, []).append(record)
    return by_name


def has_sdk_unit_path(paths: Iterable[str]) -> bool:
    return any(any(marker in path.lower() for marker in SDK_MARKERS) for path in paths)


def build_rows(index_path: str, include_forwards: bool, include_local_only: bool) -> List[ReportRow]:
    rows: Dict[str, ReportRow] = {}
    for path in iter_files(DEVELOP_ROOTS):
        for decl in parse_decls(path):
            if not include_forwards and not decl.is_definition:
                continue
            rows.setdefault(decl.name, ReportRow(decl.name)).develop_decls.append(decl)
    for path in iter_files(SDK_ROOTS):
        for decl in parse_decls(path):
            if decl.name in rows:
                rows[decl.name].sdk_decls.append(decl)

    dwarf = load_dwarf_index(index_path)
    for name, row in rows.items():
        for record in dwarf.get(name, []):
            for path in record.get("unit_paths", []):
                if isinstance(path, str):
                    row.unit_paths.add(path.replace("\\", "/"))
            display = record.get("display")
            if isinstance(display, str):
                row.dwarf_displays.add(display)
    if not include_local_only:
        rows = {
            name: row
            for name, row in rows.items()
            if row.sdk_decls or has_sdk_unit_path(row.unit_paths) or row.name.startswith(("Mws", "MWS", "ADX", "Cri"))
        }
    return sorted(rows.values(), key=lambda row: row.name)


def format_locations(decls: Sequence[SourceDecl]) -> str:
    if not decls:
        return "-"
    return "<br>".join(
        f"`{decl.path}:{decl.line}` `{decl.kind}{' definition' if decl.is_definition else ' forward'}`"
        for decl in decls
    )


def format_unit_paths(paths: Iterable[str], limit: int) -> str:
    sorted_paths = sorted(paths)
    if not sorted_paths:
        return "-"
    shown = sorted_paths[:limit]
    suffix = f"<br>+{len(sorted_paths) - limit} more" if len(sorted_paths) > limit else ""
    return "<br>".join(f"`{path}`" for path in shown) + suffix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", default=DEFAULT_INDEX, help="DwarfByUnit index.json path")
    parser.add_argument("--unit-limit", type=int, default=8, help="Maximum DWARF unit paths shown per row")
    parser.add_argument(
        "--include-forwards",
        action="store_true",
        help="Also report Develop-side forward declarations; default is definitions only",
    )
    parser.add_argument(
        "--include-local-only",
        action="store_true",
        help="Also report SDK-prefixed Develop definitions with no canonical SDK declaration or SDK unit-path evidence",
    )
    args = parser.parse_args()

    rows = build_rows(args.index, args.include_forwards, args.include_local_only)
    print("# SDK Owner Audit")
    print()
    print(f"Candidates: {len(rows)}")
    print()
    print("| Symbol | Develop declarations | Canonical SDK declarations | DWARF unit paths |")
    print("|--------|----------------------|----------------------------|------------------|")
    for row in rows:
        print(
            "| "
            f"`{row.name}` | "
            f"{format_locations(row.develop_decls)} | "
            f"{format_locations(row.sdk_decls)} | "
            f"{format_unit_paths(row.unit_paths, args.unit_limit)} |"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
