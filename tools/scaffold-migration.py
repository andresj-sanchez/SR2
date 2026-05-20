#!/usr/bin/env python3
"""Report scaffold classes whose current files differ from their line-info owner.

This is a validation aid for classes that were scaffolded quickly in a dependent
header/source before their canonical TU was known. It compares:

- expected owner files from symbol_addrs.txt + sr2_line_info.nothpp
- actual class/struct definitions under include/
- actual Owner:: function definitions under src/

The default output is docs/scaffold-migration.md.
"""

from __future__ import annotations

import argparse
import bisect
import datetime
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SYMBOLS_PATH = os.path.join(
    ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "symbol_addrs.txt"
)
LINE_INFO_PATH = os.path.join(ROOT_DIR, "symbols", "sr2_line_info.nothpp")

PROJECT_PREFIX = "Develop/Projects/SR2/pgm/"
HEADER_EXTS = {".h", ".hpp", ".hh"}
SOURCE_EXTS = {".c", ".cc", ".cpp"}
SKIP_OWNER_PREFIXES = ("hk", "Nn", "Pf")

_FUNCTION_SOURCE_CACHE: Optional[Dict[Tuple[str, int], str]] = None


@dataclass
class SymbolOwner:
    name: str
    function_symbols: List[Tuple[str, int]] = field(default_factory=list)
    weak_function_symbols: List[Tuple[str, int]] = field(default_factory=list)


@dataclass
class ExpectedOwner:
    class_name: str
    source_line_file: Optional[str]
    header: Optional[str]
    source: Optional[str]


@dataclass
class MigrationFinding:
    class_name: str
    expected_header: Optional[str]
    expected_source: Optional[str]
    actual_headers: List[str]
    actual_sources: List[str]
    reason: str


def relpath(path: str) -> str:
    return os.path.relpath(path, ROOT_DIR).replace("\\", "/")


def normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def same_path_ignoring_case(left: str, right: str) -> bool:
    return normalize_path(left).lower() == normalize_path(right).lower()


def source_line_to_project_path(path: str) -> Optional[str]:
    norm = normalize_path(path)
    idx = norm.find(PROJECT_PREFIX)
    if idx < 0:
        return None
    return norm[idx:]


def project_source_to_repo_paths(project_path: str) -> Tuple[Optional[str], Optional[str]]:
    stem, ext = os.path.splitext(project_path)
    source = f"src/{project_path}" if ext in SOURCE_EXTS else None
    header = f"include/{stem}.hpp"
    return header, source


def parse_line_info(path: str) -> List[Tuple[int, str]]:
    entries: List[Tuple[int, str]] = []
    if not os.path.exists(path):
        return entries

    re_insn = re.compile(r"^\s+([0-9A-Fa-f]{5,})\s*:\t")
    re_src = re.compile(r"^(\S[^\r\n]*):(\d+)\s*$")
    pending: List[str] = []

    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            m = re_src.match(line)
            if m:
                pending.append(m.group(1))
                continue
            m = re_insn.match(line)
            if m:
                addr = int(m.group(1), 16)
                for src in pending:
                    entries.append((addr, src))
                pending = []

    entries.sort(key=lambda item: item[0])
    return entries


def closest_source_file(entries: Sequence[Tuple[int, str]], addr: int) -> Optional[str]:
    if not entries:
        return None
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
    return entries[best][1]


def parse_function_label_sources() -> Dict[Tuple[str, int], str]:
    """Map exact objdump function labels to their first source annotation."""
    global _FUNCTION_SOURCE_CACHE
    if _FUNCTION_SOURCE_CACHE is not None:
        return _FUNCTION_SOURCE_CACHE

    sources: Dict[Tuple[str, int], str] = {}
    if not os.path.exists(LINE_INFO_PATH):
        _FUNCTION_SOURCE_CACHE = sources
        return sources

    label_re = re.compile(r"^([0-9A-Fa-f]{5,})\s+<([^>]+)>:")
    any_label_re = re.compile(r"^[0-9A-Fa-f]{5,}\s+<[^>]+>:")
    src_re = re.compile(r"^(\S[^\r\n]*):(\d+)\s*$")
    current: Optional[Tuple[str, int]] = None

    with open(LINE_INFO_PATH, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            m_label = label_re.match(line)
            if m_label:
                current = (m_label.group(2), int(m_label.group(1), 16))
                continue
            if any_label_re.match(line):
                current = None
                continue
            m = src_re.match(line)
            if current and m:
                sources.setdefault(current, m.group(1))
                current = None

    _FUNCTION_SOURCE_CACHE = sources
    return sources


def source_file_for_function_label(addr: int, mangled: str, owner: str) -> Optional[str]:
    """Return the first source annotation inside the exact owned function block."""
    if parse_owner_from_symbol(mangled) != owner:
        return None
    return parse_function_label_sources().get((mangled, addr))


def parse_owner_from_symbol(name: str) -> Optional[str]:
    if name.startswith("@") or "__vt__" in name:
        return None

    # Ordinary methods: method__7clsFooF...
    m = re.search(r"__(\d+)([A-Za-z_]\w*)F", name)
    if m:
        n = int(m.group(1))
        owner = m.group(2)[:n]
        return owner if len(owner) == n and "<" not in owner else None

    # Constructors/destructors: __ct__7clsFooF... / __dt__7clsFooF...
    m = re.search(r"__(?:ct|dt)__(\d+)([A-Za-z_]\w*)F", name)
    if m:
        n = int(m.group(1))
        owner = m.group(2)[:n]
        return owner if len(owner) == n and "<" not in owner else None

    return None


def parse_method_from_symbol(name: str, owner: str) -> Optional[str]:
    if name.startswith("@") or "__vt__" in name:
        return None

    if re.search(r"__ct__\d+" + re.escape(owner) + r"F", name):
        return owner

    if re.search(r"__dt__\d+" + re.escape(owner) + r"F", name):
        return "~" + owner

    m = re.search(r"__(\d+)" + re.escape(owner) + r"C?F", name)
    if m:
        return name[: m.start()]

    return None


def weak_methods_by_owner(symbol_owners: Dict[str, SymbolOwner]) -> Dict[str, Set[str]]:
    weak_methods: Dict[str, Set[str]] = {}
    for owner_name, owner in symbol_owners.items():
        for mangled, _addr in owner.weak_function_symbols:
            method_name = parse_method_from_symbol(mangled, owner_name)
            if method_name:
                weak_methods.setdefault(owner_name, set()).add(method_name)
    return weak_methods


def parse_symbol_owners(path: str) -> Dict[str, SymbolOwner]:
    owners: Dict[str, SymbolOwner] = {}
    if not os.path.exists(path):
        return owners

    addr_re = re.compile(r"=\s*(?:\.\w+:)?0x([0-9A-Fa-f]+)")
    weak_re = re.compile(r"visibility:weak|allow_duplicated:true")

    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("//") or "=" not in line:
                continue
            symbol_name = line.split("=", 1)[0].strip()
            owner = parse_owner_from_symbol(symbol_name)
            if owner is None:
                continue
            m = addr_re.search(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            entry = owners.setdefault(owner, SymbolOwner(owner))
            if weak_re.search(line):
                entry.weak_function_symbols.append((symbol_name, addr))
            else:
                entry.function_symbols.append((symbol_name, addr))

    return owners


def first_expected_owner(
    class_name: str, owner: SymbolOwner, line_entries: Sequence[Tuple[int, str]]
) -> ExpectedOwner:
    # Prefer non-weak functions because they usually identify the owning .cpp TU.
    # Anchor on exact objdump function labels so line-info references from
    # neighbouring functions, templates, parameters, or inline calls do not
    # masquerade as ownership.
    for mangled, addr in owner.function_symbols + owner.weak_function_symbols:
        source_line_file = source_file_for_function_label(addr, mangled, class_name)
        if not source_line_file:
            source_line_file = closest_source_file(line_entries, addr)
        if not source_line_file:
            continue
        project_path = source_line_to_project_path(source_line_file)
        if not project_path:
            continue
        header, source = project_source_to_repo_paths(project_path)
        return ExpectedOwner(class_name, source_line_file, header, source)
    return ExpectedOwner(class_name, None, None, None)


def expected_sources_for_owner(
    class_name: str, owner: SymbolOwner, line_entries: Sequence[Tuple[int, str]]
) -> Set[str]:
    sources: Set[str] = set()
    symbols = owner.function_symbols or owner.weak_function_symbols
    for mangled, addr in symbols:
        source_line_file = source_file_for_function_label(addr, mangled, class_name)
        if not source_line_file:
            source_line_file = closest_source_file(line_entries, addr)
        if not source_line_file:
            continue
        project_path = source_line_to_project_path(source_line_file)
        if not project_path:
            continue
        _header, source = project_source_to_repo_paths(project_path)
        if source:
            sources.add(source)
    return sources


def iter_files(root: str, exts: Set[str]) -> Iterable[str]:
    if not os.path.isdir(root):
        return
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if os.path.splitext(fname)[1] in exts:
                yield os.path.join(dirpath, fname)


def scan_class_definitions() -> Dict[str, Set[str]]:
    class_locations: Dict[str, Set[str]] = {}
    class_pat = re.compile(r"\b(?:class|struct)\s+([A-Za-z_]\w*)\b")

    for path in iter_files(os.path.join(ROOT_DIR, "include"), HEADER_EXTS):
        rel = relpath(path)
        pending: Optional[str] = None
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.rstrip("\n")
                    active_line = line.split("//", 1)[0]
                    stripped = active_line.strip()
                    if not stripped or stripped.startswith(("//", "*")):
                        continue

                    if "{" in active_line:
                        brace_prefix = active_line[: active_line.find("{")]
                        matched = False
                        for m in class_pat.finditer(active_line):
                            if ";" not in brace_prefix:
                                class_locations.setdefault(m.group(1), set()).add(rel)
                                matched = True
                        if not matched and pending and ";" not in brace_prefix:
                            class_locations.setdefault(pending, set()).add(rel)
                        pending = None
                        continue

                    m = class_pat.search(active_line)
                    if m:
                        pending = None if stripped.endswith(";") else m.group(1)
                    elif stripped and not active_line[:1].isspace() and not stripped.startswith(":"):
                        pending = None
        except OSError:
            continue

    return class_locations


def is_typedef_only_shim(path: str, class_name: str) -> bool:
    class_re = re.compile(r"\b(?:class|struct)\s+" + re.escape(class_name) + r"\b")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = list(fh)
    except OSError:
        return False

    for idx, raw in enumerate(lines):
        line = raw.split("//", 1)[0]
        if not class_re.search(line):
            continue
        if ";" in line and ("{" not in line or line.find(";") < line.find("{")):
            continue

        body: List[str] = []
        depth = line.count("{") - line.count("}")
        pos = idx + 1
        while pos < len(lines) and depth > 0:
            body_line = lines[pos].split("//", 1)[0]
            body.append(body_line.strip())
            depth += body_line.count("{") - body_line.count("}")
            pos += 1

        meaningful = [
            text
            for text in body
            if text and text not in {"public:", "private:", "protected:", "};"}
        ]
        return bool(meaningful) and all(text.startswith("typedef ") for text in meaningful)
    return False


def prune_typedef_shims(class_locations: Dict[str, Set[str]]) -> None:
    for class_name, paths in list(class_locations.items()):
        for rel in list(paths):
            if is_typedef_only_shim(os.path.join(ROOT_DIR, rel), class_name):
                paths.remove(rel)
        if not paths:
            del class_locations[class_name]


def scan_method_definitions(weak_methods: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    source_locations: Dict[str, Set[str]] = {}
    # Deliberately broad: this catches constructors, destructors, and ordinary methods.
    method_pat = re.compile(
        r"\b([A-Za-z_]\w*)::(~?[A-Za-z_]\w*|operator\s*[^\s(]+)\s*\("
    )

    for path in iter_files(os.path.join(ROOT_DIR, "src"), SOURCE_EXTS):
        rel = relpath(path)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    stripped = raw.strip()
                    if not stripped or stripped.startswith(("//", "*")):
                        continue
                    for m in method_pat.finditer(raw):
                        suffix = raw[m.end() :]
                        if ";" in suffix and ("{" not in suffix or suffix.find(";") < suffix.find("{")):
                            continue
                        owner_name = m.group(1)
                        method_name = m.group(2)
                        if method_name in weak_methods.get(owner_name, set()):
                            continue
                        source_locations.setdefault(owner_name, set()).add(rel)
        except OSError:
            continue

    return source_locations


def build_findings() -> Tuple[List[MigrationFinding], int, int]:
    symbol_owners = parse_symbol_owners(SYMBOLS_PATH)
    line_entries = parse_line_info(LINE_INFO_PATH)
    headers_by_class = scan_class_definitions()
    prune_typedef_shims(headers_by_class)
    sources_by_class = scan_method_definitions(weak_methods_by_owner(symbol_owners))

    findings: List[MigrationFinding] = []
    checked = 0

    for class_name in sorted(symbol_owners):
        if class_name.startswith(SKIP_OWNER_PREFIXES):
            continue
        if class_name not in headers_by_class and class_name not in sources_by_class:
            continue
        expected = first_expected_owner(class_name, symbol_owners[class_name], line_entries)
        if not expected.header and not expected.source:
            continue
        checked += 1

        actual_headers = sorted(headers_by_class.get(class_name, set()))
        actual_sources = sorted(sources_by_class.get(class_name, set()))
        expected_sources = expected_sources_for_owner(class_name, symbol_owners[class_name], line_entries)

        wrong_headers = [p for p in actual_headers if expected.header and not same_path_ignoring_case(p, expected.header)]
        wrong_sources = [
            p
            for p in actual_sources
            if expected.source and p not in (expected_sources or {expected.source})
        ]

        if not wrong_headers and not wrong_sources:
            continue

        reasons: List[str] = []
        if wrong_headers:
            reasons.append("class/struct definition is outside expected header")
        if wrong_sources:
            reasons.append("method definition is outside expected source")

        findings.append(
            MigrationFinding(
                class_name=class_name,
                expected_header=expected.header,
                expected_source=expected.source,
                actual_headers=actual_headers,
                actual_sources=actual_sources,
                reason="; ".join(reasons),
            )
        )

    return findings, checked, len(symbol_owners)


def md_list(paths: List[str]) -> str:
    if not paths:
        return ""
    return "<br>".join(f"`{path}`" for path in paths)


def write_report(path: str, findings: List[MigrationFinding], checked: int, total: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    today = datetime.date.today().isoformat()
    lines: List[str] = []
    lines.append("# Scaffold Migration Candidates\n\n")
    lines.append(f"Generated: {today}\n\n")
    lines.append("Regenerate with: `python tools/decomp-workflow.py scaffold-migration`\n\n")
    lines.append(
        "This report compares current class/source locations against canonical ownership "
        "derived from `symbol_addrs.txt` and `symbols/sr2_line_info.nothpp`.\n\n"
    )
    lines.append(f"Checked: {checked} declared/defined symbol owners out of {total} symbol owners.\n\n")
    lines.append(f"Migration candidates: {len(findings)}\n\n")

    if not findings:
        lines.append("No migration candidates found.\n")
    else:
        lines.append(
            "| Status | Owner | Expected Header | Actual Header(s) | Expected Source | Actual Source(s) | Reason |\n"
        )
        lines.append(
            "|:------:|-------|-----------------|------------------|-----------------|------------------|--------|\n"
        )
        for finding in findings:
            lines.append(
                "| [ ] "
                f"| `{finding.class_name}` "
                f"| `{finding.expected_header or ''}` "
                f"| {md_list(finding.actual_headers)} "
                f"| `{finding.expected_source or ''}` "
                f"| {md_list(finding.actual_sources)} "
                f"| {finding.reason} |\n"
            )

    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=os.path.join(ROOT_DIR, "docs", "scaffold-migration.md"),
        help="Report path (default: docs/scaffold-migration.md)",
    )
    args = parser.parse_args()

    findings, checked, total = build_findings()
    write_report(args.output, findings, checked, total)
    print(f"Wrote {len(findings)} migration candidates to {relpath(args.output)}")
    print(f"Checked {checked} declared/defined symbol owners out of {total} symbol owners")


if __name__ == "__main__":
    main()
