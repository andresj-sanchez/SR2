#!/usr/bin/env python3
"""Generate a report-only queue for pure-C SDK/library declarations.

This report is intentionally conservative: it reads DWARF-by-unit ownership
evidence, filters to SDK/library unit paths, removes symbols that already appear
under include/usr/local or src/usr/local, and writes a manual checklist grouped
by suggested canonical header.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_INDEX = os.path.join(ROOT_DIR, "symbols", "DwarfByUnit", "index.json")
DEFAULT_OUTPUT = os.path.join(ROOT_DIR, "docs", "scaffold-c-queue.md")

SDK_MARKERS = (
    "/usr/local/sega/",
    "/usr/local/cri/",
    "/usr/local/sce/",
    "/usr/local/metrowerks/",
)
HEADER_EXTS = {".h", ".hpp", ".hh"}
SOURCE_EXTS = {".c", ".cpp"}
SCAN_EXTS = HEADER_EXTS | SOURCE_EXTS
CHECKLIST_KINDS = {"class", "struct", "enum", "typedef", "global", "function"}


@dataclass
class SourceInventory:
    type_names: Set[str] = field(default_factory=set)
    typedef_names: Set[str] = field(default_factory=set)
    enum_names: Set[str] = field(default_factory=set)
    global_names: Set[str] = field(default_factory=set)
    function_names: Set[str] = field(default_factory=set)


@dataclass
class QueueRecord:
    kind: str
    name: str
    display: str
    key: str
    detail: str
    fingerprint: str
    total_entries: int
    unit_block_count: int
    unit_paths: List[str]


def relpath(path: str) -> str:
    try:
        return os.path.relpath(path, ROOT_DIR).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def md_code(value: str) -> str:
    return "`" + value.replace("`", "\\`") + "`"


def md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def normalize_unit_path(path: str) -> str:
    return path.strip().replace("\\", "/")


def unit_kind(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in HEADER_EXTS:
        return "header"
    if ext in SOURCE_EXTS:
        return "source"
    return "other"


def source_scope_relpath(unit_path: str, root_name: str) -> Optional[str]:
    normalized = normalize_unit_path(unit_path)
    lower = normalized.lower()
    marker = "/usr/local/"
    if marker not in lower:
        return None
    suffix = normalized[lower.index(marker) + 1 :]
    return f"{root_name}/{suffix}".replace("\\", "/")


def existing_repo_path(candidates: Sequence[str]) -> Optional[str]:
    for candidate in candidates:
        if os.path.exists(os.path.join(ROOT_DIR, candidate)):
            return candidate
    return None


def repo_source_path(unit_path: str) -> Optional[str]:
    rel = source_scope_relpath(unit_path, "src")
    if not rel:
        return None
    return rel if os.path.exists(os.path.join(ROOT_DIR, rel)) else rel


def repo_header_candidates(unit_path: str) -> List[str]:
    normalized = normalize_unit_path(unit_path)
    ext = os.path.splitext(normalized)[1].lower()
    base = os.path.splitext(source_scope_relpath(normalized, "include") or "")[0]
    if not base:
        return []
    if ext in HEADER_EXTS:
        return [base + ext]
    candidates = [base + ".h", base + ".hpp", base + ".hh"]
    dirname = os.path.dirname(base)
    basename = os.path.basename(base)
    if basename.startswith("nn") and dirname:
        # Many NNS source files share a directory-level umbrella header, but the
        # same-base header is still the safest first suggestion when present.
        candidates.append(os.path.join(dirname, os.path.basename(dirname).lower() + ".h").replace("\\", "/"))
    return candidates


def suggested_header(unit_paths: Sequence[str]) -> str:
    header_paths = [path for path in unit_paths if unit_kind(path) == "header"]
    candidate_paths: List[str] = []
    for path in sorted(header_paths) + sorted(unit_paths):
        candidate_paths.extend(repo_header_candidates(path))
    existing = existing_repo_path(candidate_paths)
    if existing:
        return existing
    if candidate_paths:
        return candidate_paths[0]
    return "include/usr/local/UNKNOWN.h"


def validation_path(unit_paths: Sequence[str], header: str) -> str:
    for path in sorted(unit_paths):
        if unit_kind(path) == "source":
            source_path = repo_source_path(path)
            if source_path:
                return source_path
    return header


def iter_scan_files() -> Iterable[str]:
    root = os.path.join(ROOT_DIR, "include", "usr", "local")
    for scan_root in (root, os.path.join(ROOT_DIR, "src", "usr", "local")):
        if not os.path.isdir(scan_root):
            continue
        for dirpath, _dirs, files in os.walk(scan_root):
            for fname in files:
                if os.path.splitext(fname)[1].lower() in SCAN_EXTS:
                    yield os.path.join(dirpath, fname)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def build_source_inventory() -> SourceInventory:
    inventory = SourceInventory()
    type_re = re.compile(r"\b(?:class|struct)\s+(?P<name>[A-Za-z_]\w*)\b")
    enum_re = re.compile(r"\benum\s+(?:class\s+)?(?P<name>[A-Za-z_]\w*)\b")
    typedef_re = re.compile(r"\btypedef\b[^;]*?\b(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;")
    function_re = re.compile(
        r"(?<![A-Za-z_0-9])(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:;|\{)"
    )
    extern_global_re = re.compile(
        r"^\s*(?:extern\s+|static\s+|const\s+)*[A-Za-z_][\w\s:<>*&]*?\s+"
        r"(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]+\])*\s*(?:;|=)"
    )
    function_pointer_re = re.compile(
        r"^\s*(?:extern\s+|static\s+)*[A-Za-z_][\w\s:<>*&]*?\s*"
        r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*\([^;]*\)\s*(?:;|=)"
    )
    pointer_return_function_re = re.compile(
        r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\)\s*(?:\[[^\]]+\]\s*)+\s*(?:;|\{)"
    )
    pointer_array_global_re = re.compile(
        r"^\s*(?:extern\s+|static\s+|const\s+)*[A-Za-z_][\w\s:<>*&]*?\s*"
        r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*(?:\[[^\]]+\]\s*)+\s*(?:;|=)"
    )
    skip_functions = {"if", "for", "while", "switch", "return", "sizeof"}
    skip_globals = {"typedef", "struct", "class", "enum", "return", "if", "for", "while", "switch"}

    for path in iter_scan_files():
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = strip_comments(fh.read())
        except OSError:
            continue

        for match in type_re.finditer(text):
            inventory.type_names.add(match.group("name"))
        for match in enum_re.finditer(text):
            inventory.enum_names.add(match.group("name"))
        for match in typedef_re.finditer(text):
            inventory.typedef_names.add(match.group("name"))

        flat_text = re.sub(r"\s+", " ", text)
        for match in function_re.finditer(flat_text):
            name = match.group("name")
            if name not in skip_functions:
                inventory.function_names.add(name)
        for match in pointer_return_function_re.finditer(flat_text):
            inventory.function_names.add(match.group("name"))

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "::" in stripped:
                continue
            first = stripped.split(None, 1)[0]
            if first in skip_globals:
                continue
            match = function_pointer_re.match(stripped) or pointer_array_global_re.match(stripped)
            if not match and "(" not in stripped:
                match = extern_global_re.match(stripped)
            if match:
                inventory.global_names.add(match.group("name"))

    return inventory


def source_inventory_has_record(inventory: SourceInventory, record: QueueRecord) -> bool:
    name = record_effective_name(record).split("::")[-1]
    if record.kind in {"class", "struct"}:
        return name in inventory.type_names or name in inventory.typedef_names
    if record.kind == "enum":
        return name in inventory.enum_names or name in inventory.typedef_names
    if record.kind == "typedef":
        return name in inventory.typedef_names
    if record.kind == "global":
        return name in inventory.global_names
    if record.kind == "function":
        return name in inventory.function_names
    return False


def record_effective_name(record: QueueRecord) -> str:
    display = record.display.strip()
    if record.kind == "function":
        pointer_match = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\)", display)
        if pointer_match:
            return pointer_match.group(1)
        match = re.search(r"\b([A-Za-z_]\w*)\s*\(", display)
        if match:
            return match.group(1)
    if record.kind == "global":
        pointer_match = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*(?:\[[^\]]+\]\s*)+", display)
        if pointer_match:
            return pointer_match.group(1)
    return record.name.strip()


def detail_address(detail: str) -> Optional[int]:
    match = re.search(r"address\s+(0x[0-9A-Fa-f]+)", detail)
    return int(match.group(1), 16) if match else None


def is_sdk_unit_path(path: str) -> bool:
    normalized = normalize_unit_path(path).lower()
    return any(marker in normalized for marker in SDK_MARKERS)


def is_supported_record(record: QueueRecord) -> bool:
    if record.kind not in CHECKLIST_KINDS:
        return False
    if not record.unit_paths or not all(is_sdk_unit_path(path) for path in record.unit_paths):
        return False
    name = record.name.strip()
    display = record.display.strip()
    if not name or "@" in name or "::" in name:
        return False
    if name.startswith("@") or name in {"_end", "_stack_size"}:
        return False
    if record.kind == "function" and ("operator" in display or name.startswith("~")):
        return False
    if record.kind in {"function", "global"} and display.startswith("static "):
        return False
    if record.kind == "global":
        if "__vtable" in display or display.startswith("void ") and "size 0x0" in record.detail:
            return False
        address = detail_address(record.detail)
        if address == 0:
            return False
    if record.kind in {"class", "struct"} and ("__vtable" in display or "@anon" in display):
        return False
    return True


def load_records(index_path: str) -> List[QueueRecord]:
    with open(index_path, encoding="utf-8") as fh:
        data = json.load(fh)
    records: List[QueueRecord] = []
    for entry in data.get("symbols", []):
        records.append(
            QueueRecord(
                kind=entry.get("kind", ""),
                name=entry.get("name", ""),
                display=entry.get("display", ""),
                key=entry.get("key", ""),
                detail=entry.get("detail", ""),
                fingerprint=entry.get("fingerprint", ""),
                total_entries=int(entry.get("total_entries", 0)),
                unit_block_count=int(entry.get("unit_block_count", 0)),
                unit_paths=list(entry.get("unit_paths", [])),
            )
        )
    return records


def load_checked_keys(path: str) -> Set[str]:
    if not os.path.exists(path):
        return set()
    checked: Set[str] = set()
    key_re = re.compile(r"\|\s*\[x\]\s*\|.*<!--\s*scaffold-c:([^>]+?)\s*-->", re.IGNORECASE)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            match = key_re.search(line)
            if match:
                checked.add(match.group(1).strip())
    return checked


def evidence_summary(record: QueueRecord) -> str:
    parts = [md_code(record.display)]
    if record.kind == "class":
        parts.append("emit as C `struct`, not C++ `class`")
    if record.detail:
        parts.append(md_code(record.detail))
    parts.append(f"paths: {len(record.unit_paths)}")
    parts.append(f"blocks: {record.unit_block_count}")
    parts.append(f"entries: {record.total_entries}")
    return "; ".join(parts)


def unit_paths_summary(paths: Sequence[str], limit: int = 4) -> str:
    sorted_paths = sorted(paths)
    shown = sorted_paths[:limit]
    text = "<br>".join(md_code(path) for path in shown)
    if len(sorted_paths) > limit:
        text += f"<br>+{len(sorted_paths) - limit} more"
    return text


def build_queue(records: Sequence[QueueRecord], inventory: SourceInventory) -> List[Tuple[str, QueueRecord]]:
    queue: List[Tuple[str, QueueRecord]] = []
    seen: Set[Tuple[str, str, str]] = set()
    for record in records:
        if not is_supported_record(record):
            continue
        if source_inventory_has_record(inventory, record):
            continue
        header = suggested_header(record.unit_paths)
        key = (header, record.kind, record.name)
        if key in seen:
            continue
        seen.add(key)
        queue.append((header, record))
    return sorted(queue, key=lambda item: (item[0], item[1].kind, item[1].name, item[1].display))


def filter_checked_queue(
    queue: Sequence[Tuple[str, QueueRecord]], checked_keys: Set[str]
) -> List[Tuple[str, QueueRecord]]:
    return [(header, record) for header, record in queue if record.key not in checked_keys]


def write_queue_section(
    lines: List[str], title: str, by_header: Dict[str, List[QueueRecord]], checked_keys: Set[str]
) -> None:
    total = sum(len(records) for records in by_header.values())
    lines.append(f"## {title}\n\n")
    lines.append(f"Candidates: {total}\n\n")
    if not total:
        lines.append("No candidates in this section.\n\n")
        return

    for header in sorted(by_header):
        records = by_header[header]
        lines.append(f"### {header}\n\n")
        validate = validation_path([path for record in records for path in record.unit_paths], header)
        lines.append(f"Suggested validation: `python tools/decomp-workflow.py validate {validate}`\n\n")
        lines.append("| Status | Kind | Symbol | Unit Paths | Evidence |\n")
        lines.append("|:------:|------|--------|------------|----------|\n")
        for record in records:
            status = "x" if record.key in checked_keys else " "
            kind = "struct (DWARF class)" if record.kind == "class" else record.kind
            lines.append(
                f"| [{status}] "
                f"| {md_code(kind)} "
                f"| {md_code(record.name)} "
                f"| {unit_paths_summary(record.unit_paths)} "
                f"| {md_cell(evidence_summary(record))} <!-- scaffold-c:{record.key} --> |\n"
            )
        lines.append("\n")


def write_report(path: str, index_path: str, queue: Sequence[Tuple[str, QueueRecord]], checked_keys: Set[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    today = datetime.date.today().isoformat()
    by_kind: Dict[str, int] = {}
    function_by_header: Dict[str, List[QueueRecord]] = {}
    declaration_by_header: Dict[str, List[QueueRecord]] = {}
    for header, record in queue:
        by_kind[record.kind] = by_kind.get(record.kind, 0) + 1
        if record.kind == "function":
            function_by_header.setdefault(header, []).append(record)
        else:
            declaration_by_header.setdefault(header, []).append(record)

    lines: List[str] = []
    lines.append("# C SDK Scaffold Queue\n\n")
    lines.append(f"Generated: {today}\n\n")
    lines.append("Regenerate with: `python tools/decomp-workflow.py scaffold-c-queue`\n\n")
    lines.append(
        "This report lists missing pure-C SDK/library declarations inferred from "
        f"{md_code(relpath(index_path))}. It is report-only: confirm each row with "
        "DWARF/source evidence before editing canonical `include/usr/local/...` headers.\n\n"
    )
    lines.append(
        "Rows are scoped to `usr/local/sega/`, `usr/local/cri/`, `usr/local/sce/`, "
        "and `usr/local/metrowerks/`, and records already seen under `include/usr/local` "
        "or `src/usr/local` are excluded. DWARF `class` rows must be emitted as C-compatible "
        "`struct` declarations in these headers.\n\n"
    )
    lines.append(f"Queue candidates: {len(queue)}\n\n")
    lines.append("| Kind | Count |\n")
    lines.append("|------|------:|\n")
    for kind in sorted(CHECKLIST_KINDS):
        lines.append(f"| {kind} | {by_kind.get(kind, 0)} |\n")
    lines.append("\n")

    if not queue:
        lines.append("No missing C SDK declaration candidates found after current-source filtering.\n")
    else:
        lines.append(
            "Function prototypes are listed first because their owning source/header is usually clear. "
            "Data and type declarations follow separately because they often need extra ownership review.\n\n"
        )
        write_queue_section(lines, "Function Prototype Queue", function_by_header, checked_keys)
        write_queue_section(lines, "Data And Type Declaration Queue", declaration_by_header, checked_keys)

    output = "".join(lines).rstrip() + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", default=DEFAULT_INDEX, help="DWARF-by-unit index path")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Markdown report path")
    args = parser.parse_args()

    index_path = os.path.abspath(args.index)
    output_path = os.path.abspath(args.output)
    records = load_records(index_path)
    inventory = build_source_inventory()
    checked_keys = load_checked_keys(output_path)
    queue = filter_checked_queue(build_queue(records, inventory), checked_keys)
    write_report(output_path, index_path, queue, checked_keys)
    print(f"Wrote {relpath(output_path)} ({len(queue)} candidates)")


if __name__ == "__main__":
    main()
