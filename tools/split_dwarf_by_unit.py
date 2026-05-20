#!/usr/bin/env python3
"""Split a DTK DWARF dump by unit path and index ownership evidence.

This is an evidence generator, not an automatic scaffold mover. It reads only
symbols/sr2_dwarfdump.nothpp, writes raw per-DWARF-unit-block .nothpp files, and
builds conservative reports that help identify declarations with narrow DWARF
ownership evidence.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_INPUT = os.path.join(ROOT_DIR, "symbols", "sr2_dwarfdump.nothpp")
DEFAULT_OUTPUT = os.path.join(ROOT_DIR, "symbols", "DwarfByUnit")
SYMBOL_ADDRS_PATH = os.path.join(ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "symbol_addrs.txt")

UNIT_EXTS = {".c", ".cpp", ".h", ".hpp"}
HEADER_EXTS = {".h", ".hpp"}
SOURCE_EXTS = {".c", ".cpp"}
STRIPPED_ADDR = "0XFFFFFFFF"
SOURCE_SCAN_EXTS = {".c", ".cpp", ".h", ".hpp", ".hh"}
CHECKLIST_KINDS = {"class", "struct", "function", "global"}

RE_TOTAL_SIZE = re.compile(r"^// total size:\s*(0x[0-9A-Fa-f]+)")
RE_STRUCT_NAME = re.compile(r"\b(struct|class)\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)?)")
RE_ENUM_START = re.compile(r"^enum\s+(?:class\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w:]+\s*)?\{")
RE_ENUM_NAME = re.compile(r"^enum\s+(?:class\s+)?([A-Za-z_]\w*)")
RE_FUNC_RANGE = re.compile(r"^// Range:\s*(0x[0-9A-Fa-f]+)\s*->\s*(0x[0-9A-Fa-f]+)")
RE_MEMBER = re.compile(r"offset\s+0x[0-9A-Fa-f]+,\s*size\s+0x[0-9A-Fa-f]+")
RE_ENUM_VALUE = re.compile(r"^\s+([A-Za-z_]\w*)\s*=\s*(-?\d+)", re.MULTILINE)
RE_TYPEDEF = re.compile(r"^typedef\s+\S")
RE_GLOBAL_DECL = re.compile(r"^(?:[\w\s:<>*&]+?)\b\w+(?:\s*\[[^\]]*\])*\s*;")
RE_GLOBAL_FUNCPTR_DECL = re.compile(r"^.+\(\*\s*\w+(?:\s*\[[^\]]*\])*\s*\).+;$")
RE_CHECKLIST_STATE = re.compile(r"^- \[(?P<state>[ xX])\].*<!--\s*dwarf-(?:check|symbol):(?P<key>[^>]+?)\s*-->")


@dataclass
class SymbolEntry:
    kind: str
    name: str
    key: str
    display: str
    fingerprint: str
    detail: str = ""


@dataclass
class UnitEntry:
    unit_id: int
    path: str
    normalized_path: str
    kind: str
    producer: str
    language: str
    output_path: Optional[str]
    line_count: int
    symbol_counts: Dict[str, int]
    symbol_keys: List[str]


@dataclass
class SymbolRecord:
    kind: str
    name: str
    key: str
    display: str
    fingerprint: str
    detail: str = ""
    total_entries: int = 0
    units: Set[int] = field(default_factory=set)
    unit_paths: Set[str] = field(default_factory=set)


@dataclass
class SourceInventory:
    type_names: Set[str] = field(default_factory=set)
    global_names: Set[str] = field(default_factory=set)
    qualified_global_names: Set[str] = field(default_factory=set)
    function_names: Set[str] = field(default_factory=set)
    qualified_function_names: Set[str] = field(default_factory=set)


_SYMBOL_ADDRS: Optional[Dict[str, Set[int]]] = None


@dataclass
class ChecklistItem:
    kind: str
    name: str
    display: str
    key: str
    details: Set[str] = field(default_factory=set)
    owner_candidates: Set[str] = field(default_factory=set)
    total_entries: int = 0
    units: Set[int] = field(default_factory=set)
    unit_paths: Set[str] = field(default_factory=set)


def relpath(path: str) -> str:
    try:
        return os.path.relpath(path, ROOT_DIR).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def md_code(value: str) -> str:
    return "`" + value.replace("`", "\\`") + "`"


def normalize_unit_path(path: str) -> str:
    return path.strip().replace("\\", "/")


def unit_kind(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in HEADER_EXTS:
        return "header"
    if ext in SOURCE_EXTS:
        return "source"
    return "other"


def is_supported_unit(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in UNIT_EXTS


def output_unit_relpath(normalized_path: str, seen: Dict[str, int]) -> str:
    path = re.sub(r"^[A-Za-z]:/", "", normalized_path).lstrip("/")
    path = re.sub(r'[<>:"|?*]', "_", path)
    path = path or "unknown"
    count = seen.get(path, 0) + 1
    seen[path] = count
    if count > 1:
        stem, ext = os.path.splitext(path)
        path = f"{stem}__{count}{ext}"
    return path + ".nothpp"


def short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:12]


def strip_inline_comment(line: str) -> str:
    return re.sub(r"\s*//.*$", "", line.strip())


def parse_unit_metadata(lines: Sequence[str]) -> Tuple[str, str]:
    producer = ""
    language = ""
    for line in lines[:12]:
        stripped = line.strip()
        if stripped.startswith("Producer:"):
            producer = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Language:"):
            language = stripped.split(":", 1)[1].strip()
        elif stripped == "*/":
            break
    return producer, language


def extract_struct_blocks(lines: Sequence[str]) -> List[str]:
    blocks: List[str] = []
    current: List[str] = []
    in_block = False
    brace_depth = 0

    for line in lines:
        if not in_block:
            if RE_TOTAL_SIZE.match(line):
                current = [line]
                in_block = True
                brace_depth = 0
            continue
        current.append(line)
        brace_depth += line.count("{") - line.count("}")
        if brace_depth == 0 and line.rstrip().endswith("};"):
            blocks.append("".join(current))
            in_block = False

    return blocks


def extract_enum_blocks(lines: Sequence[str]) -> List[str]:
    blocks: List[str] = []
    current: List[str] = []
    in_block = False
    brace_depth = 0

    for line in lines:
        stripped = line.strip()
        if not in_block:
            if RE_ENUM_START.match(line):
                current = [line]
                in_block = True
                brace_depth = line.count("{") - line.count("}")
            continue
        current.append(line)
        brace_depth += line.count("{") - line.count("}")
        if brace_depth == 0 and stripped.endswith("};"):
            blocks.append("".join(current))
            in_block = False

    return blocks


def extract_function_blocks(lines: Sequence[str], exclude_stripped: bool) -> List[str]:
    blocks: List[str] = []
    current: List[str] = []
    in_block = False
    brace_depth = 0
    skip = False

    for line in lines:
        if not in_block:
            m = RE_FUNC_RANGE.match(line)
            if m:
                start, end = m.group(1).upper(), m.group(2).upper()
                skip = exclude_stripped and (start == STRIPPED_ADDR or end == STRIPPED_ADDR)
                current = [line]
                in_block = True
                brace_depth = 0
            continue
        current.append(line)
        brace_depth += line.count("{") - line.count("}")
        if brace_depth == 0 and "}" in line:
            if not skip:
                blocks.append("".join(current))
            in_block = False

    return blocks


def extract_line_decls(lines: Sequence[str]) -> List[str]:
    results: List[str] = []
    in_skip_block = False
    brace_depth = 0

    for line in lines:
        stripped = line.strip()

        if not in_skip_block:
            if RE_TOTAL_SIZE.match(line) or RE_ENUM_START.match(line):
                in_skip_block = True
                brace_depth = line.count("{") - line.count("}")
                continue
            if RE_FUNC_RANGE.match(line):
                in_skip_block = True
                brace_depth = 0
                continue

        if in_skip_block:
            brace_depth += line.count("{") - line.count("}")
            if brace_depth == 0 and "}" in line:
                in_skip_block = False
            continue

        if not stripped or stripped.startswith("//"):
            continue
        if line[0].isspace():
            continue
        code = strip_inline_comment(stripped)
        if not code.endswith(";") or "{" in code:
            continue
        if RE_TYPEDEF.match(code) or RE_GLOBAL_DECL.match(code) or RE_GLOBAL_FUNCPTR_DECL.match(code):
            results.append(line.rstrip())

    return results


def member_fingerprint(block: str) -> str:
    parts: List[str] = []
    size = RE_TOTAL_SIZE.search(block)
    if size:
        parts.append(size.group(1).lower())
    parts.extend(RE_MEMBER.findall(block))
    parts.extend(f"{m.group(1)}={m.group(2)}" for m in RE_ENUM_VALUE.finditer(block))
    if not parts:
        parts.append("empty")
    return short_hash("\n".join(parts))


def first_code_line(block: str) -> str:
    for line in block.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("//"):
            return stripped
    return ""


def function_signature(block: str) -> str:
    for line in block.splitlines()[1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if "(" in stripped:
            return stripped.rstrip("{").strip()
    return ""


def function_name(signature: str) -> str:
    prefix = signature.split("(", 1)[0].strip()
    if "operator" in prefix:
        idx = prefix.rfind("operator")
        owner = prefix[:idx].split()[-1] if prefix[:idx].split() else ""
        return (owner + " " + prefix[idx:]).strip()
    tokens = prefix.split()
    return tokens[-1] if tokens else signature


def range_detail(block: str) -> str:
    m = RE_FUNC_RANGE.search(block)
    if not m:
        return ""
    return f"{m.group(1)} -> {m.group(2)}"


def typedef_name(code: str) -> Optional[str]:
    m = re.search(r"\(\*\s*([A-Za-z_]\w*)\s*\)", code)
    if m:
        return m.group(1)
    m = re.search(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;$", code)
    return m.group(1) if m else None


def global_name(code: str) -> Optional[str]:
    m = re.search(r"\(\*\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*\)", code)
    if m:
        return m.group(1)
    m = re.search(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;$", code)
    return m.group(1) if m else None


def parse_line_decl(line: str) -> Optional[SymbolEntry]:
    code = strip_inline_comment(line)
    if RE_TYPEDEF.match(code):
        name = typedef_name(code)
        if not name:
            return None
        fingerprint = short_hash(code)
        return SymbolEntry("typedef", name, f"typedef:{name}:{fingerprint}", code, fingerprint)

    name = global_name(code)
    if not name:
        return None
    detail_parts: List[str] = []
    m_size = re.search(r"// size:\s*(0x[0-9A-Fa-f]+)", line)
    m_addr = re.search(r"address:\s*(0x[0-9A-Fa-f]+)", line)
    if m_size:
        detail_parts.append(f"size {m_size.group(1)}")
    if m_addr:
        detail_parts.append(f"address {m_addr.group(1)}")
    detail = ", ".join(detail_parts)
    fingerprint = short_hash(code + "\n" + detail)
    return SymbolEntry("global", name, f"global:{name}:{fingerprint}", code, fingerprint, detail)


def extract_symbols(lines: Sequence[str], exclude_stripped: bool) -> List[SymbolEntry]:
    symbols: List[SymbolEntry] = []

    for block in extract_struct_blocks(lines):
        m = RE_STRUCT_NAME.search(block)
        if not m:
            continue
        kind, name = m.group(1), m.group(2)
        fingerprint = member_fingerprint(block)
        display = first_code_line(block).rstrip(";")
        symbols.append(SymbolEntry(kind, name, f"{kind}:{name}:{fingerprint}", display, fingerprint))

    for block in extract_enum_blocks(lines):
        m = RE_ENUM_NAME.search(block)
        if not m:
            continue
        name = m.group(1)
        fingerprint = member_fingerprint(block)
        display = first_code_line(block).rstrip("{").strip()
        symbols.append(SymbolEntry("enum", name, f"enum:{name}:{fingerprint}", display, fingerprint))

    for line in extract_line_decls(lines):
        entry = parse_line_decl(line)
        if entry:
            symbols.append(entry)

    for block in extract_function_blocks(lines, exclude_stripped=exclude_stripped):
        signature = function_signature(block)
        if not signature:
            continue
        name = function_name(signature)
        detail = range_detail(block)
        fingerprint = short_hash(signature + "\n" + detail)
        symbols.append(SymbolEntry("function", name, f"function:{name}:{fingerprint}", signature, fingerprint, detail))

    return symbols


def update_symbol_index(symbol_index: Dict[str, SymbolRecord], symbols: Sequence[SymbolEntry], unit_id: int, path: str) -> None:
    for symbol in symbols:
        record = symbol_index.get(symbol.key)
        if record is None:
            record = SymbolRecord(
                kind=symbol.kind,
                name=symbol.name,
                key=symbol.key,
                display=symbol.display,
                fingerprint=symbol.fingerprint,
                detail=symbol.detail,
            )
            symbol_index[symbol.key] = record
        record.total_entries += 1
        record.units.add(unit_id)
        record.unit_paths.add(path)


def symbol_counts(symbols: Sequence[SymbolEntry]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for symbol in symbols:
        counts[symbol.kind] = counts.get(symbol.kind, 0) + 1
    return dict(sorted(counts.items()))


def process_unit(
    unit_id: int,
    path: str,
    lines: Sequence[str],
    args: argparse.Namespace,
    seen_output_paths: Dict[str, int],
    units_dir: str,
    units: List[UnitEntry],
    symbol_index: Dict[str, SymbolRecord],
) -> None:
    normalized_path = normalize_unit_path(path)
    if not is_supported_unit(normalized_path):
        return

    output_rel: Optional[str] = None
    if not args.no_unit_files:
        output_rel = output_unit_relpath(normalized_path, seen_output_paths)
        output_path = os.path.join(units_dir, *output_rel.split("/"))
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines)

    producer, language = parse_unit_metadata(lines)
    symbols = extract_symbols(lines, exclude_stripped=args.no_stripped)
    unique_keys = sorted({symbol.key for symbol in symbols})
    update_symbol_index(symbol_index, symbols, unit_id, normalized_path)
    units.append(
        UnitEntry(
            unit_id=unit_id,
            path=path,
            normalized_path=normalized_path,
            kind=unit_kind(normalized_path),
            producer=producer,
            language=language,
            output_path=f"units/{output_rel}" if output_rel else None,
            line_count=len(lines),
            symbol_counts=symbol_counts(symbols),
            symbol_keys=unique_keys,
        )
    )


def iter_compile_units(input_path: str, args: argparse.Namespace, units_dir: str) -> Tuple[List[UnitEntry], Dict[str, SymbolRecord]]:
    units: List[UnitEntry] = []
    symbol_index: Dict[str, SymbolRecord] = {}
    seen_output_paths: Dict[str, int] = {}
    current_path: Optional[str] = None
    current_lines: List[str] = []
    unit_id = 0

    def flush() -> None:
        nonlocal unit_id, current_path, current_lines
        if current_path is not None:
            process_unit(unit_id, current_path, current_lines, args, seen_output_paths, units_dir, units, symbol_index)
            unit_id += 1
        current_path = None
        current_lines = []

    with open(input_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if "Compile unit:" in line:
                prefix: List[str] = []
                if current_lines and current_lines[-1].strip() == "/*":
                    prefix = [current_lines.pop()]
                flush()
                current_path = line.split("Compile unit:", 1)[1].strip()
                current_lines = prefix + [line]
                continue
            if current_path is not None or current_lines:
                current_lines.append(line)
        flush()

    return units, symbol_index


def symbol_records_for_json(symbol_index: Dict[str, SymbolRecord]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for record in sorted(symbol_index.values(), key=lambda r: (r.kind, r.name, r.key)):
        records.append(
            {
                "key": record.key,
                "kind": record.kind,
                "name": record.name,
                "display": record.display,
                "fingerprint": record.fingerprint,
                "detail": record.detail,
                "total_entries": record.total_entries,
                "unit_block_count": len(record.units),
                "unit_path_count": len(record.unit_paths),
                "units": sorted(record.units),
                "unit_paths": sorted(record.unit_paths),
            }
        )
    return records


def units_for_json(units: Sequence[UnitEntry]) -> List[Dict[str, Any]]:
    return [
        {
            "id": unit.unit_id,
            "path": unit.path,
            "normalized_path": unit.normalized_path,
            "kind": unit.kind,
            "producer": unit.producer,
            "language": unit.language,
            "output_path": unit.output_path,
            "line_count": unit.line_count,
            "symbol_counts": unit.symbol_counts,
            "symbol_keys": unit.symbol_keys,
        }
        for unit in units
    ]


def low_cardinality_records(symbol_index: Dict[str, SymbolRecord], max_shared: int) -> List[SymbolRecord]:
    return [record for record in symbol_index.values() if 1 < len(record.unit_paths) <= max_shared]


def likely_header_owner_records(symbol_index: Dict[str, SymbolRecord], max_shared: int) -> List[SymbolRecord]:
    records: List[SymbolRecord] = []
    for record in symbol_index.values():
        if len(record.unit_paths) > max_shared:
            continue
        if any(unit_kind(path) == "header" for path in record.unit_paths):
            records.append(record)
    return records


def iter_source_scan_files() -> Iterable[str]:
    for root_name in ("include", "src"):
        root = os.path.join(ROOT_DIR, root_name)
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fname in files:
                if os.path.splitext(fname)[1].lower() in SOURCE_SCAN_EXTS:
                    yield os.path.join(dirpath, fname)


def strip_source_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)


def add_class_method_decls(text: str, inventory: SourceInventory) -> None:
    lines = text.splitlines()
    class_name: Optional[str] = None
    pending_class_name: Optional[str] = None
    brace_depth = 0
    method_re = re.compile(r"(?<![A-Za-z_0-9])(?P<name>~?[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:;|\{|\}|$)")
    method_start_re = re.compile(r"(?<![A-Za-z_0-9])(?P<name>~?[A-Za-z_]\w*)\s*\([^;{}]*$")
    class_re = re.compile(r"\b(?:class|struct)\s+(?P<name>[A-Za-z_]\w*)\b")
    skip_names = {"if", "for", "while", "switch", "return", "sizeof"}

    for line in lines:
        if class_name is None:
            m_class = class_re.search(line)
            if m_class:
                pending_class_name = m_class.group("name")
                if ";" in line and "{" not in line:
                    pending_class_name = None
            if pending_class_name is None or "{" not in line:
                continue
            class_name = pending_class_name
            pending_class_name = None
            brace_depth = line.count("{") - line.count("}")
            continue

        for m_method in method_re.finditer(line):
            method_name = m_method.group("name")
            if method_name in skip_names:
                continue
            inventory.function_names.add(method_name)
            inventory.qualified_function_names.add(f"{class_name}::{method_name}")
        if brace_depth == 1:
            m_method_start = method_start_re.search(line)
            if m_method_start:
                method_name = m_method_start.group("name")
                if method_name not in skip_names:
                    inventory.function_names.add(method_name)
                    inventory.qualified_function_names.add(f"{class_name}::{method_name}")

        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0:
            class_name = None
            brace_depth = 0


def build_source_inventory() -> SourceInventory:
    inventory = SourceInventory()
    type_re = re.compile(r"\b(?:class|struct|enum)\s+(?:class\s+)?(?P<name>[A-Za-z_]\w*)\b")
    function_re = re.compile(
        r"(?<![A-Za-z_0-9])(?P<qual>(?:[A-Za-z_]\w*::)+)?(?P<name>~?[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:;|\{|\})"
    )
    extern_global_re = re.compile(r"^\s*extern\s+.+?\b(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]+\])*\s*;")
    header_static_global_re = re.compile(
        r"^\s*static\s+[A-Za-z_][\w\s:<>*&]*\s+\b(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]+\])*\s*(?:;|=[^;]*(?:;)?)"
    )
    global_def_re = re.compile(
        r"^[A-Za-z_][\w\s:<>*&]*\s+\b(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]*\])*\s*(?:;|=[^;]*(?:;)?)"
    )
    pointer_array_global_def_re = re.compile(
        r"^[A-Za-z_][\w\s:<>*&]*\s+\(\s*\*\s*(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]+\])*\s*\)(?:\s*\[[^\]]+\])*\s*\([^;]*\)\s*(?:;|=[^;]*(?:;)?)"
    )
    pointer_to_array_global_def_re = re.compile(
        r"^[A-Za-z_][\w\s:<>*&]*\s+\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)(?:\s*\[[^\]]+\])+\s*(?:;|=[^;]*(?:;)?)"
    )
    qualified_global_def_re = re.compile(
        r"^[A-Za-z_][\w\s:<>*&]*\s*[&*]?\s*\b(?:[A-Za-z_]\w*::)+(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]*\])*\s*(?:;|=[^;]*(?:;)?)"
    )
    qualified_global_stmt_re = re.compile(
        r"\b(?:[A-Za-z_][\w:<>*&]*\s+)+[&*]?\s*\b(?:[A-Za-z_]\w*::)+(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]+\])*\s*(?:=[^;]*)?;"
    )
    function_pointer_global_stmt_re = re.compile(
        r"\b(?:static\s+)?[A-Za-z_][\w\s:<>*&]*\s+\(\s*\*\s*(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]+\])*\s*\)\s*\([^;]*\)\s*(?:=[^;]*)?;"
    )
    qualified_function_pointer_global_stmt_re = re.compile(
        r"\b(?:static\s+)?[A-Za-z_][\w\s:<>*&]*\s+\(\s*\*\s*(?P<qualified>(?:[A-Za-z_]\w*::)+(?P<name>[A-Za-z_]\w*))(?:\s*\[[^\]]+\])*\s*\)\s*\([^;]*\)\s*(?:=[^;]*)?;"
    )
    skip_functions = {"if", "for", "while", "switch", "return", "sizeof", "catch"}
    skip_globals = {"typedef", "using", "return", "class", "struct", "enum", "namespace", "template"}

    for path in iter_source_scan_files():
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = strip_source_comments(fh.read())
        except OSError:
            continue

        for m_type in type_re.finditer(text):
            inventory.type_names.add(m_type.group("name"))

        add_class_method_decls(text, inventory)

        is_header = os.path.splitext(path)[1].lower() in HEADER_EXTS or os.path.splitext(path)[1].lower() == ".hh"
        flat_text = re.sub(r"\s+", " ", text)
        for m_function in function_re.finditer(flat_text):
            name = m_function.group("name")
            if name in skip_functions:
                continue
            qual = m_function.group("qual") or ""
            inventory.function_names.add(name)
            if qual:
                inventory.qualified_function_names.add(f"{qual}{name}")

        if not is_header:
            for m_global in qualified_global_stmt_re.finditer(flat_text):
                full_match = re.search(
                    r"\b(?P<qualified>(?:[A-Za-z_]\w*::)+%s)\b" % re.escape(m_global.group("name")),
                    m_global.group(0),
                )
                if full_match:
                    inventory.qualified_global_names.add(full_match.group("qualified"))
            for m_global in qualified_function_pointer_global_stmt_re.finditer(flat_text):
                inventory.qualified_global_names.add(m_global.group("qualified"))
            for m_global in function_pointer_global_stmt_re.finditer(flat_text):
                inventory.global_names.add(m_global.group("name"))

        current_namespace: Optional[str] = None
        namespace_depth = 0
        namespace_re = re.compile(r"^\s*namespace\s+(?P<name>[A-Za-z_]\w*)\s*{")
        unnamed_namespace_re = re.compile(r"^\s*namespace\s*{")
        path_stem = os.path.splitext(os.path.basename(path))[0]
        path_ext = os.path.splitext(path)[1].lstrip(".").lower()
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            namespace_match = namespace_re.match(line)
            if namespace_match:
                current_namespace = namespace_match.group("name")
                namespace_depth = line.count("{") - line.count("}")
                continue
            if unnamed_namespace_re.match(line):
                current_namespace = f"@unnamed@{path_stem}_{path_ext}@"
                namespace_depth = line.count("{") - line.count("}")
                continue

            in_namespace = current_namespace is not None and namespace_depth > 0

            for m_function in function_re.finditer(stripped):
                name = m_function.group("name")
                if name in skip_functions:
                    continue
                qual = m_function.group("qual") or ""
                inventory.function_names.add(name)
                if qual:
                    inventory.qualified_function_names.add(f"{qual}{name}")

            if "(" in stripped and not (
                pointer_array_global_def_re.match(line) or pointer_to_array_global_def_re.match(line)
            ):
                continue
            first = stripped.split(None, 1)[0]
            if first in skip_globals:
                continue
            if is_header:
                m_global = extern_global_re.match(stripped) or header_static_global_re.match(stripped)
            else:
                m_global = qualified_global_def_re.match(line)
            if m_global and not is_header and "::" in line:
                full_match = re.search(
                    r"\b(?P<qualified>(?:[A-Za-z_]\w*::)+%s)\b" % re.escape(m_global.group("name")), line
                )
                if full_match:
                    inventory.qualified_global_names.add(full_match.group("qualified"))
                    continue
            if not m_global and not is_header:
                m_global = global_def_re.match(line)
            if not m_global and not is_header:
                m_global = pointer_array_global_def_re.match(line)
            if not m_global and not is_header:
                m_global = pointer_to_array_global_def_re.match(line)
            if m_global:
                if in_namespace:
                    inventory.qualified_global_names.add(f"{current_namespace}::{m_global.group('name')}")
                else:
                    inventory.global_names.add(m_global.group("name"))

            if in_namespace:
                namespace_depth += line.count("{") - line.count("}")
                if namespace_depth <= 0:
                    current_namespace = None
                    namespace_depth = 0

    return inventory


def source_inventory_has_record(
    inventory: SourceInventory, record: SymbolRecord, ambiguous_global_names: Optional[Set[str]] = None
) -> bool:
    name = record.name.strip()
    unqualified = name.split("::")[-1]
    if record.kind in {"class", "struct"}:
        return name in inventory.type_names or unqualified in inventory.type_names
    if record.kind == "global":
        if "::" in name:
            return name in inventory.qualified_global_names
        if qualified_global_matches_record(inventory, record):
            return True
        if zero_address_qualified_global_matches_record(inventory, record):
            return True
        if singleton_template_global_matches_record(record):
            return True
        if local_static_global_matches_record(record):
            return True
        if unqualified_global_matches_record(inventory, record):
            return True
        if ambiguous_global_names and name in ambiguous_global_names:
            return False
        return name in inventory.global_names or unqualified in inventory.global_names
    if record.kind == "function":
        if "::" in name:
            owner, method = name.rsplit("::", 1)
            owner_name = owner.split("::")[-1]
            if name in inventory.qualified_function_names:
                return True
            if method in {owner_name, f"~{owner_name}"} and method in inventory.function_names:
                return True
            return False
        return name in inventory.function_names
    return False


def load_symbol_addrs() -> Dict[str, Set[int]]:
    global _SYMBOL_ADDRS
    if _SYMBOL_ADDRS is not None:
        return _SYMBOL_ADDRS
    result: Dict[str, Set[int]] = {}
    if not os.path.isfile(SYMBOL_ADDRS_PATH):
        _SYMBOL_ADDRS = result
        return result
    symbol_re = re.compile(r"^\s*(?P<symbol>\S+)\s*=\s*0x(?P<address>[0-9A-Fa-f]+);")
    with open(SYMBOL_ADDRS_PATH, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            match = symbol_re.match(line)
            if not match:
                continue
            result.setdefault(match.group("symbol"), set()).add(int(match.group("address"), 16))
    _SYMBOL_ADDRS = result
    return result


def detail_address(detail: str) -> Optional[int]:
    match = re.search(r"address\s+(0x[0-9A-Fa-f]+)", detail)
    return int(match.group(1), 16) if match else None


def decode_mwcc_owner_suffix(suffix: str) -> Optional[str]:
    if suffix.startswith("Q"):
        match = re.match(r"^Q(?P<count>\d+)(?P<body>.*)$", suffix)
        if not match:
            return None
        count = int(match.group("count"))
        body = match.group("body")
        parts: List[str] = []
        for _ in range(count):
            length_match = re.match(r"^(\d+)", body)
            if not length_match:
                return None
            length = int(length_match.group(1))
            start = len(length_match.group(1))
            end = start + length
            if end > len(body):
                return None
            parts.append(body[start:end])
            body = body[end:]
        return "::".join(parts) if parts and not body else None

    length_match = re.match(r"^(\d+)", suffix)
    if not length_match:
        return None
    length = int(length_match.group(1))
    start = len(length_match.group(1))
    end = start + length
    if end != len(suffix):
        return None
    return suffix[start:end]


def symbol_addr_owner_candidates(record: SymbolRecord) -> List[str]:
    if record.kind != "global":
        return []
    address = detail_address(record.detail)
    if address is None or address == 0:
        return []

    prefix = f"{record.name}__"
    candidates: Set[str] = set()
    for mangled, addresses in load_symbol_addrs().items():
        if address not in addresses or not mangled.startswith(prefix):
            continue
        owner = decode_mwcc_owner_suffix(mangled[len(prefix) :])
        if owner:
            candidates.add(f"{owner}::{record.name}")
    return sorted(candidates)


def function_start_address(detail: str) -> Optional[int]:
    match = re.search(r"\b(0x[0-9A-Fa-f]+)\s*->", detail)
    return int(match.group(1), 16) if match else None


def qualified_global_matches_record(inventory: SourceInventory, record: SymbolRecord) -> bool:
    address = detail_address(record.detail)
    if address is None:
        return False
    symbols = load_symbol_addrs()
    for qualified_name in inventory.qualified_global_names:
        owner, base_name = qualified_name.rsplit("::", 1)
        if base_name != record.name:
            continue
        for mangled in qualified_global_mangled_candidates(base_name, owner):
            addresses = symbols.get(mangled, set())
            if address == 0 and addresses:
                return True
            if address in addresses:
                return True
    return False


def zero_address_qualified_global_matches_record(inventory: SourceInventory, record: SymbolRecord) -> bool:
    if detail_address(record.detail) != 0:
        return False
    for qualified_name in inventory.qualified_global_names:
        if qualified_name.rsplit("::", 1)[-1] == record.name:
            return True
    return False


def singleton_template_global_matches_record(record: SymbolRecord) -> bool:
    if record.name != "m_tpcSingleton":
        return False
    address = detail_address(record.detail)
    if address is None:
        return False
    if address == 0:
        return True
    for mangled, addresses in load_symbol_addrs().items():
        if mangled.startswith("m_tpcSingleton__") and address in addresses:
            return True
    return False


def unqualified_global_matches_record(inventory: SourceInventory, record: SymbolRecord) -> bool:
    if record.name not in inventory.global_names:
        return False
    address = detail_address(record.detail)
    if address is None or address == 0:
        return False
    return address in load_symbol_addrs().get(record.name, set())


def local_static_global_matches_record(record: SymbolRecord) -> bool:
    address = detail_address(record.detail)
    if address is None or address == 0:
        return False
    suffix_re = re.compile(rf"@{re.escape(record.name)}(?:@\d+)?$")
    for mangled, addresses in load_symbol_addrs().items():
        if not mangled.startswith("@LOCAL@") or address not in addresses:
            continue
        if suffix_re.search(mangled):
            return True
    return False


def qualified_global_mangled_candidates(base_name: str, owner: str) -> List[str]:
    owner_parts = owner.split("::")
    if len(owner_parts) == 1:
        return [f"{base_name}__{len(owner)}{owner}"]

    q_owner = f"Q{len(owner_parts)}" + "".join(f"{len(part)}{part}" for part in owner_parts)
    return [f"{base_name}__{q_owner}"]


def weak_container_function_matches_record(record: SymbolRecord) -> bool:
    address = function_start_address(record.detail)
    if address is None:
        return False
    for mangled, addresses in load_symbol_addrs().items():
        if address not in addresses:
            continue
        if "<" not in mangled:
            continue
        if not any(owner in mangled for owner in ("Q23std", "Q25oostd", "Q210Metrowerks")):
            continue
        if mangled.startswith(f"{record.name}__"):
            return True
    return False


NNS_UTIL_CONSTANT_GLOBALS = {
    "tosUnitMatrix",
    "tosUnitScaleVec",
    "tosXVec",
    "tosYVec",
    "tosZVec",
    "tosZeroVec",
    "tosUnitScaleVecFast",
    "tosXVecFast",
    "tosYVecFast",
    "tosZVecFast",
    "tosZeroVecFast",
}

DEFERRED_SDK_PATH_MARKERS = (
    "/usr/local/sega/",
    "/usr/local/sce/",
    "/usr/local/cri/",
)


def nns_util_constant_matches_record(record: SymbolRecord) -> bool:
    if record.kind != "global" or record.name not in NNS_UTIL_CONSTANT_GLOBALS:
        return False
    address = detail_address(record.detail)
    if address is None:
        return False
    if address == 0:
        return True
    return address in load_symbol_addrs().get(f"{record.name}__9nspNnUtil", set())


def is_deferred_sdk_record(record: SymbolRecord) -> bool:
    if not record.unit_paths:
        return False
    return all(
        any(marker in normalize_unit_path(path).lower() for marker in DEFERRED_SDK_PATH_MARKERS)
        for path in record.unit_paths
    )


def checklist_bucket(record: SymbolRecord, max_shared: int) -> Optional[str]:
    path_count = len(record.unit_paths)
    has_header = any(unit_kind(path) == "header" for path in record.unit_paths)

    if path_count == 1:
        return "Unique Unit-Path Missing Symbols"
    if has_header and path_count <= max_shared:
        return "Likely Header-Owned Missing Symbols"
    if record.kind != "function" and 1 < path_count <= max_shared:
        return "Low-Cardinality Shared Missing Data/Types"
    return None


def checklist_bucket_order() -> List[str]:
    return [
        "Unique Unit-Path Missing Symbols",
        "Likely Header-Owned Missing Symbols",
        "Low-Cardinality Shared Missing Data/Types",
    ]


def checklist_bucket_report(bucket: str) -> str:
    return {
        "Unique Unit-Path Missing Symbols": "unique_symbols.md",
        "Likely Header-Owned Missing Symbols": "likely_header_owners.md",
        "Low-Cardinality Shared Missing Data/Types": "shared_symbols.md",
    }[bucket]


def checklist_bucket_note(bucket: str, max_shared: int) -> str:
    if bucket == "Unique Unit-Path Missing Symbols":
        return "Easiest pass: one DWARF unit path, so work can usually be batched by that file and validated once."
    if bucket == "Likely Header-Owned Missing Symbols":
        return f"Next pass: header-owned candidates with 2..{max_shared} unit paths. Confirm ownership before adding declarations."
    return f"Later pass: non-function data/types shared across 2..{max_shared} unit paths. Prefer canonical shared headers over duplicated declarations."


def preferred_group_path(item: ChecklistItem) -> str:
    headers = sorted(path for path in item.unit_paths if unit_kind(path) == "header")
    sources = sorted(path for path in item.unit_paths if unit_kind(path) == "source")
    if len(item.unit_paths) == 1:
        return next(iter(item.unit_paths))
    if headers:
        return headers[0]
    if sources:
        return sources[0]
    return sorted(item.unit_paths)[0]


def grouped_checklist_items(records: Sequence[ChecklistItem]) -> Dict[str, List[ChecklistItem]]:
    grouped: Dict[str, List[ChecklistItem]] = {}
    for record in records:
        grouped.setdefault(preferred_group_path(record), []).append(record)
    return grouped


def checklist_bucket_for_item(item: ChecklistItem, max_shared: int) -> Optional[str]:
    path_count = len(item.unit_paths)
    has_header = any(unit_kind(path) == "header" for path in item.unit_paths)

    if path_count == 1:
        return "Unique Unit-Path Missing Symbols"
    if has_header and path_count <= max_shared:
        return "Likely Header-Owned Missing Symbols"
    if item.kind != "function" and 1 < path_count <= max_shared:
        return "Low-Cardinality Shared Missing Data/Types"
    return None


def repo_validation_path(unit_path: str) -> Optional[str]:
    normalized = normalize_unit_path(unit_path)
    marker = "/Develop/Projects/SR2/pgm/"
    if marker not in normalized:
        return None
    suffix = normalized.split(marker, 1)[1]
    ext = os.path.splitext(suffix)[1].lower()
    root = "include" if ext in HEADER_EXTS else "src"
    rel = os.path.join(root, "Develop", "Projects", "SR2", "pgm", *suffix.split("/"))
    candidates = [rel]
    if root == "include" and ext == ".h":
        candidates.insert(0, os.path.splitext(rel)[0] + ".hpp")
    for candidate in candidates:
        if os.path.exists(os.path.join(ROOT_DIR, candidate)):
            return candidate.replace("\\", "/")
    return candidates[0].replace("\\", "/")


def is_supported_checklist_record(record: SymbolRecord) -> bool:
    name = record.name.strip()
    if is_deferred_sdk_record(record):
        return False
    if record.kind == "global" and name in {"_end", "_stack_size"}:
        return False
    if nns_util_constant_matches_record(record):
        return False
    if record.kind == "global" and record.display.strip().startswith("void ") and "size 0x0" in record.detail:
        return False
    if record.kind in {"class", "struct"} and name == "hkMallocMemory":
        return False
    if record.kind in {"class", "struct"} and "__vtable" in record.display:
        return False
    if record.kind in {"class", "struct"} and name in {"__generic_iterator", "pair"}:
        return False
    if record.kind != "function":
        return True
    owner = name.rsplit("::", 1)[0] if "::" in name else ""
    if owner in {
        "__cdeque_deleter",
        "__cdeque_deleter_common",
        "__deque_deleter",
        "__deque_deleter_common",
        "__list_imp",
        "__vector_deleter",
        "__vector_imp",
        "__vector_pod",
        "generic_iterator",
    }:
        return False
    if "::" not in name and weak_container_function_matches_record(record):
        return False
    # Raw mangled thunks can appear in DWARF function blocks; they are not useful
    # missing-declaration checklist items without demangling/line evidence.
    if "@" in name or ("__" in name and "::" not in name):
        return False
    return bool(re.match(r"^(?:[A-Za-z_]\w*::)*(?:~?[A-Za-z_]\w*)$", name))


def checklist_record_key(record: SymbolRecord) -> str:
    if record.kind in {"class", "struct"}:
        seed = record.name
    else:
        seed = record.display
    return f"{record.kind}:{record.name}:{short_hash(seed)}"


def missing_checklist_records(
    symbol_index: Dict[str, SymbolRecord], inventory: SourceInventory, max_shared: int
) -> Dict[str, List[ChecklistItem]]:
    item_by_key: Dict[str, ChecklistItem] = {}
    global_record_counts: Dict[str, int] = {}
    for record in symbol_index.values():
        if record.kind == "global":
            global_record_counts[record.name] = global_record_counts.get(record.name, 0) + 1
    ambiguous_global_names = {name for name, count in global_record_counts.items() if count > 1}
    for record in symbol_index.values():
        if record.kind not in CHECKLIST_KINDS:
            continue
        if not is_supported_checklist_record(record):
            continue
        if source_inventory_has_record(inventory, record, ambiguous_global_names):
            continue
        bucket = checklist_bucket(record, max_shared)
        if bucket:
            item_key = checklist_record_key(record)
            item = item_by_key.get(item_key)
            if item is None:
                item = ChecklistItem(
                    kind=record.kind,
                    name=record.name,
                    display=record.display,
                    key=item_key,
                )
                item_by_key[item_key] = item
            if record.detail:
                item.details.add(record.detail)
            item.owner_candidates.update(symbol_addr_owner_candidates(record))
            item.total_entries += record.total_entries
            item.units.update(record.units)
            item.unit_paths.update(record.unit_paths)
    bucket_items: Dict[str, List[ChecklistItem]] = {}
    for item in item_by_key.values():
        bucket = checklist_bucket_for_item(item, max_shared)
        if bucket:
            bucket_items.setdefault(bucket, []).append(item)
    return bucket_items


def load_checked_checklist(path: str) -> Set[str]:
    checked: Set[str] = set()
    if not os.path.isfile(path):
        return checked
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                match = RE_CHECKLIST_STATE.match(line.strip())
                if match and match.group("state").lower() == "x":
                    checked.add(match.group("key").strip())
    except OSError:
        pass
    return checked


def build_summary(
    units: Sequence[UnitEntry],
    symbol_index: Dict[str, SymbolRecord],
    max_shared: int,
    missing_checklist_symbols: int,
    missing_checklist_by_bucket: Dict[str, int],
) -> Dict[str, Any]:
    kind_counts: Dict[str, int] = {}
    for record in symbol_index.values():
        kind_counts[record.kind] = kind_counts.get(record.kind, 0) + 1
    unique_count = sum(1 for record in symbol_index.values() if len(record.unit_paths) == 1)
    unique_paths = {unit.normalized_path for unit in units}
    return {
        "unit_blocks": len(units),
        "unique_unit_paths": len(unique_paths),
        "source_unit_paths": sum(1 for path in unique_paths if unit_kind(path) == "source"),
        "header_unit_paths": sum(1 for path in unique_paths if unit_kind(path) == "header"),
        "symbols": len(symbol_index),
        "symbols_by_kind": dict(sorted(kind_counts.items())),
        "unique_symbols": unique_count,
        "low_cardinality_symbols": len(low_cardinality_records(symbol_index, max_shared)),
        "likely_header_owner_symbols": len(likely_header_owner_records(symbol_index, max_shared)),
        "missing_checklist_symbols": missing_checklist_symbols,
        "missing_checklist_by_bucket": dict(sorted(missing_checklist_by_bucket.items())),
        "max_shared": max_shared,
    }


def write_index(
    output_dir: str,
    input_path: str,
    units: Sequence[UnitEntry],
    symbol_index: Dict[str, SymbolRecord],
    max_shared: int,
    missing_checklist_symbols: int,
    missing_checklist_by_bucket: Dict[str, int],
) -> None:
    data = {
        "generated_at": datetime.date.today().isoformat(),
        "input": relpath(input_path),
        "output": relpath(output_dir),
        "reports": {
            "unique_symbols": "unique_symbols.md",
            "shared_symbols": "shared_symbols.md",
            "likely_header_owners": "likely_header_owners.md",
            "missing_checklist": "missing_symbols_checklist.md",
        },
        "summary": build_summary(
            units, symbol_index, max_shared, missing_checklist_symbols, missing_checklist_by_bucket
        ),
        "units": units_for_json(units),
        "symbols": symbol_records_for_json(symbol_index),
    }
    with open(os.path.join(output_dir, "index.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def report_header(title: str, input_path: str) -> List[str]:
    today = datetime.date.today().isoformat()
    return [
        f"# {title}\n\n",
        f"Generated: {today}\n\n",
        f"Input: {md_code(relpath(input_path))}\n\n",
        "This is DWARF unit-path ownership evidence, not an automatic edit list. "
        "Confirm candidates with source, symbols, and objdiff before moving declarations.\n\n",
    ]


def write_unique_report(output_dir: str, input_path: str, units: Sequence[UnitEntry], symbol_index: Dict[str, SymbolRecord]) -> int:
    unique = {record.key: record for record in symbol_index.values() if len(record.unit_paths) == 1}
    by_path: Dict[str, List[SymbolRecord]] = {}
    for record in unique.values():
        path = next(iter(record.unit_paths))
        by_path.setdefault(path, []).append(record)

    lines = report_header("Unique DWARF Symbols by Unit Path", input_path)
    lines.append(f"Symbols appearing in one unique DWARF unit path: {len(unique)}\n\n")
    for path in sorted(by_path):
        records = sorted(by_path[path], key=lambda r: (r.kind, r.name, r.display))
        lines.append(f"## {path}\n\n")
        lines.append(f"Symbols: {len(records)}\n\n")
        lines.append("| Kind | Symbol | DWARF Blocks | Entries | Detail |\n")
        lines.append("|------|--------|-------------:|--------:|--------|\n")
        for record in records:
            detail = record.detail or ""
            lines.append(
                f"| {record.kind} | {md_code(record.display)} | {len(record.units)} | "
                f"{record.total_entries} | {md_code(detail) if detail else ''} |\n"
            )
        lines.append("\n")

    with open(os.path.join(output_dir, "unique_symbols.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)
    return len(unique)


def write_shared_report(output_dir: str, input_path: str, symbol_index: Dict[str, SymbolRecord], max_shared: int) -> int:
    records = low_cardinality_records(symbol_index, max_shared)
    by_unit_set: Dict[Tuple[str, ...], List[SymbolRecord]] = {}
    for record in records:
        by_unit_set.setdefault(tuple(sorted(record.unit_paths)), []).append(record)

    lines = report_header("Low-Cardinality Shared DWARF Symbols", input_path)
    lines.append(f"Symbols appearing in 2..{max_shared} unique DWARF unit paths: {len(records)}\n\n")
    lines.append(
        "Path sets list unique DWARF source paths; block and entry counts can be higher when the dump repeats a path.\n\n"
    )
    for unit_paths, grouped in sorted(by_unit_set.items(), key=lambda item: (len(item[0]), item[0])):
        lines.append("## Unit Set\n\n")
        for path in unit_paths:
            lines.append(f"- {md_code(path)}\n")
        lines.append("\n")
        lines.append("| Kind | Symbol | Path Count | DWARF Blocks | Entries | Detail |\n")
        lines.append("|------|--------|-----------:|-------------:|--------:|--------|\n")
        for record in sorted(grouped, key=lambda r: (r.kind, r.name, r.display)):
            detail = record.detail or ""
            lines.append(
                f"| {record.kind} | {md_code(record.display)} | {len(record.unit_paths)} | "
                f"{len(record.units)} | {record.total_entries} | {md_code(detail) if detail else ''} |\n"
            )
        lines.append("\n")

    with open(os.path.join(output_dir, "shared_symbols.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)
    return len(records)


def write_likely_header_report(output_dir: str, input_path: str, symbol_index: Dict[str, SymbolRecord], max_shared: int) -> int:
    records = likely_header_owner_records(symbol_index, max_shared)
    lines = report_header("Likely Header Owner Candidates", input_path)
    lines.append(
        f"Symbols with at least one header unit path and no more than {max_shared} total unique DWARF unit paths: {len(records)}\n\n"
    )
    lines.append("| Kind | Symbol | Header Path(s) | Other Path(s) | DWARF Blocks | Entries | Reason |\n")
    lines.append("|------|--------|----------------|---------------|-------------:|--------:|--------|\n")
    for record in sorted(records, key=lambda r: (sorted(r.unit_paths), r.kind, r.name, r.display)):
        headers = sorted(path for path in record.unit_paths if unit_kind(path) == "header")
        others = sorted(path for path in record.unit_paths if unit_kind(path) != "header")
        reason = "unique header path" if len(headers) == 1 else "multiple header paths"
        if len(record.unit_paths) == 1:
            reason += ", unique symbol"
        lines.append(
            "| "
            f"{record.kind} | {md_code(record.display)} | "
            f"{'<br>'.join(md_code(path) for path in headers)} | "
            f"{'<br>'.join(md_code(path) for path in others)} | "
            f"{len(record.units)} | {record.total_entries} | {reason} |\n"
        )

    with open(os.path.join(output_dir, "likely_header_owners.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)
    return len(records)


def write_missing_checklist_report(
    output_dir: str,
    input_path: str,
    symbol_index: Dict[str, SymbolRecord],
    max_shared: int,
    checked_keys: Set[str],
) -> Tuple[int, Dict[str, int]]:
    inventory = build_source_inventory()
    buckets = missing_checklist_records(symbol_index, inventory, max_shared)
    bucket_counts = {bucket: len(records) for bucket, records in buckets.items()}
    total = sum(len(records) for records in buckets.values())

    lines = report_header("Missing DWARF Symbol Checklist", input_path)
    lines.append(
        "This checklist filters out classes/structs, globals, and functions that already appear in current "
        "`include/` or `src/` declarations/definitions. Checked items are preserved across regeneration by "
        "stable DWARF symbol keys embedded in each row.\n\n"
    )
    lines.append(
        "Work order is optimized for agents: unique unit-path evidence first, then likely header owners, "
        "then shared data/types. Each section is grouped by DWARF file path so one file can be filled and "
        "validated before moving to the next.\n\n"
    )
    lines.append(f"Missing checklist candidates: {total}\n\n")
    lines.append("| Kind | Count |\n")
    lines.append("|------|------:|\n")
    for kind in sorted(CHECKLIST_KINDS):
        count = sum(1 for records in buckets.values() for record in records if record.kind == kind)
        lines.append(f"| {kind} | {count} |\n")
    lines.append("\n")
    lines.append("| Bucket | Count |\n")
    lines.append("|--------|------:|\n")
    for bucket in checklist_bucket_order():
        lines.append(f"| {bucket} | {bucket_counts.get(bucket, 0)} |\n")
    lines.append("\n")

    if not total:
        lines.append("No missing DWARF symbol candidates found after current-source filtering.\n")
    for bucket in checklist_bucket_order():
        records = buckets.get(bucket, [])
        if not records:
            continue
        lines.append(f"## {bucket}\n\n")
        lines.append(f"Source report: {md_code(os.path.join('symbols/DwarfByUnit', checklist_bucket_report(bucket)).replace(os.sep, '/'))}\n\n")
        lines.append(f"{checklist_bucket_note(bucket, max_shared)}\n\n")
        grouped = grouped_checklist_items(records)
        for group_path, grouped_records in sorted(grouped.items()):
            lines.append(f"### {group_path}\n\n")
            validation_path = repo_validation_path(group_path)
            if validation_path:
                lines.append(f"Suggested validation: `python tools/decomp-workflow.py validate {validation_path}`\n\n")
            for record in sorted(grouped_records, key=lambda r: (r.kind, r.name, r.display)):
                state = "x" if record.key in checked_keys else " "
                paths = ", ".join(md_code(path) for path in sorted(record.unit_paths))
                detail_parts = [
                    f"paths: {len(record.unit_paths)}",
                    f"blocks: {len(record.units)}",
                    f"entries: {record.total_entries}",
                ]
                details = sorted(record.details)
                if len(details) == 1:
                    detail_parts.append(f"detail: {md_code(details[0])}")
                elif len(details) > 1:
                    detail_parts.append(f"details: {len(details)} ranges, first {md_code(details[0])}")
                if record.owner_candidates:
                    owners = ", ".join(md_code(owner) for owner in sorted(record.owner_candidates))
                    detail_parts.append(f"owner candidate: {owners}")
                detail = "; ".join(detail_parts)
                lines.append(
                    f"- [{state}] {md_code(record.kind)} {md_code(record.display)} - {paths}; {detail} "
                    f"<!-- dwarf-check:{record.key} -->\n"
                )
            lines.append("\n")

    with open(os.path.join(output_dir, "missing_symbols_checklist.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)
    return total, bucket_counts


def prepare_output(output_dir: str, no_unit_files: bool) -> str:
    os.makedirs(output_dir, exist_ok=True)
    units_dir = os.path.join(output_dir, "units")
    if os.path.isdir(units_dir):
        shutil.rmtree(units_dir)
    if not no_unit_files:
        os.makedirs(units_dir, exist_ok=True)
    for name in (
        "index.json",
        "unique_symbols.md",
        "shared_symbols.md",
        "likely_header_owners.md",
        "missing_symbols_checklist.md",
    ):
        path = os.path.join(output_dir, name)
        if os.path.exists(path):
            os.remove(path)
    return units_dir


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help="Input DWARF dump path (default: symbols/sr2_dwarfdump.nothpp)",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="Output directory (default: symbols/DwarfByUnit)",
    )
    parser.add_argument(
        "--no-unit-files",
        action="store_true",
        help="Write only index.json and markdown reports, not raw per-CU .nothpp files",
    )
    parser.add_argument(
        "--no-stripped",
        action="store_true",
        help="Exclude functions with a start or end address of 0xFFFFFFFF",
    )
    parser.add_argument(
        "--max-shared",
        type=int,
        default=4,
        help="Maximum unique unit-path count for low-cardinality/header-owner reports (default: 4)",
    )
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    output_dir = os.path.abspath(args.output)
    if not os.path.isfile(input_path):
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    if args.max_shared < 2:
        print("Error: --max-shared must be at least 2", file=sys.stderr)
        sys.exit(1)

    checked_keys = load_checked_checklist(os.path.join(output_dir, "missing_symbols_checklist.md"))
    units_dir = prepare_output(output_dir, args.no_unit_files)
    print(f"Reading {relpath(input_path)}", file=sys.stderr)
    units, symbol_index = iter_compile_units(input_path, args, units_dir)
    unique_count = write_unique_report(output_dir, input_path, units, symbol_index)
    shared_count = write_shared_report(output_dir, input_path, symbol_index, args.max_shared)
    header_count = write_likely_header_report(output_dir, input_path, symbol_index, args.max_shared)
    checklist_count, checklist_bucket_counts = write_missing_checklist_report(
        output_dir, input_path, symbol_index, args.max_shared, checked_keys
    )
    write_index(output_dir, input_path, units, symbol_index, args.max_shared, checklist_count, checklist_bucket_counts)

    unique_paths = {unit.normalized_path for unit in units}
    print(f"DWARF unit blocks: {len(units)}", file=sys.stderr)
    print(f"Unique unit paths: {len(unique_paths)}", file=sys.stderr)
    print(f"Symbols: {len(symbol_index)}", file=sys.stderr)
    print(f"Unique symbols: {unique_count}", file=sys.stderr)
    print(f"Low-cardinality shared symbols: {shared_count}", file=sys.stderr)
    print(f"Likely header owner symbols: {header_count}", file=sys.stderr)
    print(f"Missing checklist symbols: {checklist_count}", file=sys.stderr)
    for bucket in checklist_bucket_order():
        print(f"Missing {bucket}: {checklist_bucket_counts.get(bucket, 0)}", file=sys.stderr)
    print(f"Wrote {relpath(output_dir)}", file=sys.stderr)


if __name__ == "__main__":
    main()
