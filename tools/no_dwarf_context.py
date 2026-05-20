#!/usr/bin/env python3
"""Gather scaffold context for symbols that have no DWARF struct.

Primary data sources:
- config/SLUS-21642-PROTO-070901/symbol_addrs.txt
- symbols/sr2_line_info.nothpp

This is intentionally read-only. It does not infer layouts; it only groups
symbols by MWCC owner suffix and reports nearby line-info ownership.
"""

from __future__ import annotations

import argparse
import bisect
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYMBOL_ADDRS = os.path.join(
    ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "symbol_addrs.txt"
)
LINE_INFO = os.path.join(ROOT_DIR, "symbols", "sr2_line_info.nothpp")
NO_DWARF_DOC = os.path.join(ROOT_DIR, "docs", "no-dwarf-scaffold-candidates.md")


@dataclass
class SymbolEntry:
    name: str
    addr: int
    size: int
    raw: str


@dataclass
class LineEntry:
    addr: int
    path: str
    lineno: int


@dataclass
class Reference:
    owner: str
    line: str


SYMBOL_RE = re.compile(
    r"^\s*(?P<name>\S+)\s*=\s*(?:\.\w+:)?0x(?P<addr>[0-9A-Fa-f]+);\s*//\s*size:(?P<size>\d+)"
)
SRC_RE = re.compile(r"^(\S[^\r\n]*):(\d+)\s*$")
INSN_RE = re.compile(r"^\s+([0-9A-Fa-f]{5,})\s*:\t")
FUNC_HEADER_RE = re.compile(r"^([0-9A-Fa-f]{5,})\s+<([^>]+)>:")


def owner_token(name: str) -> str:
    return f"__{len(name)}{name}"


def load_symbols(path: str = SYMBOL_ADDRS) -> List[SymbolEntry]:
    entries: List[SymbolEntry] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.lstrip().startswith("//"):
                continue
            m = SYMBOL_RE.match(line)
            if not m:
                continue
            entries.append(
                SymbolEntry(
                    name=m.group("name"),
                    addr=int(m.group("addr"), 16),
                    size=int(m.group("size")),
                    raw=line,
                )
            )
    return entries


def load_line_entries(path: str = LINE_INFO) -> List[LineEntry]:
    entries: List[LineEntry] = []
    pending: List[Tuple[str, int]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            m = SRC_RE.match(line)
            if m:
                pending.append((m.group(1), int(m.group(2))))
                continue
            m = INSN_RE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            for src_path, lineno in pending:
                entries.append(LineEntry(addr=addr, path=src_path, lineno=lineno))
            pending = []
    return entries


def closest_line(entries: Sequence[LineEntry], addr: int) -> Tuple[Optional[LineEntry], int]:
    if not entries:
        return None, 0
    addrs = [e.addr for e in entries]
    pos = bisect.bisect_left(addrs, addr)
    candidates = []
    if pos < len(entries):
        candidates.append(pos)
    if pos > 0:
        candidates.append(pos - 1)
    best = min(candidates, key=lambda i: abs(entries[i].addr - addr))
    return entries[best], abs(entries[best].addr - addr)


def matching_symbols(symbols: Sequence[SymbolEntry], name: str) -> List[SymbolEntry]:
    token = owner_token(name)
    vt_token = f"__vt{token}"
    matches = []
    for sym in symbols:
        if sym.name == name or token in sym.name or sym.name == vt_token:
            matches.append(sym)
    return sorted(matches, key=lambda s: (s.addr, s.name))


def classify_symbol(sym: SymbolEntry, name: str) -> str:
    token = owner_token(name)
    if sym.name.startswith("__vt"):
        return "vtable"
    if sym.name == name:
        return "object/global"
    pos = sym.name.find(token)
    if pos < 0:
        return "symbol"
    tail = sym.name[pos + len(token) :]
    if tail.startswith("F") or sym.name.startswith(("__ct", "__dt")):
        return "function"
    return "object/global"


def format_source(entry: Optional[LineEntry], diff: int) -> str:
    if entry is None:
        return ""
    suffix = "" if diff == 0 else f" (closest +0x{diff:X})"
    return f"{entry.path}:{entry.lineno}{suffix}"


def tu_summary(symbols: Sequence[SymbolEntry], line_entries: Sequence[LineEntry]) -> List[str]:
    counts: Counter[str] = Counter()
    for sym in symbols:
        entry, diff = closest_line(line_entries, sym.addr)
        if entry is not None and diff <= 4:
            counts[entry.path] += 1
    return [path for path, _ in counts.most_common()]


def scan_references(
    name: str, symbols: Sequence[SymbolEntry], path: str = LINE_INFO, limit: int = 20
) -> List[Reference]:
    symbol_names = {sym.name for sym in symbols}
    needles = set(symbol_names)
    needles.add(name)
    refs: List[Reference] = []
    current_func = "<unknown>"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            m = FUNC_HEADER_RE.match(line)
            if m:
                current_func = f"0x{int(m.group(1), 16):08X} {m.group(2)}"
            if not any(needle and needle in line for needle in needles):
                continue
            if FUNC_HEADER_RE.match(line):
                continue
            refs.append(Reference(owner=current_func, line=line.strip()))
            if len(refs) >= limit:
                break
    return refs


def load_doc_candidates(path: str = NO_DWARF_DOC) -> List[str]:
    if not os.path.exists(path):
        return []
    out: List[str] = []
    row_re = re.compile(r"\|\s*\[[ xX~]\]\s*\|.*?`([^`]+)`")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = row_re.search(line)
            if m:
                out.append(m.group(1))
    return out


def is_builtin_dep(name: str) -> bool:
    if not name:
        return True
    return name in {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "bool",
        "c8",
        "s8",
        "u8",
        "s16",
        "u16",
        "s32",
        "u32",
        "s64",
        "u64",
        "f32",
        "f64",
    } or name.startswith(("NNS_", "NN_", "PF_", "__"))


def load_known_classes(include_dir: str) -> Set[str]:
    known: Set[str] = set()
    cls_pat = re.compile(r"(?:class|struct|namespace)\s+(\w+)")
    for dirpath, _dirs, files in os.walk(include_dir):
        for fname in files:
            if not fname.endswith((".hpp", ".h")):
                continue
            try:
                with open(os.path.join(dirpath, fname), encoding="utf-8", errors="replace") as fh:
                    pending: Optional[str] = None
                    for line in fh:
                        stripped = line.strip()
                        if stripped.startswith(("//", "*")):
                            continue
                        if "{" in line:
                            found = False
                            for m in cls_pat.finditer(line):
                                if ";" not in line[: line.find("{")]:
                                    known.add(m.group(1))
                                    found = True
                            if not found and pending:
                                known.add(pending)
                            pending = None
                        else:
                            m = cls_pat.search(line)
                            if m:
                                pending = None if stripped.endswith(";") else m.group(1)
                            elif stripped and not stripped.startswith(("//", "*", ":")):
                                if not line[0:1].isspace():
                                    pending = None
            except OSError:
                pass
    return known


def build_class_stats(symbols: Sequence[SymbolEntry]) -> Dict[str, Dict[str, int]]:
    sym_pat = re.compile(r"__(\d+)(\w+)F")
    weak_pat = re.compile(r"visibility:weak|allow_duplicated:true")
    vtable_pat = re.compile(r"__vt__")
    thunk_pat = re.compile(r"^@")
    stats: Dict[str, Dict[str, int]] = {}
    for sym in symbols:
        if vtable_pat.search(sym.name) or thunk_pat.match(sym.name):
            continue
        if weak_pat.search(sym.raw):
            continue
        m = sym_pat.search(sym.name)
        if not m:
            continue
        length = int(m.group(1))
        class_name = m.group(2)[:length]
        if len(class_name) != length:
            continue
        if "<" in class_name or "Q2" in sym.name[: sym.name.find("__")]:
            continue
        stats.setdefault(class_name, {"func_count": 0, "total_bytes": 0})
        stats[class_name]["func_count"] += 1
        stats[class_name]["total_bytes"] += sym.size
    return stats


def has_dwarf_struct(name: str) -> bool:
    dwarf_dir = os.path.join(ROOT_DIR, "symbols", "Dwarf")
    probe = subprocess.run(
        ["python", os.path.join("tools", "lookup.py"), dwarf_dir, "struct", name],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    return probe.returncode == 0 and bool(probe.stdout.strip())


def encoded_type_names(text: str) -> List[Tuple[str, int, int]]:
    out: List[Tuple[str, int, int]] = []
    idx = 0
    allowed_simple_prefixes = set("PCRF<,")

    def parse_length_name(pos: int) -> Optional[Tuple[str, int, int]]:
        start = pos
        while pos < len(text) and text[pos].isdigit():
            pos += 1
        if start == pos:
            return None
        try:
            length = int(text[start:pos])
        except ValueError:
            return None
        name = text[pos : pos + length]
        if len(name) == length and re.match(r"^[A-Za-z_]\w*$", name):
            return name, start, pos + length
        return None

    while idx < len(text):
        if text.startswith("Q", idx) and idx + 1 < len(text) and text[idx + 1].isdigit():
            count = int(text[idx + 1])
            pos = idx + 2
            parsed: List[Tuple[str, int, int]] = []
            ok = True
            for _ in range(count):
                item = parse_length_name(pos)
                if item is None:
                    ok = False
                    break
                parsed.append(item)
                pos = item[2]
            if ok and parsed:
                out.extend(parsed)
                idx = pos
                continue
        if not text[idx].isdigit():
            idx += 1
            continue
        prev = text[idx - 1] if idx > 0 else ""
        if prev and (prev.isalnum() or prev == "_") and prev not in allowed_simple_prefixes:
            idx += 1
            continue
        start = idx
        item = parse_length_name(idx)
        if item is not None:
            out.append(item)
            idx = item[2]
        else:
            idx = start + 1
    return out


def qualified_type_groups(text: str) -> List[List[str]]:
    groups: List[List[str]] = []
    idx = 0

    def parse_length_name(pos: int) -> Optional[Tuple[str, int]]:
        start = pos
        while pos < len(text) and text[pos].isdigit():
            pos += 1
        if start == pos:
            return None
        try:
            length = int(text[start:pos])
        except ValueError:
            return None
        name = text[pos : pos + length]
        if len(name) == length and re.match(r"^[A-Za-z_]\w*$", name):
            return name, pos + length
        return None

    while idx < len(text):
        if text.startswith("Q", idx) and idx + 1 < len(text) and text[idx + 1].isdigit():
            count = int(text[idx + 1])
            pos = idx + 2
            group: List[str] = []
            ok = True
            for _ in range(count):
                parsed = parse_length_name(pos)
                if parsed is None:
                    ok = False
                    break
                name, pos = parsed
                group.append(name)
            if ok and len(group) >= 2:
                groups.append(group)
                idx = pos
                continue
        idx += 1
    return groups


def nested_dep_token(owner: str, inner: str) -> str:
    return f"{owner}::{inner}"


def dep_context_command(dep: str) -> str:
    owner = dep.split("::", 1)[0]
    return f"python tools/no_dwarf_context.py {owner}"


def extract_no_dwarf_deps(
    owner: str,
    symbols: Sequence[SymbolEntry],
    known_classes: Set[str],
) -> Set[str]:
    deps: Set[str] = set()
    related = [sym for sym in symbols if owner in sym.raw]
    for sym in related:
        qualified_skip: Set[str] = set()
        for group in qualified_type_groups(sym.name):
            outer, inner = group[-2], group[-1]
            if outer == owner or outer in known_classes:
                qualified_skip.add(inner)
            if outer == owner or inner == owner or is_builtin_dep(inner):
                continue
            if outer in known_classes and inner not in known_classes:
                deps.add(nested_dep_token(outer, inner))
        names = encoded_type_names(sym.name)
        for name, _start, _end in names:
            if is_builtin_dep(name) or name == owner:
                continue
            if name in qualified_skip:
                continue
            # Nested helper types owned by this same symbol are part of the owner scaffold,
            # not separate dependency rows.
            if f"Q2{len(owner)}{owner}{len(name)}{name}" in sym.name:
                continue
            if name not in known_classes:
                deps.add(name)
    return deps


def generate_no_dwarf_queue(output_path: str = NO_DWARF_DOC) -> None:
    import datetime

    symbols = load_symbols()
    known_classes = load_known_classes(os.path.join(ROOT_DIR, "include"))
    class_stats = build_class_stats(symbols)

    root_names = [
        name
        for name, stats in class_stats.items()
        if stats["func_count"] > 0 and name not in known_classes and not has_dwarf_struct(name)
    ]
    root_names.sort(key=lambda n: (-class_stats[n]["total_bytes"], -class_stats[n]["func_count"], n.lower()))
    root_set = set(root_names)

    rows: Dict[str, Dict[str, object]] = {}

    def add_row(name: str, funcs: int = 0, bytes_: int = 0, reason: str = "no DWARF") -> None:
        rows.setdefault(
            name,
            {
                "funcs": funcs,
                "bytes": bytes_,
                "reason": reason,
                "deps": set(),
            },
        )

    for name in root_names:
        stats = class_stats[name]
        add_row(name, stats["func_count"], stats["total_bytes"], "no DWARF")
        deps = extract_no_dwarf_deps(name, symbols, known_classes)
        filtered_deps = set()
        for dep in deps:
            dep_base = dep.split("::", 1)[0]
            if dep == name or dep_base == name or is_builtin_dep(dep_base):
                continue
            if dep_base in known_classes and "::" not in dep:
                continue
            filtered_deps.add(dep)
            if dep not in rows:
                if dep in root_set:
                    dep_stats = class_stats[dep]
                    add_row(dep, dep_stats["func_count"], dep_stats["total_bytes"], "no DWARF")
                else:
                    add_row(dep, 0, 0, "dependency shell")
        rows[name]["deps"] = filtered_deps

    def priority_key(name: str) -> Tuple[int, int, str]:
        row = rows[name]
        return (-int(row["bytes"]), -int(row["funcs"]), name.lower())

    ordered: List[str] = []
    visiting: Set[str] = set()
    visited: Set[str] = set()

    def visit(name: str) -> None:
        if name in visited or name in visiting:
            return
        visiting.add(name)
        for dep in sorted(rows[name]["deps"], key=priority_key):  # type: ignore[index]
            if dep in rows:
                visit(dep)
        visiting.remove(name)
        visited.add(name)
        ordered.append(name)

    for name in sorted(rows, key=priority_key):
        visit(name)

    lines: List[str] = []
    lines.append("# No-DWARF Scaffold Queue\n\n")
    lines.append(f"Generated: {datetime.date.today().isoformat()}  |  Queued: {len(ordered)}\n\n")
    lines.append(
        "These candidates remain after normal scaffold queue regeneration. They are excluded from "
        "`docs/scaffold-queue.md` because no DWARF struct layout exists, so scaffold them manually "
        "from `symbol_addrs.txt`, ASM, line ownership, and `tools/no_dwarf_context.py`.\n\n"
    )
    lines.append("Workflow:\n")
    lines.append("1. Find the first `[ ]` row where `Deps = 0`.\n")
    lines.append("2. Run its `Context Command`.\n")
    lines.append("3. Use the reported symbols, TU candidates, line references, ASM, and call sites to scaffold only what is provable.\n")
    lines.append("4. Mark the row `[x]`, unblock dependents whose listed deps are all `[x]`, update `docs/progress.md`, and validate the touched object.\n\n")
    lines.append("Bulk context command: `python tools/no_dwarf_context.py --all`\n\n")
    lines.append("| Status meaning | |\n")
    lines.append("|---|---|\n")
    lines.append("| `[ ]` | Ready — scaffold this now (Deps = 0) |\n")
    lines.append("| `[~]` | Blocked — scaffold the listed Blocking Deps first |\n")
    lines.append("| `[x]` | Done |\n")
    lines.append("| `Funcs = 0` | Dep-only shell — add only declarations/stubs provable from use sites |\n\n")
    lines.append("| Status | Symbol | Funcs | Bytes | Deps | Blocking Deps | Reason | Context Command |\n")
    lines.append("|:------:|--------|------:|------:|:----:|---------------|--------|-----------------|\n")
    for name in ordered:
        row = rows[name]
        deps = sorted(row["deps"])  # type: ignore[arg-type]
        status = "[ ]" if not deps else "[~]"
        dep_list = ", ".join(deps)
        lines.append(
            f"| {status} | `{name}` | {row['funcs']} | {row['bytes']} | {len(deps)} | {dep_list} | {row['reason']} | `{dep_context_command(name)}` |\n"
        )

    with open(output_path, "w", encoding="utf-8") as out:
        out.writelines(lines)
    print(f"Wrote {len(ordered)} no-DWARF rows to {output_path}")


def emit_context(name: str, all_symbols: Sequence[SymbolEntry], line_entries: Sequence[LineEntry]) -> None:
    symbols = matching_symbols(all_symbols, name)
    print(f"# No-DWARF Context: {name}")
    print()
    print(f"Owner token: `{owner_token(name)}`")
    print()
    if not symbols:
        print("No matching `symbol_addrs.txt` entries found.")
        print()
        return

    print("## Symbols")
    print()
    print("| Kind | Symbol | Address | Size | Source |")
    print("|------|--------|---------|-----:|--------|")
    for sym in symbols:
        entry, diff = closest_line(line_entries, sym.addr)
        source = format_source(entry, diff) if diff <= 4 else ""
        print(
            f"| {classify_symbol(sym, name)} | `{sym.name}` | 0x{sym.addr:08X} | {sym.size} | {source} |"
        )
    print()

    paths = tu_summary(symbols, line_entries)
    print("## TU Candidates")
    print()
    if paths:
        for path in paths:
            print(f"- `{path}`")
    else:
        print("- No close line-info source path found.")
    print()

    refs = scan_references(name, symbols)
    print("## Line-Info References")
    print()
    if refs:
        print("| Enclosing Function | Line |")
        print("|--------------------|------|")
        for ref in refs:
            print(f"| `{ref.owner}` | `{ref.line}` |")
    else:
        print("No textual references found in line info.")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gather no-DWARF scaffold context from symbol_addrs and sr2 line info."
    )
    parser.add_argument("symbols", nargs="*", help="Class/namespace symbols to inspect")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Inspect symbols listed in docs/no-dwarf-scaffold-candidates.md",
    )
    parser.add_argument(
        "--generate-queue",
        action="store_true",
        help="Regenerate docs/no-dwarf-scaffold-candidates.md with dependency ordering",
    )
    parser.add_argument(
        "--output",
        default=NO_DWARF_DOC,
        help="Output path for --generate-queue",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.generate_queue:
        generate_no_dwarf_queue(args.output)
        return
    names: List[str] = list(args.symbols)
    if args.all:
        names.extend(load_doc_candidates())
    seen = set()
    names = [name for name in names if not (name in seen or seen.add(name))]
    if not names:
        raise SystemExit("Usage: python tools/no_dwarf_context.py <symbol> [<symbol> ...] [--all]")

    symbols = load_symbols()
    line_entries = load_line_entries()
    for idx, name in enumerate(names):
        if idx:
            print("\n---\n")
        emit_context(name, symbols, line_entries)


if __name__ == "__main__":
    main()
