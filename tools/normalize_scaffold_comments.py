#!/usr/bin/env python3
"""Normalize scaffold member comments with DWARF-backed offset and size data.

This updates active class/struct member declarations that already have a partial
layout comment, converting `// 0xNN`, `// offset 0xNN`, or `// size 0xNN` into
`// offset 0xNN, size 0xNN` when the containing type and member name match DWARF
exactly. Conflicting existing values are left untouched.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Set, Tuple


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SCAFFOLD_AUDIT_PATH = os.path.join(SCRIPT_DIR, "scaffold-audit.py")
spec = importlib.util.spec_from_file_location("scaffold_audit", SCAFFOLD_AUDIT_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"failed to load {SCAFFOLD_AUDIT_PATH}")
scaffold_audit = importlib.util.module_from_spec(spec)
sys.modules["scaffold_audit"] = scaffold_audit
spec.loader.exec_module(scaffold_audit)


ROOT_DIR = scaffold_audit.ROOT_DIR
HEADER_EXTS = {".h", ".hpp", ".hh"}

CLASS_RE = re.compile(r"\b(class|struct)\s+([A-Za-z_]\w*)\b")
MEMBER_LINE_RE = re.compile(
    r"^(?P<prefix>\s*(?P<type>.+?)\s+(?P<ptr>[*&]+\s*)?"
    r"(?P<name>[A-Za-z_]\w*(?:\[[^\]]+\])*)\s*;)"
    r"(?P<space>\s*)//(?P<comment>.*?)(?P<newline>\r?\n?)$"
)
OFFSET_RE = re.compile(r"(?:\boffset\s+)?0x([0-9A-Fa-f]+)")
SIZE_RE = re.compile(r"\bsize\s+0x([0-9A-Fa-f]+)")


def iter_headers(paths: List[str]) -> Iterable[str]:
    if paths:
        for path in paths:
            abs_path = path if os.path.isabs(path) else os.path.join(ROOT_DIR, path)
            if os.path.isdir(abs_path):
                for root, _dirs, files in os.walk(abs_path):
                    for fname in files:
                        if os.path.splitext(fname)[1] in HEADER_EXTS:
                            yield os.path.join(root, fname)
            else:
                yield abs_path
        return

    include_root = os.path.join(ROOT_DIR, "include")
    for root, _dirs, files in os.walk(include_root):
        for fname in files:
            if os.path.splitext(fname)[1] in HEADER_EXTS:
                yield os.path.join(root, fname)


def strip_line_comment(line: str) -> str:
    return line.split("//", 1)[0]


def member_name_from_line(line: str) -> Optional[str]:
    match = MEMBER_LINE_RE.match(line)
    if not match:
        return None
    return match.group("name").split("[", 1)[0]


def normalized_line(line: str, dwarf_member: scaffold_audit.MemberInfo) -> Optional[str]:
    match = MEMBER_LINE_RE.match(line)
    if not match:
        return None
    if match.group("prefix").lstrip().startswith("static "):
        return None

    comment = match.group("comment")
    offset_match = OFFSET_RE.search(comment)
    size_match = SIZE_RE.search(comment)
    if not offset_match and not size_match:
        return None

    if offset_match and int(offset_match.group(1), 16) != dwarf_member.offset:
        return None
    if size_match and int(size_match.group(1), 16) != dwarf_member.size:
        return None

    expected_comment = f"offset 0x{dwarf_member.offset:X}, size 0x{dwarf_member.size:X}"
    if comment.strip() == expected_comment:
        return None

    return (
        f"{match.group('prefix')}{match.group('space')}"
        f"// offset 0x{dwarf_member.offset:X}, size 0x{dwarf_member.size:X}"
        f"{match.group('newline')}"
    )


def normalize_file(path: str, dwarf_by_name: Dict[str, scaffold_audit.DwarfStruct], write: bool) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            lines = fh.readlines()
    except OSError:
        return 0

    out = list(lines)
    changes = 0
    depth = 0
    pending_template = False
    class_stack: List[Tuple[str, int, Dict[str, scaffold_audit.MemberInfo]]] = []
    for i, line in enumerate(lines):
        while class_stack and depth <= class_stack[-1][1]:
            class_stack.pop()

        stripped = line.strip()
        active_prefix = strip_line_comment(line)
        class_match = CLASS_RE.search(active_prefix)
        class_starts = bool(class_match and "{" in active_prefix)
        forward_decl = bool(
            class_match
            and ";" in active_prefix
            and ("{" not in active_prefix or active_prefix.find(";") < active_prefix.find("{"))
        )

        if class_stack and not class_starts:
            member_name = member_name_from_line(line)
            dwarf_members = class_stack[-1][2]
            if member_name and member_name in dwarf_members:
                replacement = normalized_line(line, dwarf_members[member_name])
                if replacement and replacement != line:
                    out[i] = replacement
                    changes += 1

        if stripped.startswith("template"):
            pending_template = True
        elif class_match and not forward_decl:
            if class_starts:
                name = class_match.group(2)
                dwarf = dwarf_by_name.get(name)
                dwarf_members = {member.name: member for member in dwarf.members} if dwarf and not pending_template else {}
                class_stack.append((name, depth, dwarf_members))
            pending_template = False
        elif stripped and not stripped.startswith("//"):
            pending_template = False

        no_comment = strip_line_comment(line)
        depth += no_comment.count("{") - no_comment.count("}")

    if changes and write:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.writelines(out)
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Headers or directories to normalize; defaults to include/")
    parser.add_argument("--check", action="store_true", help="Report files that would change without writing")
    args = parser.parse_args()

    dwarf_by_name = scaffold_audit.parse_dwarf_structs(scaffold_audit.DWARF_GLOBALS_PATH)
    total_changes = 0
    changed_files: List[Tuple[str, int]] = []
    seen: Set[str] = set()
    for path in iter_headers(args.paths):
        norm = os.path.normpath(path)
        if norm in seen:
            continue
        seen.add(norm)
        changes = normalize_file(norm, dwarf_by_name, write=not args.check)
        if changes:
            total_changes += changes
            changed_files.append((scaffold_audit.relpath(norm), changes))

    for rel, changes in changed_files:
        print(f"{rel}: {changes}")
    verb = "would normalize" if args.check else "normalized"
    print(f"{verb} {total_changes} member comment(s) in {len(changed_files)} file(s)")
    return 1 if args.check and changed_files else 0


if __name__ == "__main__":
    sys.exit(main())
