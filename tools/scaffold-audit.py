#!/usr/bin/env python3
"""Report classes whose current declarations look under-scaffolded.

This is a candidate report, not a source of truth.  It compares DWARF struct
records from symbols/Dwarf/globals.nothpp against active class/struct bodies
under include/ and flags declarations that are missing, empty, commented out,
gap-only, enum-erased, visibly smaller than the DWARF layout, or missing owned
method declarations/definitions from symbol_addrs.txt.

The default output is docs/scaffold-audit.md.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DWARF_GLOBALS_PATH = os.path.join(ROOT_DIR, "symbols", "Dwarf", "globals.nothpp")
DWARF_FUNCTIONS_PATH = os.path.join(ROOT_DIR, "symbols", "Dwarf", "functions.nothpp")
DWARF_DUMP_PATH = os.path.join(ROOT_DIR, "symbols", "sr2_dwarfdump.nothpp")
DWARF_BY_UNIT_INDEX_PATH = os.path.join(ROOT_DIR, "symbols", "DwarfByUnit", "index.json")
LINE_INFO_PATH = os.path.join(ROOT_DIR, "symbols", "sr2_line_info.nothpp")
SYMBOL_ADDRS_PATH = os.path.join(ROOT_DIR, "config", "SLUS-21642-PROTO-070901", "symbol_addrs.txt")
SCAFFOLD_SKIP_PATH = os.path.join(ROOT_DIR, "docs", "scaffold-skip.txt")
SCAFFOLD_MIGRATION_PATH = os.path.join(ROOT_DIR, "docs", "scaffold-migration.md")
C_HEADER_AUDIT_ROOTS = (
    os.path.join(ROOT_DIR, "include", "usr", "local", "sega"),
    os.path.join(ROOT_DIR, "include", "usr", "local", "cri"),
    os.path.join(ROOT_DIR, "include", "usr", "local", "sce"),
)
GAME_INCLUDE_SRC_PREFIX = "include/Develop/Projects/SR2/pgm/src/"
SDK_INCLUDE_PREFIXES = (
    "include/usr/local/sega/",
    "include/usr/local/cri/",
    "include/usr/local/sce/",
)
SDK_TYPE_PREFIXES = ("NNS", "_NNS", "NVS", "PXS", "PXE", "Mwsfd", "sce")

_EXE = ".exe" if sys.platform == "win32" else ""
_DTK = os.path.join(ROOT_DIR, "build", "tools", "dtk" + _EXE)
_OBJDIFF_JSON = os.path.join(ROOT_DIR, "objdiff.json")

HEADER_EXTS = {".h", ".hpp", ".hh"}
SOURCE_EXTS = {".c", ".cpp", ".h", ".hpp"}
SKIP_PREFIXES = ("hk", "Nn", "Pf", "NNS", "_NNS")
EXTRA_AUDIT_TYPE_NAMES = {"__tree", "generic_iterator", "hkArray"}


@dataclass
class MemberInfo:
    type_name: str
    name: str
    offset: int
    size: int
    raw: str


@dataclass
class DwarfStruct:
    name: str
    kind: str
    size: int
    members: List[MemberInfo] = field(default_factory=list)

    @property
    def first_member_offset(self) -> Optional[int]:
        if not self.members:
            return None
        return min(member.offset for member in self.members)

    @property
    def last_member_end(self) -> int:
        if not self.members:
            return 0
        return max(member.offset + member.size for member in self.members)

    @property
    def last_member_offset(self) -> int:
        if not self.members:
            return 0
        return max(member.offset for member in self.members)


@dataclass
class SourceDecl:
    name: str
    kind: str
    path: str
    start_line: int
    body_lines: List[str]
    members: List[MemberInfo]
    qualified_name: Optional[str] = None
    parent_name: Optional[str] = None
    methods: Set[str] = field(default_factory=set)
    inline_methods: Set[str] = field(default_factory=set)
    has_commented_body: bool = False
    is_template: bool = False
    has_base: bool = False

    @property
    def last_member_end(self) -> int:
        if not self.members:
            return 0
        return max(member.offset + member.size for member in self.members)

    @property
    def last_member_offset(self) -> int:
        if not self.members:
            return 0
        return max(member.offset for member in self.members)


@dataclass
class Finding:
    class_name: str
    path: Optional[str]
    reasons: List[str]
    details: str


@dataclass
class TemplateVariantFinding:
    class_name: str
    locations: List[str]
    reason: str
    details: str


@dataclass
class TemplateOwnerEvidence:
    base_name: str
    owner_name: str
    args: Tuple[str, ...]
    method_name: str
    mangled: str
    line: int


@dataclass
class SourceTypedef:
    name: str
    target: str
    path: str
    line: int


@dataclass
class SourceGlobal:
    name: str
    type_name: str
    array_suffix: str
    path: str
    line: int
    namespace: Optional[str] = None


@dataclass
class DwarfGlobal:
    name: str
    type_name: str
    array_suffix: str
    size: int
    address: int
    raw: str


@dataclass
class MethodInfo:
    class_name: str
    method_name: str
    mangled: str
    is_weak: bool
    address: Optional[int] = None


@dataclass
class SourceMethodReturn:
    class_name: str
    method_name: str
    return_type: str
    param_types: Tuple[str, ...]
    is_const: bool
    path: str
    line: int


@dataclass
class ReturnTypeMismatch:
    class_name: str
    method_name: str
    path: str
    source_return: str
    dwarf_return: str
    mangled: str
    address: int


@dataclass
class SignatureMismatch:
    unit_name: str
    source_path: str
    # (mangled, demangled) pairs in reference but absent from compiled
    ref_only: List[Tuple[str, str]]
    # (mangled, demangled) pairs in compiled but absent from reference
    compiled_only: List[Tuple[str, str]]


@dataclass
class BoolCandidateFinding:
    class_name: str
    path: str
    # member names that are typed u8 but have a boolean Hungarian prefix
    members: List[str]


@dataclass
class CHeaderFinding:
    path: str
    line: int
    token: str
    text: str


@dataclass
class DuplicateLayoutFinding:
    name: str
    locations: List[str]
    members: List[str]


@dataclass
class DuplicateNamespaceGlobalFinding:
    qualified_name: str
    locations: List[str]
    declaration: str


@dataclass
class LibTypeInGameFinding:
    name: str
    location: str
    canonical_locations: List[str]
    reason: str


@dataclass
class MissingSourcePathFinding:
    source_path: str
    evidence: List[str]


@dataclass
class UnqualifiedGlobalOwnerFinding:
    name: str
    location: str
    declaration: str
    owner_candidates: List[str]
    reason: str


@dataclass
class DwarfByUnitSummary:
    index_path: str
    generated_at: str
    unit_blocks: int
    unique_unit_paths: int
    source_unit_paths: int
    header_unit_paths: int
    symbols: int
    unique_symbols: int
    low_cardinality_symbols: int
    likely_header_owner_symbols: int
    missing_checklist_symbols: int
    max_shared: int
    reports: Dict[str, str]


@dataclass
class MigrationReportSummary:
    report_path: str
    generated_at: str
    checked: str
    total: str
    candidate_count: int
    rows: List[str]


def relpath(path: str) -> str:
    return os.path.relpath(path, ROOT_DIR).replace("\\", "/")


def iter_files(root: str, exts: Set[str]) -> Iterable[str]:
    if not os.path.isdir(root):
        return
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if os.path.splitext(fname)[1] in exts:
                yield os.path.join(dirpath, fname)


def strip_line_comment(line: str) -> str:
    return line.split("//", 1)[0]


def is_project_type(name: str) -> bool:
    if not name or name.startswith(SKIP_PREFIXES):
        return False
    return name.startswith(("cls", "stc"))


def is_audit_type(name: str) -> bool:
    return is_project_type(name) or name in EXTRA_AUDIT_TYPE_NAMES


_MEMBER_RE = re.compile(
    r"^\s*(?P<type>.+?)\s+(?P<ptr>[*&]+\s*)?(?P<name>[A-Za-z_]\w*(?:\[[^\]]+\])*)\s*;"
    r"\s*//\s*(?:offset\s+)?0x(?P<offset>[0-9A-Fa-f]+)(?:,\s*size\s+0x(?P<size>[0-9A-Fa-f]+))?"
)
_MEMBER_FUNCTION_PTR_RE = re.compile(
    r"^\s*(?P<ret>.+?)\s*\((?P<class>[A-Za-z_]\w*)::\*\s*(?P<name>[A-Za-z_]\w*)\)\s*"
    r"\([^;]*\)\s*;\s*//\s*(?:offset\s+)?0x(?P<offset>[0-9A-Fa-f]+)"
    r"(?:,\s*size\s+0x(?P<size>[0-9A-Fa-f]+))?"
)
_ENUM_TAIL_MEMBER_RE = re.compile(
    r"^\s*}\s*(?P<name>[A-Za-z_]\w*(?:\[[^\]]+\])*)\s*;"
    r"\s*//\s*(?:offset\s+)?0x(?P<offset>[0-9A-Fa-f]+)(?:,\s*size\s+0x(?P<size>[0-9A-Fa-f]+))?"
)
_DWARF_OFFSET_RE = re.compile(r"DWARF\s+shows\s+0x(?P<offset>[0-9A-Fa-f]+)")
_ARRAY_SUFFIX_RE = re.compile(r"(?P<base>[A-Za-z_]\w*)(?P<arrays>(?:\[[^\]]+\])*)$")
_PLAIN_MEMBER_RE = re.compile(
    r"^\s*(?P<type>(?:class|struct|enum)\s+[A-Za-z_]\w*|.+?)\s+"
    r"(?P<ptr>[*&]+\s*)?(?P<name>[A-Za-z_]\w*(?:\[[^\]]+\])*)\s*;"
)


def parse_member(line: str) -> Optional[MemberInfo]:
    if strip_line_comment(line).strip().startswith("static "):
        return None
    m_member_function_ptr = _MEMBER_FUNCTION_PTR_RE.match(line.strip())
    if m_member_function_ptr:
        type_name = f"{m_member_function_ptr.group('ret')} ({m_member_function_ptr.group('class')}::*)()"
        return MemberInfo(
            type_name=" ".join(type_name.split()),
            name=m_member_function_ptr.group("name"),
            offset=int(m_member_function_ptr.group("offset"), 16),
            size=int(m_member_function_ptr.group("size"), 16) if m_member_function_ptr.group("size") else 0,
            raw=line.rstrip("\n"),
        )
    m_enum_tail = _ENUM_TAIL_MEMBER_RE.match(line.strip())
    if m_enum_tail:
        name = m_enum_tail.group("name")
        return MemberInfo(
            type_name="enum",
            name=name.split("[", 1)[0],
            offset=int(m_enum_tail.group("offset"), 16),
            size=int(m_enum_tail.group("size"), 16) if m_enum_tail.group("size") else 0,
            raw=line.rstrip("\n"),
        )
    m = _MEMBER_RE.match(line.strip())
    if not m:
        return None
    name = m.group("name")
    bare_name = name.split("[", 1)[0]
    type_name = " ".join(m.group("type").split())
    ptr = m.group("ptr")
    if ptr:
        type_name = f"{type_name} {''.join(ptr.split())}"
    dwarf_offset = _DWARF_OFFSET_RE.search(line)
    return MemberInfo(
        type_name=type_name,
        name=bare_name,
        offset=int((dwarf_offset or m).group("offset"), 16),
        size=int(m.group("size"), 16) if m.group("size") else 0,
        raw=line.rstrip("\n"),
    )


def parse_method_decls(class_name: str, body_lines: Sequence[str]) -> Tuple[Set[str], Set[str]]:
    methods: Set[str] = set()
    inline_methods: Set[str] = set()
    method_re = re.compile(r"(?:^|\s)(?P<name>~?[A-Za-z_]\w*)\s*\(")
    skip_names = {"if", "for", "while", "switch", "return", "sizeof", "static_cast", "const_cast"}

    for line in body_lines:
        active = strip_line_comment(line).strip()
        if "(" not in active or active.startswith(("typedef", "using")):
            continue
        m = method_re.search(active)
        if not m:
            continue
        name = m.group("name")
        if name in skip_names:
            continue
        methods.add(name)
        if "{" in active:
            inline_methods.add(name)

    return methods, inline_methods


def parse_top_level_members(body_lines: Sequence[str]) -> List[MemberInfo]:
    members: List[MemberInfo] = []
    depth = 0
    anonymous_union_depth: Optional[int] = None
    # Buffer for a wrapped type line (e.g. clang-format splits long template types across lines).
    # When non-None it holds the comment-stripped content of the previous unresolved line.
    pending_prefix: Optional[str] = None
    for line in body_lines:
        active = strip_line_comment(line)
        at_top = depth == 0 or anonymous_union_depth is not None
        enum_tail = depth == 1 and bool(_ENUM_TAIL_MEMBER_RE.match(line.strip()))
        if at_top or enum_tail:
            # At top level, try joining a buffered type prefix with the current line.
            if at_top and pending_prefix and not enum_tail:
                joined = pending_prefix + " " + line.lstrip()
                member = parse_member(joined)
            else:
                member = parse_member(line)
            if member:
                members.append(member)
                pending_prefix = None
            elif at_top and not enum_tail and ";" not in active and "{" not in active and "}" not in active and "(" not in active:
                # No semicolon/brace/paren — could be a type-only continuation line; buffer it.
                new_content = active.strip()
                if new_content and not new_content.endswith(":"):
                    pending_prefix = ((pending_prefix + " " + new_content) if pending_prefix else new_content)
                else:
                    pending_prefix = None
            else:
                pending_prefix = None
        else:
            pending_prefix = None
        if anonymous_union_depth is None and depth == 0 and re.match(r"^\s*union\s*\{", active):
            anonymous_union_depth = depth + active.count("{") - active.count("}")
        depth += active.count("{") - active.count("}")
        if anonymous_union_depth is not None and depth < anonymous_union_depth:
            anonymous_union_depth = None
        if depth < 0:
            depth = 0
    return members


def parse_mangled_method(mangled: str, class_names: Set[str]) -> Optional[Tuple[str, str]]:
    # Strip MWCC this-adjustor thunk prefixes, e.g. @4@__dt__13clsFooFv.
    mangled = re.sub(r"^(?:@\d+@)+", "", mangled)

    special = re.match(r"__(?P<kind>ct|dt)__", mangled)
    if special:
        rest = mangled[special.end() :]
        m_class = re.match(r"(?P<len>\d+)(?P<tail>.+)", rest)
        if not m_class:
            return None
        length = int(m_class.group("len"))
        class_name = m_class.group("tail")[:length]
        if class_name not in class_names:
            return None
        method_name = class_name if special.group("kind") == "ct" else f"~{class_name}"
        return class_name, method_name

    if "__" not in mangled:
        return None
    method_name, rest = mangled.split("__", 1)
    if not method_name or method_name.startswith("_") or not re.match(r"^[A-Za-z_]\w*$", method_name):
        return None
    m_class = re.match(r"(?P<len>\d+)(?P<tail>.+)", rest)
    if not m_class:
        return None
    length = int(m_class.group("len"))
    tail = m_class.group("tail")
    class_name = tail[:length]
    if class_name not in class_names:
        return None
    suffix = tail[length:]
    # Data members use the same name__Class mangling without a function-type suffix.
    # Member functions continue with F... or C...F... for const-qualified methods.
    if not suffix.startswith(("F", "C")):
        return None
    return class_name, method_name


def parse_length_prefixed_name(text: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"(?P<len>\d+)(?P<tail>.+)", text)
    if not m:
        return None
    length = int(m.group("len"))
    tail = m.group("tail")
    if len(tail) < length:
        return None
    return tail[:length], tail[length:]


def decode_mwcc_owner_suffix(suffix: str) -> Optional[str]:
    if suffix.startswith("Q"):
        m = re.match(r"^Q(?P<count>\d+)(?P<body>.*)$", suffix)
        if not m:
            return None
        count = int(m.group("count"))
        body = m.group("body")
        parts: List[str] = []
        for _ in range(count):
            parsed = parse_length_prefixed_name(body)
            if not parsed:
                return None
            name, body = parsed
            parts.append(name)
        return "::".join(parts) if parts and not body else None

    parsed = parse_length_prefixed_name(suffix)
    if parsed and not parsed[1]:
        return parsed[0]
    return None


def split_template_args(args: str) -> List[str]:
    parts: List[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(args):
        if char == "<":
            depth += 1
        elif char == ">" and depth > 0:
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(args[start:index].strip())
            start = index + 1
    tail = args[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def decode_mwcc_type_name(text: str) -> str:
    primitive_names = {
        "v": "void",
        "b": "bool",
        "c": "char",
        "Uc": "unsigned char",
        "s": "short",
        "Us": "unsigned short",
        "i": "int",
        "Ui": "unsigned int",
        "l": "long",
        "Ul": "unsigned long",
        "x": "long long",
        "Ux": "unsigned long long",
        "f": "float",
        "d": "double",
    }
    if text in primitive_names:
        return primitive_names[text]
    if text.startswith("P"):
        return f"{decode_mwcc_type_name(text[1:])}*"
    if text.startswith("R"):
        return f"{decode_mwcc_type_name(text[1:])}&"
    if len(text) >= 2 and text[0] == "Q" and text[1].isdigit():
        count = int(text[1])
        rest = text[2:]
        names: List[str] = []
        for _ in range(count):
            parsed = parse_length_prefixed_name(rest)
            if not parsed:
                return text
            name, rest = parsed
            names.append(name)
        if not rest:
            return "::".join(names)
    parsed = parse_length_prefixed_name(text)
    if parsed and not parsed[1]:
        return parsed[0]
    return text


def describe_template_owner(owner_name: str) -> Optional[Tuple[str, Tuple[str, ...]]]:
    if "<" not in owner_name or not owner_name.endswith(">"):
        return None
    base_name, args_text = owner_name.split("<", 1)
    args_text = args_text[:-1]
    if not is_audit_type(base_name):
        return None
    args = tuple(decode_mwcc_type_name(arg) for arg in split_template_args(args_text))
    if not args:
        return None
    return base_name, args


def parse_mangled_template_owner(mangled: str) -> Optional[Tuple[str, Tuple[str, ...], str, str]]:
    mangled = re.sub(r"^(?:@\d+@)+", "", mangled)

    special = re.match(r"__(?P<kind>ct|dt)__", mangled)
    if special:
        parsed = parse_length_prefixed_name(mangled[special.end() :])
        if not parsed:
            return None
        owner_name, _suffix = parsed
        described = describe_template_owner(owner_name)
        if not described:
            return None
        base_name, args = described
        method_name = base_name if special.group("kind") == "ct" else f"~{base_name}"
        return base_name, args, owner_name, method_name

    if "__" not in mangled:
        return None
    method_name, rest = mangled.split("__", 1)
    if not method_name or method_name.startswith("_") or not re.match(r"^[A-Za-z_]\w*$", method_name):
        return None
    parsed = parse_length_prefixed_name(rest)
    if not parsed:
        return None
    owner_name, suffix = parsed
    if not suffix.startswith(("F", "C")):
        return None
    described = describe_template_owner(owner_name)
    if not described:
        return None
    base_name, args = described
    return base_name, args, owner_name, method_name


def parse_symbol_template_owners(path: str) -> Dict[str, List[TemplateOwnerEvidence]]:
    groups: Dict[str, List[TemplateOwnerEvidence]] = {}
    if not os.path.exists(path):
        return groups

    symbol_re = re.compile(r"^\s*(?P<mangled>\S+)\s*=\s*0x[0-9A-Fa-f]+;")
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            m = symbol_re.match(line)
            if not m:
                continue
            mangled = m.group("mangled")
            parsed = parse_mangled_template_owner(mangled)
            if not parsed:
                continue
            base_name, args, owner_name, method_name = parsed
            groups.setdefault(base_name, []).append(
                TemplateOwnerEvidence(
                    base_name=base_name,
                    owner_name=owner_name,
                    args=args,
                    method_name=method_name,
                    mangled=mangled,
                    line=line_no,
                )
            )
    return groups


def parse_symbol_methods(path: str, class_names: Set[str]) -> Dict[str, List[MethodInfo]]:
    methods: Dict[str, List[MethodInfo]] = {}
    if not os.path.exists(path):
        return methods

    symbol_re = re.compile(r"^\s*(?P<mangled>\S+)\s*=\s*0x(?P<address>[0-9A-Fa-f]+);(?P<comment>.*)$")
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = symbol_re.match(line)
            if not m:
                continue
            mangled = m.group("mangled")
            parsed = parse_mangled_method(mangled, class_names)
            if not parsed:
                continue
            class_name, method_name = parsed
            methods.setdefault(class_name, []).append(
                MethodInfo(
                    class_name=class_name,
                    method_name=method_name,
                    mangled=mangled,
                    is_weak="visibility:weak" in m.group("comment") or "allow_duplicated:true" in m.group("comment"),
                    address=int(m.group("address"), 16),
                )
            )

    return methods


def parse_symbol_global_owners(path: str) -> Tuple[Dict[str, Set[str]], Set[str]]:
    owners_by_name: Dict[str, Set[str]] = {}
    bare_names: Set[str] = set()
    if not os.path.exists(path):
        return owners_by_name, bare_names

    symbol_re = re.compile(r"^\s*(?P<mangled>\S+)\s*=\s*0x[0-9A-Fa-f]+;")
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = symbol_re.match(line)
            if not m:
                continue
            mangled = m.group("mangled")
            if "__" not in mangled:
                if re.match(r"^[A-Za-z_]\w*$", mangled):
                    bare_names.add(mangled)
                continue
            name, suffix = mangled.split("__", 1)
            if not re.match(r"^[A-Za-z_]\w*$", name):
                continue
            owner = decode_mwcc_owner_suffix(suffix)
            if owner:
                owners_by_name.setdefault(name, set()).add(f"{owner}::{name}")
    return owners_by_name, bare_names


def split_param_types(params_str: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in params_str:
        if ch in "(<[":
            depth += 1
            cur.append(ch)
        elif ch in ")>]":
            if depth > 0:
                depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    if len(parts) == 1 and parts[0] in {"", "void"}:
        return []
    return [p for p in parts if p]


def normalize_signature_type(type_name: str) -> str:
    type_name = re.sub(r"/\*.*?\*/", "", type_name)
    type_name = re.sub(r"\b(?:class|struct|enum)\s+", "", type_name)
    type_name = re.sub(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)", "(*)", type_name)
    type_name = " ".join(type_name.replace("*", " *").replace("&", " &").split())
    type_name = normalize_type_name(type_name)
    type_name = type_name.replace(" *", "*").replace(" &", "&")
    return type_name


def source_param_type(param: str) -> str:
    param = param.split("=", 1)[0].strip()
    param = re.sub(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)", "(*)", param)
    param = re.sub(r"\s+[A-Za-z_]\w*(?:\s*\[[^\]]+\])*\s*$", "", param).strip()
    return normalize_signature_type(param)


def parse_demangled_method_signature(demangled: str) -> Optional[Tuple[str, Tuple[str, ...], bool]]:
    m = re.match(r"^(?P<name>.+?)\((?P<params>.*)\)(?P<const>\s+const)?$", demangled.strip())
    if not m:
        return None
    name = m.group("name").rsplit("::", 1)[-1]
    params = tuple(normalize_signature_type(param) for param in split_param_types(m.group("params")))
    return name, params, bool(m.group("const"))


def parse_source_method_returns(source_decls: Dict[str, List[SourceDecl]]) -> Dict[Tuple[str, str], List[SourceMethodReturn]]:
    returns: Dict[Tuple[str, str], List[SourceMethodReturn]] = {}
    method_re = re.compile(
        r"^(?P<ret>.+?)\s+(?P<name>~?[A-Za-z_]\w*)\s*\((?P<params>.*)\)\s*(?P<const>const)?(?:\s*(?:=\s*0|\{|;).*)?$"
    )
    qualifier_re = re.compile(r"^(?:virtual|inline|static|friend)\s+")

    for class_name, decls in source_decls.items():
        for decl in decls:
            depth = 0
            pending_stmt: Optional[str] = None
            pending_line = 0
            for idx, line in enumerate(decl.body_lines):
                active = strip_line_comment(line).strip()
                at_top = depth == 0
                if at_top and active and not active.startswith(("typedef", "using", "#")):
                    if pending_stmt is not None:
                        pending_stmt = f"{pending_stmt} {active}"
                    elif "(" in active:
                        pending_stmt = active
                        pending_line = decl.start_line + idx + 1

                    if pending_stmt is not None and not any(token in pending_stmt for token in (";", "{")):
                        depth += active.count("{") - active.count("}")
                        if depth < 0:
                            depth = 0
                        continue

                if pending_stmt is not None:
                    probe = pending_stmt
                    pending_stmt = None
                    while True:
                        new_probe = qualifier_re.sub("", probe).strip()
                        if new_probe == probe:
                            break
                        probe = new_probe
                    m = method_re.match(probe)
                    if m:
                        name = m.group("name")
                        if name != class_name and name != f"~{class_name}":
                            ret = " ".join(m.group("ret").split())
                            params = tuple(source_param_type(param) for param in split_param_types(m.group("params")))
                            returns.setdefault((class_name, name), []).append(
                                SourceMethodReturn(
                                    class_name=class_name,
                                    method_name=name,
                                    return_type=ret,
                                    param_types=params,
                                    is_const=bool(m.group("const")),
                                    path=decl.path,
                                    line=pending_line,
                                )
                            )
                depth += active.count("{") - active.count("}")
                if depth < 0:
                    depth = 0
    return returns


def parse_dwarf_function_returns(path: str) -> Dict[int, str]:
    returns: Dict[int, str] = {}
    if not os.path.exists(path):
        return returns
    range_re = re.compile(r"^//\s*Range:\s*0x(?P<address>[0-9A-Fa-f]+)\s*->")
    sig_re = re.compile(r"^(?P<ret>.+?)\s+(?P<name>~?[A-Za-z_]\w*(?:::\w+)*)\s*\(")
    pending_addr: Optional[int] = None

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            m_range = range_re.match(stripped)
            if m_range:
                pending_addr = int(m_range.group("address"), 16)
                continue
            if pending_addr is None:
                continue
            if not stripped or stripped.startswith("//"):
                continue
            m_sig = sig_re.match(stripped)
            if m_sig:
                returns[pending_addr] = " ".join(m_sig.group("ret").split())
            pending_addr = None
    return returns


def parse_source_method_defs() -> Dict[str, Set[str]]:
    defs: Dict[str, Set[str]] = {}
    method_re = re.compile(r"\b(?P<class>[A-Za-z_]\w*)::(?P<method>~?[A-Za-z_]\w*)\s*\(")
    for path in iter_files(os.path.join(ROOT_DIR, "src"), {".c", ".cc", ".cpp"}):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in method_re.finditer(text):
            defs.setdefault(m.group("class"), set()).add(m.group("method"))
    return defs


def parse_skip_list(path: str) -> Set[str]:
    names: Set[str] = set()
    if not os.path.exists(path):
        return names
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            active = line.split("#", 1)[0].strip()
            if not active:
                continue
            names.add(active.split()[0])
    return names


def better_dwarf_struct(old: Optional[DwarfStruct], new: DwarfStruct) -> DwarfStruct:
    if old is None:
        return new
    old_score = (len(old.members), old.size)
    new_score = (len(new.members), new.size)
    return new if new_score > old_score else old


def parse_dwarf_structs(path: str) -> Dict[str, DwarfStruct]:
    structs: Dict[str, DwarfStruct] = {}
    if not os.path.exists(path):
        return structs

    total_size_re = re.compile(r"^//\s*total size:\s*0x([0-9A-Fa-f]+)")
    start_re = re.compile(r"^(class|struct)\s+([A-Za-z_]\w*)\b[^;{]*(\{|\{\};)")
    pending_size: Optional[int] = None

    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = list(fh)

    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")
        m_size = total_size_re.match(line)
        if m_size:
            pending_size = int(m_size.group(1), 16)
            i += 1
            continue

        m_start = start_re.match(line)
        if not m_start:
            i += 1
            continue

        kind, name = m_start.group(1), m_start.group(2)
        if "@anon" in line:
            pending_size = None
            i += 1
            continue

        size = pending_size or 0
        body: List[str] = []
        depth = line.count("{") - line.count("}")
        i += 1
        while i < len(lines) and depth > 0:
            body_line = lines[i].rstrip("\n")
            body.append(body_line)
            depth += body_line.count("{") - body_line.count("}")
            i += 1

        members = parse_top_level_members(body)
        entry = DwarfStruct(name=name, kind=kind, size=size, members=members)
        structs[name] = better_dwarf_struct(structs.get(name), entry)
        pending_size = None

    return structs


def should_audit_dwarf_struct(name: str, source_decls: Dict[str, List[SourceDecl]]) -> bool:
    if is_audit_type(name):
        return True
    # Middleware/root-skipped names can still be actively scaffolded in project
    # headers. Audit those existing declarations, but do not report every missing
    # Havok/NNS/platform type from DWARF.
    return name in source_decls


def parse_dwarf_struct_variants(path: str) -> Dict[str, List[DwarfStruct]]:
    structs: Dict[str, List[DwarfStruct]] = {}
    if not os.path.exists(path):
        return structs

    total_size_re = re.compile(r"^//\s*total size:\s*0x([0-9A-Fa-f]+)")
    start_re = re.compile(r"^(class|struct)\s+([A-Za-z_]\w*)\b[^;{]*(\{|\{\};)")
    pending_size: Optional[int] = None

    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = list(fh)

    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")
        m_size = total_size_re.match(line)
        if m_size:
            pending_size = int(m_size.group(1), 16)
            i += 1
            continue

        m_start = start_re.match(line)
        if not m_start:
            i += 1
            continue

        kind, name = m_start.group(1), m_start.group(2)
        if "@anon" in line:
            pending_size = None
            i += 1
            continue

        size = pending_size or 0
        body: List[str] = []
        depth = line.count("{") - line.count("}")
        i += 1
        while i < len(lines) and depth > 0:
            body_line = lines[i].rstrip("\n")
            body.append(body_line)
            depth += body_line.count("{") - body_line.count("}")
            i += 1

        members = parse_top_level_members(body)
        structs.setdefault(name, []).append(DwarfStruct(name=name, kind=kind, size=size, members=members))
        pending_size = None

    return structs


def choose_dwarf_struct(variants: Sequence[DwarfStruct], decl: Optional[SourceDecl]) -> DwarfStruct:
    if not variants:
        raise ValueError("choose_dwarf_struct requires at least one variant")
    if decl is None or not decl.members:
        chosen = variants[0]
        for variant in variants[1:]:
            chosen = better_dwarf_struct(chosen, variant)
        return chosen

    def score(variant: DwarfStruct) -> Tuple[int, int, int, int, int]:
        missing_count = len(missing_offsets(variant, decl))
        source_by_offset = {member.offset: member.name for member in decl.members}
        name_mismatch_count = sum(
            1
            for member in variant.members
            if member.offset in source_by_offset and source_by_offset[member.offset] != member.name
        )
        ends_before = int(bool(variant.members and decl.last_member_offset < variant.last_member_offset))
        size_delta = abs(variant.last_member_end - decl.last_member_end)
        return (missing_count, name_mismatch_count, ends_before, size_delta, -len(variant.members))

    return min(variants, key=score)


def scan_commented_classes(path: str) -> Set[str]:
    names: Set[str] = set()
    class_re = re.compile(r"^\s*//+\s*(?:class|struct)\s+([A-Za-z_]\w*)\b[^;{]*\{")
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = class_re.match(line)
            if m:
                names.add(m.group(1))
    return names


def infer_scope_qualifier(lines: Sequence[str], target_line: int) -> List[str]:
    """Return namespace/class scopes active before a 1-based source line."""
    scopes: List[Tuple[str, int]] = []
    depth = 0
    namespace_re = re.compile(r"\bnamespace\s+([A-Za-z_]\w*)\s*\{")
    type_re = re.compile(r"\b(?:class|struct)\s+([A-Za-z_]\w*)\b[^;{]*\{")

    for line_no, line in enumerate(lines, 1):
        if line_no >= target_line:
            break
        active = strip_line_comment(line)
        m_namespace = namespace_re.search(active)
        m_type = type_re.search(active)
        if m_namespace:
            scopes.append((m_namespace.group(1), depth))
        elif m_type:
            scopes.append((m_type.group(1), depth))
        depth += active.count("{") - active.count("}")
        while scopes and depth <= scopes[-1][1]:
            scopes.pop()

    return [name for name, _scope_depth in scopes]


def parse_nested_source_decls(
    lines: Sequence[str], path: str, base_line: int, parent_name: str, parent_qualified_name: str
) -> List[SourceDecl]:
    decls: List[SourceDecl] = []
    header_re = re.compile(r"\b(class|struct)\s+([A-Za-z_]\w*)\b")

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            i += 1
            continue

        active_prefix = strip_line_comment(line)
        m = header_re.search(active_prefix)
        if not m:
            i += 1
            continue
        if ";" in active_prefix and ("{" not in active_prefix or active_prefix.find(";") < active_prefix.find("{")):
            i += 1
            continue

        start_line = base_line + i
        kind, name = m.group(1), m.group(2)
        while "{" not in active_prefix and i + 1 < len(lines):
            i += 1
            active_prefix += strip_line_comment(lines[i])
        if "{" not in active_prefix:
            i += 1
            continue

        body: List[str] = []
        depth = active_prefix.count("{") - active_prefix.count("}")
        i += 1
        while i < len(lines) and depth > 0:
            body_line = lines[i].rstrip("\n")
            body.append(body_line)
            no_comment = strip_line_comment(body_line)
            depth += no_comment.count("{") - no_comment.count("}")
            i += 1

        if is_audit_type(name):
            members = parse_top_level_members(body)
            methods, inline_methods = parse_method_decls(name, body)
            decls.append(
                SourceDecl(
                    name=name,
                    kind=kind,
                    path=path,
                    start_line=start_line,
                    body_lines=body,
                    members=members,
                    qualified_name=f"{parent_qualified_name}::{name}",
                    parent_name=parent_name,
                    methods=methods,
                    inline_methods=inline_methods,
                    has_base=":" in active_prefix.split("{", 1)[0],
                )
            )
        decls.extend(parse_nested_source_decls(body, path, start_line + 1, name, f"{parent_qualified_name}::{name}"))

    return decls


def parse_source_decls() -> Dict[str, List[SourceDecl]]:
    decls: Dict[str, List[SourceDecl]] = {}
    header_re = re.compile(r"\b(class|struct)\s+([A-Za-z_]\w*)\b")

    for path in iter_files(os.path.join(ROOT_DIR, "include"), HEADER_EXTS):
        rel = relpath(path)
        try:
            commented = scan_commented_classes(path)
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = list(fh)
        except OSError:
            continue

        i = 0
        pending_template = False
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                i += 1
                continue
            if stripped.startswith("template"):
                pending_template = True
                i += 1
                continue
            active_prefix = strip_line_comment(line)
            m = header_re.search(active_prefix)
            if not m:
                pending_template = False
                i += 1
                continue
            if ";" in active_prefix and ("{" not in active_prefix or active_prefix.find(";") < active_prefix.find("{")):
                pending_template = False
                i += 1
                continue

            start_line = i + 1
            kind, name = m.group(1), m.group(2)
            scope = infer_scope_qualifier(lines, start_line)
            qualified_name = "::".join(scope + [name]) if scope else name
            while "{" not in active_prefix and i + 1 < len(lines):
                i += 1
                active_prefix += strip_line_comment(lines[i])
            if "{" not in active_prefix:
                i += 1
                continue

            body: List[str] = []
            depth = active_prefix.count("{") - active_prefix.count("}")
            i += 1
            while i < len(lines) and depth > 0:
                body_line = lines[i].rstrip("\n")
                body.append(body_line)
                no_comment = strip_line_comment(body_line)
                depth += no_comment.count("{") - no_comment.count("}")
                i += 1

            members = parse_top_level_members(body)
            methods, inline_methods = parse_method_decls(name, body)
            decl = SourceDecl(
                name=name,
                kind=kind,
                path=rel,
                start_line=start_line,
                body_lines=body,
                members=members,
                qualified_name=qualified_name,
                methods=methods,
                inline_methods=inline_methods,
                has_commented_body=name in commented,
                is_template=pending_template,
                has_base=":" in active_prefix.split("{", 1)[0],
            )
            pending_template = False
            decls.setdefault(name, []).append(decl)
            for nested_decl in parse_nested_source_decls(body, rel, start_line + 1, name, qualified_name):
                decls.setdefault(nested_decl.name, []).append(nested_decl)

    return decls


def parse_source_typedefs() -> List[SourceTypedef]:
    typedefs: List[SourceTypedef] = []
    typedef_re = re.compile(r"^\s*typedef\s+(?P<target>.+?)\s+(?P<name>(?:cls|stc)\w+)\s*;")
    for path in iter_files(os.path.join(ROOT_DIR, "include"), HEADER_EXTS):
        rel = relpath(path)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = list(fh)
                for line_no, line in enumerate(lines, 1):
                    active = strip_line_comment(line)
                    m = typedef_re.match(active)
                    if not m:
                        continue
                    typedefs.append(
                        SourceTypedef(
                            name=m.group("name"),
                            target=" ".join(m.group("target").split()),
                            path=rel,
                            line=line_no,
                        )
                    )
        except OSError:
            continue
    return typedefs


def parse_source_globals() -> List[SourceGlobal]:
    globals_: List[SourceGlobal] = []
    extern_re = re.compile(
        r"^\s*extern\s+(?P<type>.+?)\s+(?P<name>[A-Za-z_]\w*(?:\[[^\]]+\])*)\s*;"
    )
    for path in iter_files(os.path.join(ROOT_DIR, "include"), HEADER_EXTS):
        rel = relpath(path)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = list(fh)
                for line_no, line in enumerate(lines, 1):
                    active = strip_line_comment(line)
                    m = extern_re.match(active)
                    if not m:
                        continue
                    name_match = _ARRAY_SUFFIX_RE.match(m.group("name"))
                    if not name_match:
                        continue
                    globals_.append(
                        SourceGlobal(
                            name=name_match.group("base"),
                            type_name=" ".join(m.group("type").split()),
                            array_suffix=name_match.group("arrays"),
                            path=rel,
                            line=line_no,
                            namespace="::".join(infer_scope_qualifier(lines, line_no)) or None,
                        )
                    )
        except OSError:
            continue
    return globals_


def iter_source_global_candidates() -> Iterable[Tuple[str, int, str, str, Optional[str]]]:
    normal_re = re.compile(
        r"^\s*(?:extern\s+|static\s+|const\s+)*"
        r"(?P<type>[A-Za-z_][\w\s:<>*&]*?)\s+"
        r"(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]+\])*\s*(?:;|=)"
    )
    function_pointer_re = re.compile(
        r"^\s*(?:extern\s+|static\s+)*[A-Za-z_][\w\s:<>*&]*?\s*"
        r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*\([^;]*\)\s*(?:;|=)"
    )
    skip_first = {
        "class",
        "struct",
        "enum",
        "namespace",
        "template",
        "typedef",
        "using",
        "return",
        "if",
        "for",
        "while",
        "switch",
    }

    for root in (os.path.join(ROOT_DIR, "include"), os.path.join(ROOT_DIR, "src")):
        for path in iter_files(root, SOURCE_EXTS):
            rel = relpath(path)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines = list(fh)
            except OSError:
                continue

            namespace_stack: List[Tuple[str, int]] = []
            type_stack: List[Tuple[str, int]] = []
            depth = 0
            for line_no, line in enumerate(lines, 1):
                active = strip_line_comment(line)
                stripped = active.strip()

                while namespace_stack and depth <= namespace_stack[-1][1]:
                    namespace_stack.pop()
                while type_stack and depth <= type_stack[-1][1]:
                    type_stack.pop()

                if not stripped or stripped.startswith("#"):
                    depth += active.count("{") - active.count("}")
                    depth = max(depth, 0)
                    continue

                m_namespace = re.match(r"^\s*namespace\s+([A-Za-z_]\w*)\s*\{", active)
                if m_namespace:
                    namespace_stack.append((m_namespace.group(1), depth))

                # Do not audit class/struct members as unqualified file globals.
                m_type = re.match(r"^\s*(?:class|struct)\s+([A-Za-z_]\w*)\b[^;{]*\{", active)
                if m_type:
                    type_stack.append((m_type.group(1), depth))

                at_file_scope = depth == len(namespace_stack)
                if at_file_scope and not type_stack:
                    first = stripped.split(None, 1)[0]
                    if first not in skip_first and "::" not in stripped:
                        match = function_pointer_re.match(active)
                        if not match and "(" not in stripped:
                            match = normal_re.match(active)
                        if match:
                            namespace = "::".join(name for name, _scope_depth in namespace_stack) or None
                            yield rel, line_no, match.group("name"), stripped.rstrip(";"), namespace

                depth += active.count("{") - active.count("}")
                depth = max(depth, 0)


def build_unqualified_global_owner_findings() -> List[UnqualifiedGlobalOwnerFinding]:
    owners_by_name, bare_names = parse_symbol_global_owners(SYMBOL_ADDRS_PATH)
    findings: List[UnqualifiedGlobalOwnerFinding] = []
    seen: Set[Tuple[str, str, int]] = set()

    for path, line, name, declaration, namespace in iter_source_global_candidates():
        owner_candidates = sorted(owners_by_name.get(name, set()))
        if not owner_candidates or name in bare_names:
            continue
        if namespace:
            qualified_name = f"{namespace}::{name}"
            if qualified_name in owner_candidates:
                continue
        # Anonymous namespace/source-local symbols are already represented as unqualified
        # source declarations and should not be moved to a class/namespace owner solely
        # because another TU has a same-name local static.
        non_local_candidates = [owner for owner in owner_candidates if not owner.startswith("@unnamed@")]
        if not non_local_candidates:
            continue
        key = (name, path, line)
        if key in seen:
            continue
        seen.add(key)
        reason = "unqualified source global has only qualified symbol_addrs owner candidates"
        findings.append(
            UnqualifiedGlobalOwnerFinding(
                name=name,
                location=f"{path}:{line}",
                declaration=declaration,
                owner_candidates=non_local_candidates,
                reason=reason,
            )
        )

    return sorted(findings, key=lambda finding: (finding.location, finding.name))


def build_duplicate_namespace_global_findings(
    source_globals: Optional[Sequence[SourceGlobal]] = None,
) -> List[DuplicateNamespaceGlobalFinding]:
    if source_globals is None:
        source_globals = parse_source_globals()
    by_decl: Dict[Tuple[str, str, str], List[SourceGlobal]] = {}
    for source_global in source_globals:
        qualified_name = (
            f"{source_global.namespace}::{source_global.name}" if source_global.namespace else source_global.name
        )
        key = (qualified_name, normalize_type_name(source_global.type_name), source_global.array_suffix)
        by_decl.setdefault(key, []).append(source_global)

    findings: List[DuplicateNamespaceGlobalFinding] = []
    for (qualified_name, type_name, array_suffix), duplicates in sorted(by_decl.items()):
        locations = sorted({f"{source_global.path}:{source_global.line}" for source_global in duplicates})
        if len(locations) < 2:
            continue
        findings.append(
            DuplicateNamespaceGlobalFinding(
                qualified_name=qualified_name,
                locations=locations,
                declaration=f"{type_name} {qualified_name}{array_suffix}",
            )
        )
    return findings


def parse_dwarf_globals(path: str) -> Dict[str, List[DwarfGlobal]]:
    globals_: Dict[str, List[DwarfGlobal]] = {}
    if not os.path.exists(path):
        return globals_

    scalar_type = r"(?:unsigned|signed)\s+(?:char|short|int|long(?:\s+long)?)|[A-Za-z_]\w+"
    global_re = re.compile(
        r"^\s*(?:static\s+)?(?P<type>(?:class|struct|enum)\s+[A-Za-z_]\w*|(?:"
        + scalar_type
        + r")(?:\s+\*)?)\s+"
        r"(?P<name>[A-Za-z_]\w*(?:\[[^\]]+\])*)\s*;\s*//\s*size:\s*0x(?P<size>[0-9A-Fa-f]+),\s*address:\s*0x(?P<address>[0-9A-Fa-f]+)"
    )
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = global_re.match(line)
            if not m:
                continue
            name_match = _ARRAY_SUFFIX_RE.match(m.group("name"))
            if not name_match:
                continue
            address = int(m.group("address"), 16)
            if address == 0:
                continue
            name = name_match.group("base")
            entry = DwarfGlobal(
                name=name,
                type_name=" ".join(m.group("type").split()),
                array_suffix=name_match.group("arrays"),
                size=int(m.group("size"), 16),
                address=address,
                raw=line.rstrip("\n"),
            )
            globals_.setdefault(name, []).append(entry)
    return globals_


def symbol_text(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def body_is_empty(decl: SourceDecl) -> bool:
    for line in decl.body_lines:
        stripped = strip_line_comment(line).strip()
        if not stripped or stripped in {"public:", "private:", "protected:", "};", "{"}:
            continue
        return False
    return True


def has_concrete_body(decl: SourceDecl) -> bool:
    if decl.is_template:
        return False
    if decl.members or decl.methods or decl.has_base:
        return True
    return not body_is_empty(decl)


def build_duplicate_definition_findings(source_decls: Dict[str, List[SourceDecl]]) -> List[Finding]:
    findings: List[Finding] = []
    for name in sorted(source_decls):
        if not name.startswith(("hk", "NNS", "_NNS")):
            continue
        concrete_decls = [decl for decl in source_decls[name] if has_concrete_body(decl)]
        if len(concrete_decls) < 2:
            continue
        canonical = concrete_decls[0]
        duplicate_locations = [f"{decl.path}:{decl.start_line}" for decl in concrete_decls[1:]]
        shown = ", ".join(duplicate_locations[:6])
        if len(duplicate_locations) > 6:
            shown += f", +{len(duplicate_locations) - 6} more"
        findings.append(
            Finding(
                class_name=name,
                path=f"{canonical.path}:{canonical.start_line}",
                reasons=["duplicate concrete declarations"],
                details=(
                    "Multiple active class/struct bodies exist for this name. "
                    f"Other location(s): {shown}. Prefer one canonical owner and include it instead of redeclaring."
                ),
            )
        )
    return findings


def member_is_gap(member: MemberInfo) -> bool:
    text = f"{member.type_name} {member.name}".lower()
    return any(token in text for token in ("gap", "pad", "unk", "field_", "storage"))


def member_is_opaque_storage(member: MemberInfo) -> bool:
    return "storage" in member.name.lower()


def is_gap_only(decl: SourceDecl) -> bool:
    return bool(decl.members) and all(member_is_gap(member) for member in decl.members)


def byte_buffer_placeholder(decl: SourceDecl) -> Optional[str]:
    if decl.has_base:
        return None
    active_lines = []
    for line in decl.body_lines:
        stripped = strip_line_comment(line).strip()
        if not stripped or stripped in {"public:", "private:", "protected:", "};", "{"}:
            continue
        active_lines.append(stripped)
    if len(active_lines) != 1:
        return None
    m = re.match(
        r"^(?P<type>u8|s8|c8|char|unsigned\s+char|signed\s+char)\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*\[(?P<size>[^\]]+)\]\s*;",
        active_lines[0],
    )
    if not m:
        return None
    return f"{m.group('type')} {m.group('name')}[{m.group('size')}]"


def is_byte_type(type_name: str) -> bool:
    return " ".join(type_name.split()) in {"u8", "s8", "c8", "char", "unsigned char", "signed char"}


def byte_buffer_matches_dwarf(dwarf: DwarfStruct, decl: SourceDecl) -> bool:
    if len(decl.members) != 1 or len(dwarf.members) != 1:
        return False
    source_member = decl.members[0]
    dwarf_member = dwarf.members[0]
    return (
        source_member.name == dwarf_member.name
        and source_member.offset == dwarf_member.offset
        and source_member.size == dwarf_member.size
        and is_byte_type(source_member.type_name)
        and is_byte_type(dwarf_member.type_name)
    )


def enum_erased_members(dwarf: DwarfStruct, decl: SourceDecl) -> List[str]:
    source_by_name = {member.name: member for member in decl.members}
    erased: List[str] = []
    for member in dwarf.members:
        if not member.type_name.startswith("enum "):
            continue
        source_member = source_by_name.get(member.name)
        if source_member and source_member.type_name in {"s32", "u32", "signed int", "unsigned int"}:
            erased.append(member.name)
    return erased


def missing_offsets(dwarf: DwarfStruct, decl: SourceDecl) -> List[str]:
    source_offsets = {member.offset for member in decl.members}
    missing = [member for member in dwarf.members if member.offset not in source_offsets]
    return [f"0x{member.offset:X} {member.name}" for member in missing]


def find_parent_member_size(dwarf_variants: Dict[str, List[DwarfStruct]], decl: SourceDecl) -> Optional[int]:
    if not decl.parent_name:
        return None
    for parent in dwarf_variants.get(decl.parent_name, []):
        for member in parent.members:
            if member.type_name.endswith(f" {decl.name}") or member.type_name == decl.name:
                return member.size
    return None


def missing_offsets_within_size(dwarf: DwarfStruct, decl: SourceDecl, size_limit: Optional[int]) -> List[str]:
    source_offsets = {member.offset for member in decl.members}
    missing = []
    for member in dwarf.members:
        if size_limit is not None and member.offset >= size_limit:
            continue
        if member.offset not in source_offsets:
            missing.append(member)
    return [f"0x{member.offset:X} {member.name}" for member in missing]


def source_only_gap_members(
    dwarf: DwarfStruct,
    decl: SourceDecl,
    size_limit: Optional[int],
    variants: Sequence[DwarfStruct],
) -> List[str]:
    dwarf_offsets = {member.offset for member in dwarf.members}
    extra = []
    for member in decl.members:
        if not member_is_gap(member):
            continue
        if member_is_opaque_storage(member):
            continue
        if size_limit is not None and member.offset >= size_limit:
            continue
        if member.offset not in dwarf_offsets:
            if any(
                variant_member.name == member.name and variant_member.offset == member.offset
                for variant in variants
                for variant_member in variant.members
            ):
                continue
            extra.append(member)
    return [f"0x{member.offset:X} {member.name}" for member in extra]


def source_members_outside_selected_layout(
    dwarf: DwarfStruct,
    decl: SourceDecl,
    size_limit: Optional[int],
    variants: Sequence[DwarfStruct],
) -> List[str]:
    extra = []
    first_dwarf_offset = dwarf.first_member_offset
    for member in decl.members:
        if member_is_gap(member):
            continue
        if member.size == 0 and member.offset == dwarf.size:
            continue
        if size_limit is not None and member.offset >= size_limit:
            continue
        if decl.has_base and first_dwarf_offset is not None and member.offset < first_dwarf_offset:
            continue
        if not any(dwarf_member.offset == member.offset and dwarf_member.name == member.name for dwarf_member in dwarf.members):
            in_other_variant = any(
                variant != dwarf
                and any(variant_member.offset == member.offset and variant_member.name == member.name for variant_member in variant.members)
                for variant in variants
            )
            suffix = " (matches another DWARF variant)" if in_other_variant else ""
            extra.append(f"0x{member.offset:X} {member.name}{suffix}")
    return extra


def is_known_flattened_stl_container(name: str, decl: SourceDecl, variants: Sequence[DwarfStruct]) -> bool:
    member_names = {member.name for member in decl.members}
    if name == "vector" and decl.path.endswith("lib/OO/core/OOVector.hpp"):
        return member_names == {"_capacity", "_size", "_data"}
    if name == "map" and decl.path.endswith("lib/OO/core/OOFontSystem.hpp"):
        has_tree_variant = any(
            len(variant.members) == 1 and variant.members[0].name == "tree_" for variant in variants
        )
        return has_tree_variant and member_names == {"_capacity", "_size", "_lo", "_hi"}
    return False


def has_plain_sdk_member_body(decl: SourceDecl) -> bool:
    if not decl.path.startswith("include/usr/local/sce/"):
        return False
    return has_plain_member_body(decl)


def has_plain_member_body(decl: SourceDecl) -> bool:
    for line in decl.body_lines:
        active = strip_line_comment(line).strip()
        if not active or active.startswith(("#", "public:", "private:", "protected:")):
            continue
        if active.startswith(("typedef", "static", "enum", "union", "struct", "class")):
            continue
        if ";" in active and "(" not in active:
            return True
    return False


def anonymous_union_member_names(decl: SourceDecl) -> Set[str]:
    names: Set[str] = set()
    depth = 0
    union_depth: Optional[int] = None
    for line in decl.body_lines:
        active = strip_line_comment(line).strip()
        if union_depth is not None and depth >= union_depth:
            m = _PLAIN_MEMBER_RE.match(active)
            if m and "(" not in active:
                names.add(m.group("name").split("[", 1)[0])
        if union_depth is None and re.match(r"^union\s*\{", active):
            union_depth = depth + active.count("{") - active.count("}")
        depth += active.count("{") - active.count("}")
        if union_depth is not None and depth < union_depth:
            union_depth = None
        if depth < 0:
            depth = 0
    return names


def source_union_matches_dwarf(decl: SourceDecl, dwarf: DwarfStruct) -> bool:
    if decl.members:
        return False
    if not dwarf.members or any(member.offset != 0 for member in dwarf.members):
        return False
    union_names = anonymous_union_member_names(decl)
    return bool(union_names) and all(member.name in union_names for member in dwarf.members)


def source_only_gap_declarations(dwarf: DwarfStruct, decl: SourceDecl) -> List[str]:
    dwarf_names = {member.name for member in dwarf.members}
    parsed_names = {member.name for member in decl.members}
    extra = []
    member_re = re.compile(
        r"^\s*(?P<type>[A-Za-z_]\w*(?:\s*[*&])?)\s+"
        r"(?P<name>[A-Za-z_]\w*)(?P<arrays>(?:\[[^\]]+\])*)\s*;"
    )
    depth = 0
    for line in decl.body_lines:
        active = strip_line_comment(line).strip()
        if depth > 0:
            depth += active.count("{") - active.count("}")
            continue
        if "{" in active:
            depth += active.count("{") - active.count("}")
            continue
        m = member_re.match(active)
        if not m:
            continue
        name = m.group("name")
        if name in parsed_names or name in dwarf_names:
            continue
        text = f"{m.group('type')} {name}".lower()
        if any(token in text for token in ("gap", "pad", "unk", "field_")):
            extra.append(f"{m.group('type')} {name}{m.group('arrays')}")
    return extra


def source_only_declarations(dwarf: DwarfStruct, decl: SourceDecl) -> List[str]:
    dwarf_names = {member.name for member in dwarf.members}
    parsed_names = {member.name for member in decl.members}
    extra = []
    member_re = re.compile(
        r"^\s*(?P<type>(?:class|struct|enum)\s+[A-Za-z_]\w*|[A-Za-z_]\w*(?:\s*[*&])?)\s+"
        r"(?P<name>[A-Za-z_]\w*)(?P<arrays>(?:\[[^\]]+\])*)\s*;"
    )
    depth = 0
    for line in decl.body_lines:
        active = strip_line_comment(line).strip()
        if depth > 0:
            depth += active.count("{") - active.count("}")
            continue
        if "{" in active:
            depth += active.count("{") - active.count("}")
            continue
        m = member_re.match(active)
        if not m:
            continue
        name = m.group("name")
        if name in parsed_names or name in dwarf_names:
            continue
        text = f"{m.group('type')} {name}".lower()
        if any(token in text for token in ("gap", "pad", "unk", "field_")):
            continue
        extra.append(f"{m.group('type')} {name}{m.group('arrays')}")
    return extra


def normalize_type_name(type_name: str) -> str:
    type_name = type_name.replace("*", " *").replace("&", " &")
    type_name = " ".join(type_name.replace("::", " :: ").split())
    type_name = type_name.replace(" :: ", "::")
    for prefix in ("class ", "struct ", "enum "):
        if type_name.startswith(prefix):
            type_name = type_name[len(prefix) :]
            break
    type_name = type_name.replace(" *", "*").replace(" &", "&")
    aliases = {
        "f32": "float",
        "f64": "double",
        "u8": "unsigned char",
        "s8": "signed char",
        "c8": "char",
        "u16": "unsigned short",
        "s16": "signed short",
        "u32": "unsigned int",
        "s32": "signed int",
        "u64": "unsigned long long",
        "s64": "signed long long",
        "u8*": "unsigned char*",
        "s8*": "char*",
        "c8*": "char*",
        "u16*": "unsigned short*",
        "s16*": "signed short*",
        "u32*": "unsigned int*",
        "s32*": "signed int*",
        "u64*": "unsigned long long*",
        "s64*": "signed long long*",
        "void*": "void*",
        "void *": "void*",
        "float*": "float*",
        "nspPackId::enm": "enm",
        "nspGear::enmLevel": "enmLevel",
    }
    return aliases.get(type_name, type_name)


def display_type_name(type_name: str) -> str:
    """Render audit type names in project spelling where possible."""
    normalized = normalize_type_name(type_name)
    aliases = {
        "char": "c8",
        "signed char": "s8",
        "unsigned char": "u8",
        "signed short": "s16",
        "unsigned short": "u16",
        "signed int": "s32",
        "unsigned int": "u32",
        "signed long long": "s64",
        "unsigned long long": "u64",
        "float": "f32",
        "double": "f64",
        "char*": "c8*",
        "signed char*": "s8*",
        "unsigned char*": "u8*",
        "signed short*": "s16*",
        "unsigned short*": "u16*",
        "signed int*": "s32*",
        "unsigned int*": "u32*",
        "signed long long*": "s64*",
        "unsigned long long*": "u64*",
        "float*": "f32*",
        "double*": "f64*",
    }
    return aliases.get(normalized, normalized)


def normalized_variant_key(variant: DwarfStruct) -> Tuple[int, Tuple[Tuple[int, int, str, str], ...]]:
    return (
        variant.size,
        tuple((member.offset, member.size, normalize_type_name(member.type_name), member.name) for member in variant.members),
    )


def member_names_key(variant: DwarfStruct) -> Tuple[str, ...]:
    return tuple(member.name for member in variant.members)


def layout_key(variant: DwarfStruct) -> Tuple[int, Tuple[Tuple[int, int, str], ...]]:
    return variant.size, tuple((member.offset, member.size, member.name) for member in variant.members)


def type_family(type_name: str) -> str:
    normalized = normalize_type_name(type_name)
    if "*" in normalized:
        return "pointer"
    if normalized in {
        "char",
        "signed char",
        "unsigned char",
        "signed short",
        "unsigned short",
        "signed int",
        "unsigned int",
        "signed long long",
        "unsigned long long",
        "float",
        "double",
    }:
        return "scalar"
    if normalized.startswith("enum "):
        return "enum"
    return "object"


def same_member_names_template_group(variants: Sequence[DwarfStruct]) -> Tuple[bool, str]:
    if len(variants) < 2 or not variants[0].members:
        return False, ""
    names = member_names_key(variants[0])
    if not all(member_names_key(variant) == names for variant in variants):
        return False, ""

    member_count = len(names)
    if member_count > 4:
        return False, ""

    for member_index in range(member_count):
        families = {type_family(variant.members[member_index].type_name) for variant in variants}
        if not families.issubset({"scalar", "enum"}):
            return False, ""
    return True, "same member names with scalar storage-size variants"


def unique_dwarf_variants(variants: Sequence[DwarfStruct]) -> List[DwarfStruct]:
    unique: List[DwarfStruct] = []
    seen: Set[Tuple[int, Tuple[Tuple[int, int, str, str], ...]]] = set()
    for variant in variants:
        key = normalized_variant_key(variant)
        if key in seen:
            continue
        seen.add(key)
        unique.append(variant)
    return unique


def summarize_template_variants(variants: Sequence[DwarfStruct]) -> str:
    summaries = []
    for variant in variants[:6]:
        members = ", ".join(
            f"0x{member.offset:X}:{normalize_type_name(member.type_name)} {member.name}"
            for member in variant.members[:4]
        )
        if len(variant.members) > 4:
            members += ", ..."
        summaries.append(f"size 0x{variant.size:X} ({members})")
    if len(variants) > 6:
        summaries.append(f"+{len(variants) - 6} more")
    return "; ".join(summaries)


def summarize_template_owner_evidence(evidence: Sequence[TemplateOwnerEvidence]) -> str:
    summaries = []
    for item in evidence[:8]:
        arg_text = ", ".join(item.args)
        summaries.append(f"{item.method_name}<{arg_text}> from `{item.mangled}` (symbol_addrs.txt:{item.line})")
    if len(evidence) > 8:
        summaries.append(f"+{len(evidence) - 8} more")
    return "; ".join(summaries)


def summarize_missing_template_methods(evidence: Sequence[TemplateOwnerEvidence], missing_methods: Sequence[str]) -> str:
    summaries: List[str] = []
    missing_set = set(missing_methods)
    shown_methods: Set[str] = set()
    for item in evidence:
        if item.method_name not in missing_set or item.method_name in shown_methods:
            continue
        shown_methods.add(item.method_name)
        arg_text = ", ".join(item.args)
        summaries.append(f"{item.method_name}<{arg_text}> from `{item.mangled}` (symbol_addrs.txt:{item.line})")
        if len(summaries) >= 8:
            break
    remaining = len(missing_set - shown_methods)
    if remaining:
        summaries.append(f"+{remaining} more missing method(s)")
    return "; ".join(summaries)


def build_template_owner_findings(
    template_owners: Dict[str, List[TemplateOwnerEvidence]],
    source_decls: Dict[str, List[SourceDecl]],
    dwarf_variants: Dict[str, List[DwarfStruct]],
) -> List[TemplateVariantFinding]:
    findings: List[TemplateVariantFinding] = []
    for base_name, evidence in sorted(template_owners.items()):
        source_matches = source_decls.get(base_name, [])
        template_matches = [decl for decl in source_matches if decl.is_template]
        if template_matches:
            declared_methods = set().union(*(decl.methods for decl in template_matches))
            symbol_methods = {item.method_name for item in evidence}
            missing_methods = sorted(symbol_methods - declared_methods)
            if missing_methods:
                findings.append(
                    TemplateVariantFinding(
                        class_name=base_name,
                        locations=[f"{decl.path}:{decl.start_line}" for decl in template_matches],
                        reason="symbol_addrs template owner methods missing from declared template",
                        details=summarize_missing_template_methods(evidence, missing_methods),
                    )
                )
            continue
        unique_by_args: Dict[Tuple[str, ...], TemplateOwnerEvidence] = {}
        for item in evidence:
            unique_by_args.setdefault(item.args, item)
        if len(unique_by_args) < 2:
            continue

        locations = [f"{decl.path}:{decl.start_line}" for decl in source_matches]
        if not locations:
            locations = ["not declared"]
        reason = "symbol_addrs template owners with multiple concrete template arguments"
        if dwarf_variants.get(base_name):
            reason += "; DWARF has flattened unqualified struct/class body"
        findings.append(
            TemplateVariantFinding(
                class_name=base_name,
                locations=locations,
                reason=reason,
                details=summarize_template_owner_evidence(list(unique_by_args.values())),
            )
        )
    return findings


def build_template_variant_findings(
    dwarf_variants: Dict[str, List[DwarfStruct]], source_decls: Dict[str, List[SourceDecl]]
) -> List[TemplateVariantFinding]:
    findings: List[TemplateVariantFinding] = []
    for name, variants in sorted(dwarf_variants.items()):
        if any(decl.is_template for decl in source_decls.get(name, [])):
            continue
        unique = unique_dwarf_variants(variants)
        if len(unique) < 2:
            continue

        groups: Dict[Tuple[str, ...], List[DwarfStruct]] = {}
        for variant in unique:
            groups.setdefault(member_names_key(variant), []).append(variant)

        candidate_groups: List[Tuple[str, List[DwarfStruct]]] = []
        for group in groups.values():
            layout_groups: Dict[Tuple[int, Tuple[Tuple[int, int, str], ...]], List[DwarfStruct]] = {}
            for variant in group:
                layout_groups.setdefault(layout_key(variant), []).append(variant)
            for layout_group in layout_groups.values():
                if len(layout_group) > 1:
                    candidate_groups.append(("same storage layout with differing member types", layout_group))

            is_template_like, reason = same_member_names_template_group(group)
            if is_template_like:
                candidate_groups.append((reason, group))

        if not candidate_groups:
            continue

        locations = [f"{decl.path}:{decl.start_line}" for decl in source_decls.get(name, [])]
        if not locations:
            locations = ["not declared"]
        reason, group = max(candidate_groups, key=lambda item: len(item[1]))
        findings.append(
            TemplateVariantFinding(
                class_name=name,
                locations=locations,
                reason=reason,
                details=summarize_template_variants(group),
            )
        )
    return findings


def is_byte_placeholder_global(source: SourceGlobal, dwarf: DwarfGlobal) -> bool:
    source_type = normalize_type_name(source.type_name)
    dwarf_type = normalize_type_name(dwarf.type_name)
    if source_type not in {"char", "unsigned char", "signed char"}:
        return False
    if not source.array_suffix:
        return False
    return dwarf_type not in {"u8", "s8", "c8", "char", "unsigned char", "signed char"}


def source_type_matches_dwarf_global(source: SourceGlobal, dwarf: DwarfGlobal) -> bool:
    return normalize_type_name(source.type_name) == normalize_type_name(dwarf.type_name)


def array_suffix_matches(source_suffix: str, dwarf_suffix: str) -> bool:
    if source_suffix == dwarf_suffix:
        return True
    if not source_suffix or not dwarf_suffix:
        return False
    # Macro-sized source arrays may intentionally spell the same DWARF extent symbolically.
    if re.search(r"[A-Za-z_]", source_suffix):
        return True
    return False


def source_global_matches_dwarf(source: SourceGlobal, dwarf: DwarfGlobal) -> bool:
    return source_type_matches_dwarf_global(source, dwarf) and array_suffix_matches(source.array_suffix, dwarf.array_suffix)


def best_dwarf_global_match(source: SourceGlobal, dwarf_options: List[DwarfGlobal]) -> Optional[DwarfGlobal]:
    exact = [dwarf for dwarf in dwarf_options if source_global_matches_dwarf(source, dwarf)]
    if exact:
        return exact[0]
    type_matches = [dwarf for dwarf in dwarf_options if source_type_matches_dwarf_global(source, dwarf)]
    if type_matches:
        return type_matches[0]
    non_byte = [dwarf for dwarf in dwarf_options if normalize_type_name(dwarf.type_name) not in {"char", "unsigned char", "signed char"}]
    if non_byte:
        return non_byte[0]
    return dwarf_options[0] if dwarf_options else None


def _demangle(mangled: str) -> str:
    """Return a human-readable demangled name for a MWCC-mangled symbol."""
    if not os.path.isfile(_DTK):
        return mangled
    try:
        result = subprocess.run(
            [_DTK, "demangle", mangled],
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
            timeout=5,
        )
        out = result.stdout.strip()
        return out if out else mangled
    except Exception:
        return mangled


def _read_text_symbols(obj_path: str) -> List[str]:
    """Return all function symbol names from the .text section of an ELF object.

    Uses pure Python struct parsing — no subprocess.  Symbols ending with
    ``.NON_MATCHING`` are skipped (objdiff bookkeeping entries).
    """
    try:
        with open(obj_path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return []
    endian = ">" if data[5] == 2 else "<"
    (e_shoff,) = struct.unpack_from(endian + "I", data, 32)
    (e_shentsize,) = struct.unpack_from(endian + "H", data, 46)
    (e_shnum,) = struct.unpack_from(endian + "H", data, 48)
    (e_shstrndx,) = struct.unpack_from(endian + "H", data, 50)
    if e_shnum == 0 or e_shentsize < 40 or e_shstrndx >= e_shnum:
        return []
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + 40 > len(data):
            break
        sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, _info, _align, sh_entsize = struct.unpack_from(
            endian + "10I", data, off
        )
        sections.append(
            {
                "name": sh_name,
                "type": sh_type,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "entsize": sh_entsize,
            }
        )
    shstr_sec = sections[e_shstrndx]
    shstrtab = data[shstr_sec["offset"] : shstr_sec["offset"] + shstr_sec["size"]]

    def _sec_name(idx: int) -> str:
        try:
            end = shstrtab.index(b"\x00", idx)
            return shstrtab[idx:end].decode("utf-8", "replace")
        except (ValueError, IndexError):
            return ""

    text_indices: Set[int] = {i for i, s in enumerate(sections) if _sec_name(s["name"]) == ".text"}
    sym_sec = next((s for s in sections if s["type"] == 2), None)  # SHT_SYMTAB
    if sym_sec is None:
        return []
    strtab_sec = sections[sym_sec["link"]]
    strtab = data[strtab_sec["offset"] : strtab_sec["offset"] + strtab_sec["size"]]
    entry_size = sym_sec["entsize"] or 16
    names: List[str] = []
    for i in range(sym_sec["size"] // entry_size):
        off = sym_sec["offset"] + i * entry_size
        if off + 16 > len(data):
            break
        st_name, _value, _size, st_info, _other, st_shndx = struct.unpack_from(endian + "IIIBBH", data, off)
        if st_shndx not in text_indices:
            continue
        if (st_info & 0xF) not in (0, 2):  # STT_NOTYPE or STT_FUNC
            continue
        try:
            end = strtab.index(b"\x00", st_name)
            name = strtab[st_name:end].decode("utf-8", "replace")
        except (ValueError, IndexError):
            continue
        if name and not name.endswith(".NON_MATCHING"):
            names.append(name)
    return names


def _mangled_base_key(name: str) -> Optional[str]:
    """Extract a ``method__Nclassname`` key (no parameter encoding) from a mangled symbol.

    Returns ``None`` for global functions, operators, or symbols that cannot be
    matched by base name alone (e.g. Q-encoded nested classes).
    """
    # Strip thunk prefix (@4@...)
    if name.startswith("@"):
        at = name.find("@", 1)
        if at != -1:
            name = name[at + 1 :]
    # Must contain __ separator
    sep = name.find("__")
    if sep < 0:
        return None
    method_part = name[:sep]
    rest = name[sep + 2 :]  # everything after __
    # Skip operators (empty method part or starts with special char)
    if not method_part or method_part.startswith("op"):
        pass  # operators have names like "op+" — we keep them if they follow the pattern
    # rest must start with a digit (length-encoded class name)
    m = re.match(r"(\d+)", rest)
    if not m:
        return None  # Q-encoded nested, template specialisation, etc.
    n = int(m.group(1))
    class_start = m.end()
    class_end = class_start + n
    if class_end > len(rest):
        return None
    class_name = rest[class_start:class_end]
    suffix = rest[class_end:]
    # suffix should start with F (params) or CF (const params) or SF (static)
    if not suffix.startswith(("F", "C", "S")):
        return None
    return f"{method_part}__{m.group(1)}{class_name}"


_BOOL_MEMBER_RE = re.compile(r"^(?:m_)?b[A-Z0-9]")


def build_bool_candidate_findings(
    source_decls: Optional[Dict[str, "List[SourceDecl]"]] = None,
) -> List[BoolCandidateFinding]:
    """Return bool member candidates.

    Disabled by design: a ``m_bFoo``/``bFoo`` field name is not source-of-truth
    evidence that the member's declared type was ``bool``. DWARF frequently
    records these byte-sized fields as ``unsigned char``, while function
    signatures must be decided from mangling/objdiff evidence instead.
    """
    return []


_CXX_IN_C_HEADER_RE = re.compile(r"\b(class|public\s*:|private\s*:|protected\s*:)\b")


def build_c_header_findings() -> List[CHeaderFinding]:
    """Find C++-only syntax in known pure-C SDK headers."""
    findings: List[CHeaderFinding] = []
    for root in C_HEADER_AUDIT_ROOTS:
        for path in iter_files(root, {".h"}):
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, 1):
                    m = _CXX_IN_C_HEADER_RE.search(strip_line_comment(line))
                    if not m:
                        continue
                    findings.append(
                        CHeaderFinding(
                            path=relpath(path),
                            line=line_no,
                            token=m.group(1),
                            text=line.strip(),
                        )
                    )
    return findings


def _member_layout_signature(decl: SourceDecl) -> Tuple[Tuple[str, str, int, int], ...]:
    return tuple((member.name, normalize_type_name(member.type_name), member.offset, member.size) for member in decl.members)


def build_duplicate_layout_findings(
    source_decls: Optional[Dict[str, "List[SourceDecl]"]] = None,
) -> List[DuplicateLayoutFinding]:
    """Find same-name declarations that duplicate the exact same member layout."""
    if source_decls is None:
        source_decls = parse_source_decls()
    findings: List[DuplicateLayoutFinding] = []
    for name, decl_list in sorted(source_decls.items()):
        by_identity: Dict[Tuple[str, Tuple[Tuple[str, str, int, int], ...]], List[SourceDecl]] = {}
        for decl in decl_list:
            if decl.is_template:
                continue
            if not decl.members:
                continue
            identity = (decl.qualified_name or decl.name, _member_layout_signature(decl))
            by_identity.setdefault(identity, []).append(decl)
        for (qualified_name, layout), duplicates in by_identity.items():
            locations = sorted({f"{decl.path}:{decl.start_line}" for decl in duplicates})
            if len(locations) < 2:
                continue
            member_summary = [f"0x{offset:X} {type_name} {member_name}" for member_name, type_name, offset, _size in layout]
            findings.append(DuplicateLayoutFinding(name=qualified_name, locations=locations, members=member_summary))
    return findings


def build_lib_type_in_game_findings(
    source_decls: Optional[Dict[str, List[SourceDecl]]] = None,
) -> List[LibTypeInGameFinding]:
    if source_decls is None:
        source_decls = parse_source_decls()

    findings: List[LibTypeInGameFinding] = []
    for name, decl_list in sorted(source_decls.items()):
        if not name.startswith(SDK_TYPE_PREFIXES):
            continue
        canonical_locations = [
            f"{decl.path}:{decl.start_line}"
            for decl in decl_list
            if decl.path.startswith(SDK_INCLUDE_PREFIXES)
        ]
        for decl in decl_list:
            if not decl.path.startswith(GAME_INCLUDE_SRC_PREFIX):
                continue
            findings.append(
                LibTypeInGameFinding(
                    name=name,
                    location=f"{decl.path}:{decl.start_line}",
                    canonical_locations=canonical_locations,
                    reason="SDK/library-style type declared under game include path",
                )
            )
    return findings


def _project_source_prefix() -> str:
    return "C:" + "\\" + "Develop" + "\\" + "Projects" + "\\" + "SR2" + "\\" + "pgm" + "\\"


def _normalize_project_source_path(path: str) -> str:
    return path.replace("\\", "/")


def _add_evidence_path(paths: Dict[str, Set[str]], rel: str, evidence: str) -> None:
    rel = _normalize_project_source_path(rel.strip())
    if os.path.splitext(rel)[1] not in SOURCE_EXTS:
        return
    paths.setdefault(rel, set()).add(evidence)


def _collect_dwarf_source_paths() -> Dict[str, Set[str]]:
    paths: Dict[str, Set[str]] = {}
    prefix = _project_source_prefix()
    marker = "Compile unit: "
    if os.path.isfile(DWARF_DUMP_PATH):
        with open(DWARF_DUMP_PATH, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if marker not in line or prefix not in line:
                    continue
                path = line.split(marker, 1)[1].strip()
                if path.startswith(prefix):
                    _add_evidence_path(paths, path[len(prefix) :], "DWARF compile unit")

    if os.path.isfile(LINE_INFO_PATH):
        with open(LINE_INFO_PATH, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                idx = line.find(prefix)
                if idx < 0:
                    continue
                rest = line[idx + len(prefix) :]
                for ext in sorted(SOURCE_EXTS, key=len, reverse=True):
                    marker = ext + ":"
                    end = rest.find(marker)
                    if end >= 0:
                        _add_evidence_path(paths, rest[: end + len(ext)], "line info")
                        break

    return paths


def _collect_existing_project_source_paths() -> Set[str]:
    existing: Set[str] = set()
    roots = (
        os.path.join(ROOT_DIR, "src", "Develop", "Projects", "SR2", "pgm"),
        os.path.join(ROOT_DIR, "include", "Develop", "Projects", "SR2", "pgm"),
    )
    for root in roots:
        for path in iter_files(root, SOURCE_EXTS):
            existing.add(os.path.relpath(path, root).replace("\\", "/"))
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "src/Develop/Projects/SR2/pgm", "include/Develop/Projects/SR2/pgm"],
            cwd=ROOT_DIR,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        tracked = []
    for path in tracked:
        if os.path.splitext(path)[1] not in SOURCE_EXTS:
            continue
        for prefix in ("src/Develop/Projects/SR2/pgm/", "include/Develop/Projects/SR2/pgm/"):
            if path.startswith(prefix):
                existing.add(path[len(prefix) :])
                break
    return existing


def _source_path_exists(rel: str, existing: Set[str]) -> bool:
    if rel in existing:
        return True
    if rel.endswith(".h") and rel[:-2] + ".hpp" in existing:
        return True
    return False


def build_missing_source_path_findings() -> List[MissingSourcePathFinding]:
    """Find source paths that have DWARF/line-info evidence but no workspace file."""
    dwarf_paths = _collect_dwarf_source_paths()
    existing_paths = _collect_existing_project_source_paths()
    findings: List[MissingSourcePathFinding] = []
    for source_path, evidence in sorted(dwarf_paths.items()):
        if _source_path_exists(source_path, existing_paths):
            continue
        findings.append(MissingSourcePathFinding(source_path=source_path, evidence=sorted(evidence)))
    return findings


def load_dwarf_by_unit_summary(index_path: str = DWARF_BY_UNIT_INDEX_PATH) -> Optional[DwarfByUnitSummary]:
    """Load the optional DWARF unit-path ownership index generated from sr2_dwarfdump.nothpp."""
    if not os.path.isfile(index_path):
        return None
    try:
        with open(index_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    summary = data.get("summary", {})
    reports = data.get("reports", {})
    output_dir = os.path.dirname(index_path)
    resolved_reports: Dict[str, str] = {}
    for key, value in reports.items():
        if isinstance(value, str):
            resolved_reports[key] = relpath(os.path.join(output_dir, value))
    return DwarfByUnitSummary(
        index_path=relpath(index_path),
        generated_at=str(data.get("generated_at", "")),
        unit_blocks=int(summary.get("unit_blocks", summary.get("compile_units", 0))),
        unique_unit_paths=int(summary.get("unique_unit_paths", 0)),
        source_unit_paths=int(summary.get("source_unit_paths", 0)),
        header_unit_paths=int(summary.get("header_unit_paths", 0)),
        symbols=int(summary.get("symbols", 0)),
        unique_symbols=int(summary.get("unique_symbols", 0)),
        low_cardinality_symbols=int(summary.get("low_cardinality_symbols", 0)),
        likely_header_owner_symbols=int(summary.get("likely_header_owner_symbols", 0)),
        missing_checklist_symbols=int(summary.get("missing_checklist_symbols", 0)),
        max_shared=int(summary.get("max_shared", 0)),
        reports=resolved_reports,
    )


def load_migration_report_summary(path: str = SCAFFOLD_MIGRATION_PATH) -> Optional[MigrationReportSummary]:
    """Load the generated scaffold migration report so scaffold-audit can surface ownership rows."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return None

    generated_at = ""
    checked = ""
    total = ""
    candidate_count = 0
    rows: List[str] = []
    in_table = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Generated:"):
            generated_at = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Checked:"):
            m = re.search(r"Checked:\s*(\d+)\s+declared/defined symbol owners out of\s*(\d+)", stripped)
            if m:
                checked, total = m.group(1), m.group(2)
        elif stripped.startswith("Migration candidates:"):
            m = re.search(r"Migration candidates:\s*(\d+)", stripped)
            if m:
                candidate_count = int(m.group(1))
        elif stripped.startswith("| Status | Owner |"):
            in_table = True
            continue
        elif in_table and stripped.startswith("|:------"):
            continue
        elif in_table and stripped.startswith("| "):
            rows.append(line)
        elif in_table and not stripped:
            continue
        elif in_table:
            break

    return MigrationReportSummary(
        report_path=relpath(path),
        generated_at=generated_at,
        checked=checked,
        total=total,
        candidate_count=candidate_count,
        rows=rows,
    )


def build_sig_mismatch_findings() -> Tuple[List[SignatureMismatch], int]:
    """Compare compiled objects against reference objects for signature mismatches.

    A signature mismatch occurs when a function's base name (class + method)
    exists in both objects but the full mangled name (including parameter
    encoding) differs.  This prevents objdiff from pairing the functions and
    blocks contributors from matching them.

    Returns a list of ``SignatureMismatch`` findings and the number of units
    checked.
    """
    if not os.path.isfile(_OBJDIFF_JSON):
        return [], 0
    with open(_OBJDIFF_JSON, encoding="utf-8") as fh:
        cfg = json.load(fh)
    units = cfg.get("units", [])

    mismatches: List[SignatureMismatch] = []
    checked = 0

    for unit in units:
        target_path = unit.get("target_path", "")
        base_path = unit.get("base_path", "")
        if not target_path or not base_path:
            continue
        ref_abs = os.path.join(ROOT_DIR, target_path)
        src_abs = os.path.join(ROOT_DIR, base_path)
        if not os.path.isfile(ref_abs) or not os.path.isfile(src_abs):
            continue

        ref_syms = _read_text_symbols(ref_abs)
        compiled_syms = _read_text_symbols(src_abs)
        if not ref_syms or not compiled_syms:
            checked += 1
            continue

        checked += 1

        ref_set = set(ref_syms)
        compiled_set = set(compiled_syms)
        missing = ref_set - compiled_set  # in ref but not compiled
        extra = compiled_set - ref_set  # in compiled but not ref

        if not missing or not extra:
            continue

        # Index by base key
        missing_by_key: Dict[str, List[str]] = {}
        for sym in missing:
            key = _mangled_base_key(sym)
            if key:
                missing_by_key.setdefault(key, []).append(sym)

        extra_by_key: Dict[str, List[str]] = {}
        for sym in extra:
            key = _mangled_base_key(sym)
            if key:
                extra_by_key.setdefault(key, []).append(sym)

        shared_keys = set(missing_by_key) & set(extra_by_key)
        if not shared_keys:
            continue

        def _strip_thunk(s: str) -> str:
            return re.sub(r"^(?:@\d+@)+", "", s)

        ref_only: List[Tuple[str, str]] = []
        compiled_only: List[Tuple[str, str]] = []
        for key in sorted(shared_keys):
            ref_syms_for_key = sorted(missing_by_key[key])
            cmp_syms_for_key = sorted(extra_by_key[key])
            # Skip thunk-only mismatches: the sole difference is the @N@ prefix.
            # These represent compiler-generated this-adjusting thunks whose offset
            # depends on class layout; contributors don't write them manually.
            ref_stripped = {_strip_thunk(s) for s in ref_syms_for_key}
            cmp_stripped = {_strip_thunk(s) for s in cmp_syms_for_key}
            if ref_stripped == cmp_stripped:
                continue
            for sym in ref_syms_for_key:
                ref_only.append((sym, _demangle(sym)))
            for sym in cmp_syms_for_key:
                compiled_only.append((sym, _demangle(sym)))

        if not ref_only and not compiled_only:
            continue

        source_path = unit.get("metadata", {}).get("source_path", "")
        mismatches.append(
            SignatureMismatch(
                unit_name=unit.get("name", ""),
                source_path=source_path,
                ref_only=ref_only,
                compiled_only=compiled_only,
            )
        )

    return mismatches, checked


def build_return_type_mismatch_findings(
    source_decls: Optional[Dict[str, List[SourceDecl]]] = None,
) -> List[ReturnTypeMismatch]:
    """Compare source method return declarations with DWARF function records.

    Return types are not encoded in ordinary C++ mangled names, so objdiff symbol
    comparison cannot catch source declarations such as ``s32`` where DWARF says
    ``enum Foo``.  Use symbol_addrs addresses to pair class methods with DWARF
    function records.
    """
    if source_decls is None:
        source_decls = parse_source_decls()

    source_returns = parse_source_method_returns(source_decls)
    dwarf_returns = parse_dwarf_function_returns(DWARF_FUNCTIONS_PATH)
    symbol_methods = parse_symbol_methods(SYMBOL_ADDRS_PATH, set(source_decls))
    findings: List[ReturnTypeMismatch] = []

    for class_name, methods in sorted(symbol_methods.items()):
        for method in methods:
            if method.address is None:
                continue
            dwarf_return = dwarf_returns.get(method.address)
            if not dwarf_return:
                continue
            if dwarf_return == "(ctor/dtor)":
                continue
            sources = source_returns.get((class_name, method.method_name), [])
            demangled_sig = parse_demangled_method_signature(_demangle(method.mangled))
            if demangled_sig is not None:
                _name, params, is_const = demangled_sig
                matched_sources = [src for src in sources if src.param_types == params and src.is_const == is_const]
                if matched_sources:
                    sources = matched_sources
                elif len(sources) > 1:
                    # Do not guess among overloads; a false-positive row is worse than a missing candidate.
                    continue
            if not sources:
                continue
            if any(normalize_type_name(src.return_type) == normalize_type_name(dwarf_return) for src in sources):
                continue
            for src in sources:
                findings.append(
                    ReturnTypeMismatch(
                        class_name=class_name,
                        method_name=method.method_name,
                        path=f"{src.path}:{src.line}",
                        source_return=src.return_type,
                        dwarf_return=dwarf_return,
                        mangled=method.mangled,
                        address=method.address,
                    )
                )

    return findings


def build_findings() -> Tuple[List[Finding], List[TemplateVariantFinding], int, int]:
    dwarf_structs = parse_dwarf_structs(DWARF_GLOBALS_PATH)
    dwarf_variants = parse_dwarf_struct_variants(DWARF_GLOBALS_PATH)
    dwarf_globals = parse_dwarf_globals(DWARF_GLOBALS_PATH)
    source_decls = parse_source_decls()
    source_typedefs = parse_source_typedefs()
    source_globals = parse_source_globals()
    symbol_methods = parse_symbol_methods(SYMBOL_ADDRS_PATH, set(dwarf_structs) | set(source_decls))
    source_method_defs = parse_source_method_defs()
    skip_listed = parse_skip_list(SCAFFOLD_SKIP_PATH)
    symbols = symbol_text(SYMBOL_ADDRS_PATH)
    findings: List[Finding] = []

    findings.extend(build_duplicate_definition_findings(source_decls))

    for typedef in source_typedefs:
        if typedef.name in skip_listed:
            continue
        if typedef.name in dwarf_structs or typedef.name in symbols:
            continue
        findings.append(
            Finding(
                class_name=typedef.name,
                path=f"{typedef.path}:{typedef.line}",
                reasons=["source-only project typedef"],
                details=(
                    f"Typedef target is `{typedef.target}`, but `{typedef.name}` has no DWARF struct/global or symbol_addrs evidence. "
                    "Prefer the evidence-backed type instead of inventing a project-style alias."
                ),
            )
        )

    for source_global in source_globals:
        dwarf_options = dwarf_globals.get(source_global.name, [])
        if any(source_global_matches_dwarf(source_global, dwarf_global) for dwarf_global in dwarf_options):
            continue
        dwarf_global = best_dwarf_global_match(source_global, dwarf_options)
        if not dwarf_global:
            continue
        if is_byte_placeholder_global(source_global, dwarf_global):
            findings.append(
                Finding(
                    class_name=source_global.name,
                    path=f"{source_global.path}:{source_global.line}",
                    reasons=["byte-array global placeholder"],
                    details=(
                        f"Source declares `{source_global.type_name} {source_global.name}{source_global.array_suffix}`; "
                        f"DWARF fixed-address global is `{dwarf_global.type_name} {dwarf_global.name}{dwarf_global.array_suffix}` "
                        f"at 0x{dwarf_global.address:X}, size 0x{dwarf_global.size:X}."
                    ),
                )
            )
        elif not source_global_matches_dwarf(source_global, dwarf_global):
            findings.append(
                Finding(
                    class_name=source_global.name,
                    path=f"{source_global.path}:{source_global.line}",
                    reasons=["global declaration differs from DWARF"],
                    details=(
                        f"Source declares `{source_global.type_name} {source_global.name}{source_global.array_suffix}`; "
                        f"DWARF fixed-address global is `{dwarf_global.type_name} {dwarf_global.name}{dwarf_global.array_suffix}` "
                        f"at 0x{dwarf_global.address:X}, size 0x{dwarf_global.size:X}."
                    ),
                )
            )

    for name in sorted(dwarf_structs):
        if name in skip_listed:
            continue
        if not should_audit_dwarf_struct(name, source_decls):
            continue
        dwarf = choose_dwarf_struct(dwarf_variants.get(name, [dwarf_structs[name]]), None)
        if not dwarf.members and dwarf.size <= 4:
            continue

        decl_list = source_decls.get(name, [])
        if not decl_list:
            findings.append(
                Finding(
                    class_name=name,
                    path=None,
                    reasons=["missing declaration"],
                    details=f"DWARF has {len(dwarf.members)} member(s), size 0x{dwarf.size:X}.",
                )
            )
            continue

        if any(decl.is_template for decl in decl_list):
            continue

        for decl in decl_list:
            dwarf = choose_dwarf_struct(dwarf_variants.get(name, [dwarf_structs[name]]), decl)
            variants = dwarf_variants.get(name, [dwarf_structs[name]])
            if is_known_flattened_stl_container(name, decl, variants):
                continue
            if has_plain_sdk_member_body(decl):
                continue
            if not decl.members and has_plain_member_body(decl) and any(other.members for other in decl_list if other is not decl):
                continue
            if source_union_matches_dwarf(decl, dwarf):
                continue
            parent_member_size = find_parent_member_size(dwarf_variants, decl)
            reasons: List[str] = []
            details: List[str] = []
            if decl.has_commented_body:
                reasons.append("commented-out body nearby")
            if body_is_empty(decl) and dwarf.members:
                reasons.append("empty body")
            if is_gap_only(decl) and any(not member_is_gap(member) for member in dwarf.members):
                reasons.append("gap-only body")

            if dwarf.members and not decl.members:
                reasons.append("missing DWARF members")
                details.append(
                    f"Source declares no data members; DWARF has {len(dwarf.members)} named member(s), size 0x{dwarf.size:X}."
                )

            byte_placeholder = byte_buffer_placeholder(decl)
            if byte_placeholder and (dwarf.members or dwarf.size > 1) and not byte_buffer_matches_dwarf(dwarf, decl):
                reasons.append("byte-buffer struct placeholder")
                if dwarf.members:
                    details.append(
                        f"Source only declares `{byte_placeholder}`; DWARF has {len(dwarf.members)} named member(s), size 0x{dwarf.size:X}."
                    )
                else:
                    details.append(
                        f"Source only declares `{byte_placeholder}`; DWARF has a non-empty {dwarf.kind}, size 0x{dwarf.size:X}."
                    )

            missing = missing_offsets_within_size(dwarf, decl, parent_member_size)
            if missing and decl.members:
                reasons.append("missing DWARF member offsets")
                shown = ", ".join(missing[:8])
                if len(missing) > 8:
                    shown += f", +{len(missing) - 8} more"
                details.append(f"Missing offsets: {shown}.")

            extra_members = source_members_outside_selected_layout(
                dwarf,
                decl,
                parent_member_size,
                variants,
            )
            extra_member_decls = source_only_declarations(dwarf, decl)
            if extra_members or extra_member_decls:
                reasons.append("source members outside selected DWARF layout")
                combined_members = extra_members + extra_member_decls
                shown = ", ".join(combined_members[:8])
                if len(combined_members) > 8:
                    shown += f", +{len(combined_members) - 8} more"
                details.append(f"Members not present in selected DWARF layout: {shown}.")

            extra_gaps = source_only_gap_members(
                dwarf,
                decl,
                parent_member_size,
                variants,
            )
            extra_gap_decls = source_only_gap_declarations(dwarf, decl)
            if extra_gaps or extra_gap_decls:
                reasons.append("source-only gap members")
                combined_gaps = extra_gaps + extra_gap_decls
                shown = ", ".join(combined_gaps[:8])
                if len(combined_gaps) > 8:
                    shown += f", +{len(combined_gaps) - 8} more"
                details.append(f"Gap/padding members not present in DWARF: {shown}.")

            erased = enum_erased_members(dwarf, decl)
            if erased:
                reasons.append("enum members declared as scalar")
                shown = ", ".join(erased[:8])
                if len(erased) > 8:
                    shown += f", +{len(erased) - 8} more"
                details.append(f"Enum-erased members: {shown}.")

            if (
                dwarf.members
                and decl.members
                and dwarf.last_member_offset > decl.last_member_offset
                and (parent_member_size is None or dwarf.last_member_offset < parent_member_size)
            ):
                reasons.append("source body ends before DWARF layout")
                details.append(
                    f"Source last member offset is 0x{decl.last_member_offset:X}; DWARF last member offset is 0x{dwarf.last_member_offset:X}."
                )

            owned_methods = symbol_methods.get(name, [])
            if owned_methods:
                owned_names = {method.method_name for method in owned_methods}
                missing_decls = sorted(owned_names - decl.methods)
                if missing_decls:
                    reasons.append("missing method declarations")
                    shown = ", ".join(missing_decls[:8])
                    if len(missing_decls) > 8:
                        shown += f", +{len(missing_decls) - 8} more"
                    details.append(f"Missing method declarations: {shown}.")

                source_defs = source_method_defs.get(name, set())
                required_defs = {
                    method.method_name
                    for method in owned_methods
                    if not method.is_weak
                    and method.method_name in decl.methods
                    and method.method_name not in decl.inline_methods
                }
                missing_defs = sorted(required_defs - source_defs)
                if missing_defs:
                    reasons.append("missing method definitions")
                    shown = ", ".join(missing_defs[:8])
                    if len(missing_defs) > 8:
                        shown += f", +{len(missing_defs) - 8} more"
                    details.append(f"Missing source definitions: {shown}.")

            if reasons:
                if not details:
                    details.append(f"DWARF has {len(dwarf.members)} member(s), size 0x{dwarf.size:X}.")
                findings.append(
                    Finding(
                        class_name=name,
                        path=f"{decl.path}:{decl.start_line}",
                        reasons=reasons,
                        details=" ".join(details),
                    )
                )

    template_variant_findings = build_template_variant_findings(dwarf_variants, source_decls)
    template_variant_findings.extend(
        build_template_owner_findings(
            parse_symbol_template_owners(SYMBOL_ADDRS_PATH),
            source_decls,
            dwarf_variants,
        )
    )
    declared_count = len(source_decls) + len({typedef.name for typedef in source_typedefs})
    return findings, template_variant_findings, declared_count, len(dwarf_structs)


def md_text(value: Optional[str]) -> str:
    if not value:
        return ""
    return f"`{value}`"


def split_location(value: str) -> Tuple[str, int]:
    m = re.match(r"^(?P<path>.*):(?P<line>\d+)$", value)
    if not m:
        return value, 0
    return m.group("path"), int(m.group("line"))


def write_report(
    path: str,
    findings: Sequence[Finding],
    template_variant_findings: Sequence[TemplateVariantFinding],
    declared: int,
    dwarf_total: int,
    sig_mismatches: Optional[Sequence[SignatureMismatch]] = None,
    checked_units: int = 0,
    return_type_mismatches: Optional[Sequence[ReturnTypeMismatch]] = None,
    bool_candidates: Optional[Sequence[BoolCandidateFinding]] = None,
    c_header_findings: Optional[Sequence[CHeaderFinding]] = None,
    duplicate_layout_findings: Optional[Sequence[DuplicateLayoutFinding]] = None,
    duplicate_namespace_global_findings: Optional[Sequence[DuplicateNamespaceGlobalFinding]] = None,
    lib_type_in_game_findings: Optional[Sequence[LibTypeInGameFinding]] = None,
    missing_source_path_findings: Optional[Sequence[MissingSourcePathFinding]] = None,
    dwarf_by_unit_summary: Optional[DwarfByUnitSummary] = None,
    migration_report_summary: Optional[MigrationReportSummary] = None,
    unqualified_global_owner_findings: Optional[Sequence[UnqualifiedGlobalOwnerFinding]] = None,
) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    today = datetime.date.today().isoformat()
    lines: List[str] = []
    lines.append("# Scaffold Audit Candidates\n\n")
    lines.append(f"Generated: {today}\n\n")
    lines.append("Regenerate with: `python tools/decomp-workflow.py scaffold-audit`\n\n")
    lines.append(
        "This report compares active headers against DWARF structs from "
        "`symbols/Dwarf/globals.nothpp` and class-owned methods from "
        "`symbol_addrs.txt`. Treat every row as a manual validation "
        "candidate; confirm with `tools/find-symbol.py`, `tools/lookup.py`, and "
        "scaffold output before editing declarations.\n\n"
    )
    lines.append(f"DWARF structs scanned: {dwarf_total}\n\n")
    lines.append(f"Declared names scanned: {declared}\n\n")
    lines.append(f"Audit candidates: {len(findings)}\n\n")

    if not findings:
        lines.append("No scaffold audit candidates found.\n")
    else:
        lines.append("| Status | Class | Location | Reason | Details |\n")
        lines.append("|:------:|-------|----------|--------|---------|\n")
        for finding in findings:
            lines.append(
                "| [ ] "
                f"| `{finding.class_name}` "
                f"| {md_text(finding.path)} "
                f"| {', '.join(finding.reasons)} "
                f"| {finding.details} |\n"
            )

    lines.append("\n## Template-Like Candidates\n\n")
    lines.append(
        "These are review candidates for flattened template or generic types from DWARF variants "
        "and template-owned symbols in `symbol_addrs.txt`. "
        "They are not scaffold failures; inspect each before replacing concrete declarations with templates.\n\n"
    )
    lines.append(f"Template-like candidates: {len(template_variant_findings)}\n\n")
    if not template_variant_findings:
        lines.append("No template-like DWARF variant candidates found.\n")
    else:
        lines.append("| Status | Class | Location(s) | Reason | Variants |\n")
        lines.append("|:------:|-------|-------------|--------|----------|\n")
        for finding in template_variant_findings:
            locations = ", ".join(md_text(location) for location in finding.locations)
            lines.append(
                "| [ ] "
                f"| `{finding.class_name}` "
                f"| {locations} "
                f"| {finding.reason} "
                f"| {finding.details} |\n"
            )

    lines.append("\n## Signature Mismatches\n\n")
    lines.append(
        "These units have functions whose base name (class + method) exists in both the reference "
        "object and the compiled object, but with different parameter signatures.  "
        "objdiff cannot pair them, so contributors cannot match these functions until the "
        "C++ declaration is corrected to match the reference signature.\n\n"
    )
    sm_list = sig_mismatches or []
    lines.append(f"Units with signature mismatches: {len(sm_list)} / {checked_units} checked\n\n")
    if not sm_list:
        lines.append("No signature mismatches detected.\n")
    else:
        lines.append("| Status | Unit | Source | Reference signature | Compiled signature |\n")
        lines.append("|:------:|------|--------|---------------------|--------------------|\n")
        for sm in sm_list:
            src_col = md_text(sm.source_path) if sm.source_path else ""
            ref_sigs = "<br>".join(f"`{d}`" for _, d in sm.ref_only)
            cmp_sigs = "<br>".join(f"`{d}`" for _, d in sm.compiled_only)
            lines.append(
                "| [ ] "
                f"| `{sm.unit_name}` "
                f"| {src_col} "
                f"| {ref_sigs} "
                f"| {cmp_sigs} |\n"
            )

    lines.append("\n## Return Type Mismatches\n\n")
    lines.append(
        "These methods have source declarations whose return type differs from the DWARF function record. "
        "Return types are usually not encoded in the mangled symbol, so these issues may not appear in "
        "the objdiff signature mismatch section. Confirm each row with `tools/lookup.py` before editing.\n\n"
    )
    rt_list = return_type_mismatches or []
    lines.append(f"Return type mismatches: {len(rt_list)}\n\n")
    if not rt_list:
        lines.append("No return type mismatches detected.\n")
    else:
        by_file: Dict[str, List[Tuple[int, ReturnTypeMismatch]]] = {}
        for rt in rt_list:
            file_path, line_no = split_location(rt.path)
            by_file.setdefault(file_path, []).append((line_no, rt))
        lines.append(f"Files with return type mismatches: {len(by_file)}\n")
        for file_path in sorted(by_file):
            rows = sorted(by_file[file_path], key=lambda row: (row[0], row[1].class_name, row[1].method_name, row[1].mangled))
            lines.append(f"\n### `{file_path}` ({len(rows)})\n\n")
            lines.append("| Status | Line | Class | Method | Source return | DWARF return | Symbol |\n")
            lines.append("|:------:|-----:|-------|--------|---------------|--------------|--------|\n")
            for line_no, rt in rows:
                line_col = f"`{line_no}`" if line_no else ""
                lines.append(
                    "| [ ] "
                    f"| {line_col} "
                    f"| `{rt.class_name}` "
                    f"| `{rt.method_name}` "
                    f"| `{display_type_name(rt.source_return)}` "
                    f"| `{display_type_name(rt.dwarf_return)}` "
                    f"| `{rt.mangled}` @ `0x{rt.address:X}` |\n"
                )

    lines.append("\n## Bool Candidate Members\n\n")
    lines.append(
        "Field names such as `m_bFoo` or `bFoo` are not enough evidence to change a member "
        "from `u8` to `bool`. Keep DWARF-sourced byte fields as `u8`; use reference mangling "
        "and objdiff signature mismatches only for function parameter/return types.\n\n"
    )
    bc_list = bool_candidates or []
    lines.append(f"Bool candidate classes: {len(bc_list)}\n\n")
    if not bc_list:
        lines.append("No bool candidate members found.\n")
    else:
        lines.append("| Status | Class | Location | Members |\n")
        lines.append("|:------:|-------|----------|---------|\n")
        for bc in bc_list:
            members_col = ", ".join(f"`{m}`" for m in bc.members)
            lines.append(
                "| [ ] "
                f"| `{bc.class_name}` "
                f"| {md_text(bc.path)} "
                f"| {members_col} |\n"
            )

    lines.append("\n## C Header Candidates\n\n")
    lines.append(
        "Known pure-C SDK headers under `include/usr/local/{sega,cri,sce}` must not use "
        "C++-only syntax such as `class` declarations or access specifiers. Use `struct` "
        "and C-compatible declarations instead.\n\n"
    )
    ch_list = c_header_findings or []
    lines.append(f"C header candidates: {len(ch_list)}\n\n")
    if not ch_list:
        lines.append("No C header C++ syntax candidates found.\n")
    else:
        lines.append("| Status | Location | Token | Line |\n")
        lines.append("|:------:|----------|-------|------|\n")
        for finding in ch_list:
            lines.append(
                "| [ ] "
                f"| {md_text(f'{finding.path}:{finding.line}')} "
                f"| `{finding.token}` "
                f"| `{md_text(finding.text)}` |\n"
            )

    lines.append("\n## Duplicate Layout Candidates\n\n")
    lines.append(
        "These are same-name declarations that repeat the exact same parsed member layout in "
        "multiple places. Same-name structs can be legitimate when their layouts differ, so this "
        "section only reports identical member layouts as likely duplicated declarations to review.\n\n"
    )
    dl_list = duplicate_layout_findings or []
    lines.append(f"Duplicate layout candidates: {len(dl_list)}\n\n")
    if not dl_list:
        lines.append("No duplicate same-name layout candidates found.\n")
    else:
        lines.append("| Status | Name | Locations | Members |\n")
        lines.append("|:------:|------|-----------|---------|\n")
        for finding in dl_list:
            locations = "<br>".join(md_text(location) for location in finding.locations)
            members = "<br>".join(f"`{md_text(member)}`" for member in finding.members[:12])
            if len(finding.members) > 12:
                members += f"<br>... {len(finding.members) - 12} more"
            lines.append(
                "| [ ] "
                f"| `{finding.name}` "
                f"| {locations} "
                f"| {members} |\n"
            )

    lines.append("\n## Duplicate Namespace Globals\n\n")
    lines.append(
        "These are repeated extern declarations for the same qualified namespace/global symbol. "
        "Repeated namespace blocks are fine; repeated globals usually mean one header should own the declaration.\n\n"
    )
    dng_list = duplicate_namespace_global_findings or []
    lines.append(f"Duplicate namespace globals: {len(dng_list)}\n\n")
    if not dng_list:
        lines.append("No duplicate namespace global declarations found.\n")
    else:
        lines.append("| Status | Declaration | Locations |\n")
        lines.append("|:------:|-------------|-----------|\n")
        for finding in dng_list:
            locations = "<br>".join(md_text(location) for location in finding.locations)
            lines.append(f"| [ ] | `{md_text(finding.declaration)}` | {locations} |\n")

    lines.append("\n## SDK Types Declared In Game Headers\n\n")
    lines.append(
        "These are SDK/library-style type declarations, such as `NNS_*`, `NVS_*`, `PXS_*`, or `Mwsfd*`, "
        "that currently live under `include/Develop/Projects/SR2/pgm/src/`. They may be legitimate temporary "
        "scaffold dependencies, but prefer canonical SDK/lib headers when evidence supports moving them.\n\n"
    )
    ltg_list = lib_type_in_game_findings or []
    lines.append(f"SDK types in game headers: {len(ltg_list)}\n\n")
    if not ltg_list:
        lines.append("No SDK/library-style type declarations found in game headers.\n")
    else:
        lines.append("| Status | Type | Location | Canonical SDK Location(s) | Reason |\n")
        lines.append("|:------:|------|----------|----------------------------|--------|\n")
        for finding in ltg_list:
            canonical = "<br>".join(md_text(location) for location in finding.canonical_locations)
            lines.append(
                "| [ ] "
                f"| `{finding.name}` "
                f"| {md_text(finding.location)} "
                f"| {canonical} "
                f"| {finding.reason} |\n"
            )

    lines.append("\n## Missing Source Path Candidates\n\n")
    lines.append(
        "These paths appear in DWARF compile-unit records or source line-info, but no matching "
        "file exists under `src/Develop/Projects/SR2/pgm` or `include/Develop/Projects/SR2/pgm`. "
        "A `.h` path is considered covered by an existing `.hpp` file with the same stem. "
        "Treat these as future scaffold or data TU coverage candidates, not automatic create/delete instructions.\n\n"
    )
    msp_list = missing_source_path_findings or []
    lines.append(f"Missing source path candidates: {len(msp_list)}\n\n")
    if not msp_list:
        lines.append("No missing DWARF/line-info source path candidates found.\n")
    else:
        lines.append("| Status | Source Path | Evidence |\n")
        lines.append("|:------:|-------------|----------|\n")
        for finding in msp_list:
            evidence = ", ".join(finding.evidence)
            lines.append(f"| [ ] | `{finding.source_path}` | {evidence} |\n")

    lines.append("\n## Unqualified Globals With Qualified Owners\n\n")
    lines.append(
        "These are file-scope or extern global declarations that are unqualified in current source, "
        "but `symbol_addrs.txt` only has class/namespace-owned forms for the same name. "
        "They are warning-only ownership review candidates; confirm with DWARF and objdiff before editing.\n\n"
    )
    ug_list = unqualified_global_owner_findings or []
    lines.append(f"Unqualified global owner candidates: {len(ug_list)}\n\n")
    if not ug_list:
        lines.append("No suspicious unqualified globals with qualified owners found.\n")
    else:
        lines.append("| Status | Location | Declaration | Owner Candidate(s) | Reason |\n")
        lines.append("|:------:|----------|-------------|--------------------|--------|\n")
        for finding in ug_list:
            owners = "<br>".join(f"`{owner}`" for owner in finding.owner_candidates)
            lines.append(
                "| [ ] "
                f"| {md_text(finding.location)} "
                f"| {md_text(finding.declaration)} "
                f"| {owners} "
                f"| {finding.reason} |\n"
            )

    lines.append("\n## Scaffold Migration Candidates\n\n")
    lines.append(
        "These rows come from `docs/scaffold-migration.md`, which compares current class/source "
        "locations against canonical ownership derived from `symbol_addrs.txt` and line-info. "
        "They are ownership review candidates, not automatic move instructions.\n\n"
    )
    if migration_report_summary is None:
        lines.append(
            "No generated migration report found. Run `python tools/scaffold-migration.py` "
            "before regenerating this audit to include migration candidates.\n"
        )
    else:
        lines.append(f"Report: `{migration_report_summary.report_path}`\n\n")
        if migration_report_summary.generated_at:
            lines.append(f"Report generated: {migration_report_summary.generated_at}\n\n")
        if migration_report_summary.checked and migration_report_summary.total:
            lines.append(
                f"Checked: {migration_report_summary.checked} declared/defined symbol owners out of "
                f"{migration_report_summary.total}.\n\n"
            )
        lines.append(f"Migration candidates: {migration_report_summary.candidate_count}\n\n")
        if not migration_report_summary.rows:
            lines.append("No scaffold migration candidates found.\n")
        else:
            lines.append("| Status | Owner | Expected Header | Actual Header(s) | Expected Source | Actual Source(s) | Reason |\n")
            lines.append("|:------:|-------|-----------------|------------------|-----------------|------------------|--------|\n")
            lines.extend(migration_report_summary.rows)

    lines.append("\n## DWARF Unit-Path Ownership Index\n\n")
    lines.append(
        "This optional index is generated directly from `symbols/sr2_dwarfdump.nothpp` by "
        "`python tools/split_dwarf_by_unit.py`. It splits raw DWARF content per unit block and "
        "reports unique, low-cardinality, and likely header-owned symbols as review evidence only.\n\n"
    )
    if dwarf_by_unit_summary is None:
        lines.append(
            "No DWARF unit-path ownership index found. Run `python tools/split_dwarf_by_unit.py` "
            "to generate `symbols/DwarfByUnit/index.json` and the companion reports.\n"
        )
    else:
        lines.append(f"Index: `{dwarf_by_unit_summary.index_path}`\n\n")
        if dwarf_by_unit_summary.generated_at:
            lines.append(f"Index generated: {dwarf_by_unit_summary.generated_at}\n\n")
        lines.append("| Metric | Count |\n")
        lines.append("|--------|------:|\n")
        lines.append(f"| DWARF unit blocks | {dwarf_by_unit_summary.unit_blocks} |\n")
        lines.append(f"| Unique unit paths | {dwarf_by_unit_summary.unique_unit_paths} |\n")
        lines.append(f"| Unique source paths | {dwarf_by_unit_summary.source_unit_paths} |\n")
        lines.append(f"| Unique header paths | {dwarf_by_unit_summary.header_unit_paths} |\n")
        lines.append(f"| Indexed symbols | {dwarf_by_unit_summary.symbols} |\n")
        lines.append(f"| Unique symbols | {dwarf_by_unit_summary.unique_symbols} |\n")
        lines.append(
            f"| Symbols in 2..{dwarf_by_unit_summary.max_shared} unique unit paths | "
            f"{dwarf_by_unit_summary.low_cardinality_symbols} |\n"
        )
        lines.append(f"| Likely header owner symbols | {dwarf_by_unit_summary.likely_header_owner_symbols} |\n")
        lines.append(f"| Missing checklist symbols | {dwarf_by_unit_summary.missing_checklist_symbols} |\n")
        if dwarf_by_unit_summary.reports:
            report_links = ", ".join(f"`{path}`" for path in sorted(dwarf_by_unit_summary.reports.values()))
            lines.append(f"\nReports: {report_links}\n")

    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=os.path.join(ROOT_DIR, "docs", "scaffold-audit.md"),
        help="Report path (default: docs/scaffold-audit.md)",
    )
    args = parser.parse_args()

    findings, template_variant_findings, declared, dwarf_total = build_findings()
    sig_mismatches, checked_units = build_sig_mismatch_findings()
    return_type_mismatches = build_return_type_mismatch_findings()
    bool_candidates = build_bool_candidate_findings()
    c_header_findings = build_c_header_findings()
    duplicate_layout_findings = build_duplicate_layout_findings()
    duplicate_namespace_global_findings = build_duplicate_namespace_global_findings()
    lib_type_in_game_findings = build_lib_type_in_game_findings()
    missing_source_path_findings = build_missing_source_path_findings()
    unqualified_global_owner_findings = build_unqualified_global_owner_findings()
    dwarf_by_unit_summary = load_dwarf_by_unit_summary()
    migration_report_summary = load_migration_report_summary()
    write_report(
        args.output, findings, template_variant_findings, declared, dwarf_total,
        sig_mismatches, checked_units, return_type_mismatches, bool_candidates, c_header_findings,
        duplicate_layout_findings, duplicate_namespace_global_findings, lib_type_in_game_findings,
        missing_source_path_findings, dwarf_by_unit_summary, migration_report_summary,
        unqualified_global_owner_findings,
    )
    print(f"Wrote {len(findings)} scaffold audit candidates to {relpath(args.output)}")
    print(f"Wrote {len(template_variant_findings)} template-like candidates")
    print(f"Scanned {dwarf_total} DWARF structs and {declared} declared names")
    print(f"Signature mismatches: {len(sig_mismatches)} units affected ({checked_units} units checked)")
    print(f"Return type mismatches: {len(return_type_mismatches)}")
    print(f"Bool candidate members: {len(bool_candidates)} classes")
    print(f"C header candidates: {len(c_header_findings)}")
    print(f"Duplicate layout candidates: {len(duplicate_layout_findings)}")
    print(f"Duplicate namespace globals: {len(duplicate_namespace_global_findings)}")
    print(f"SDK types in game headers: {len(lib_type_in_game_findings)}")
    print(f"Missing source path candidates: {len(missing_source_path_findings)}")
    print(f"Unqualified global owner candidates: {len(unqualified_global_owner_findings)}")
    if migration_report_summary is None:
        print("Scaffold migration candidates: report not generated")
    else:
        print(f"Scaffold migration candidates: {migration_report_summary.candidate_count}")
    if dwarf_by_unit_summary is None:
        print("DWARF unit-path ownership index: not generated")
    else:
        print(f"DWARF unit-path ownership index: {dwarf_by_unit_summary.symbols} symbols")


if __name__ == "__main__":
    main()
