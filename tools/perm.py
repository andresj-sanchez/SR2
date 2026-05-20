#!/usr/bin/env python3
"""
perm.py — C++ line permuter for decompilation matching.

Permutes lines within // PERM_BEGIN / // PERM_END marker regions in a source
file, respecting data dependencies, compiling and scoring each permutation.

Usage:
  python tools/perm.py \\
      -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp \\
      -d "clsPrfm::setup" \\
      [--top 10] [--dry-run] [--max-trials N] [--apply-best] \\
      [--float-temps] [--guided]

Add markers to your source file to mark permutable regions:

    // PERM_BEGIN base
    this->m_sBase.f32Speed[0] = f32AdjustSpeedRate * rcBase.f32Speed[0];
    this->m_sBase.f32Accele[0] = f32AdjustCurveRate * rcBase.f32Accele[0];
    ...
    // PERM_END

--float-temps:
  For eligible lines of the form  `this->dst = rate * src->field;`  inside a
  PERM region, the permuter randomly chooses one of three forms each trial:

    Form 0 — no split (original):
        this->dst = rate * src->field;

    Form 1 — whole-RHS temp:
        float fVarN = rate * src->field;
        this->dst   = fVarN;

    Form 2 — field-load temp (matches 89.37% pattern):
        float fVarN = src->field;
        this->dst   = rate * fVarN;

  Form 2 is the key pattern: it extracts the field load into a separate line
  that the permuter can then hoist earlier, forcing multiple FP registers live
  simultaneously (the ft0/fv1/fv0 pattern seen in the target assembly).

--guided:
  Simulated annealing: mutate from the current best result instead of always
  starting from scratch.  Worse results are sometimes accepted on purpose
  (probability decreases as the search progresses) so the search can escape
  local maxima and find better regions.  Temperature starts at 2.0 and cools
  by 0.5% each trial.

Extra mutations (always active, probability-weighted):
  - refer_to_var:   Insert  if (var) {}  dummy reference after a line that
                    defines a local var. Forces the compiler to keep the value
                    live in a register longer, shifting register allocation.
  - self_assign:    Insert  var = var;  no-op after a definition. Same effect
                    as refer_to_var but via an assignment rather than a branch.
  - ins_block:      Wrap a contiguous run of lines in  if (1) { }  or
                    do { } while (0).  Changes scope/control flow structure
                    which can affect how MWCC allocates FP registers.
  - commutative:    For lines with  a * b  or  a + b , randomly swap operands
                    to  b * a  /  b + a .  MWCC may use different registers
                    depending on evaluation order.
  - pad_var_decl:   Insert an unused  float fPadN = 0.0f;  declaration.
                    Shifts stack layout and register pressure.
"""

import argparse
import copy
import itertools
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import random as _rng
from typing import Dict, List, Optional, Set, Tuple

script_dir = os.path.dirname(os.path.realpath(__file__))
root_dir = os.path.abspath(os.path.join(script_dir, ".."))

EXE = ".exe" if sys.platform == "win32" else ""
_default_cli = os.path.join(root_dir, "build", "tools", f"objdiff-cli{EXE}")
OBJDIFF_CLI = os.environ.get("OBJDIFF_CLI", _default_cli)

_MWCC_VERSION = "PS2/mwcps2-3.0.1b198-051011"
_MWCC_EXE = os.path.join(root_dir, "build", "compilers",
                         _MWCC_VERSION.replace("/", os.sep), f"mwccps2{EXE}")
_MWCC_CFLAGS = [
    "-lang=c++", "-O3,p", "-sdatathreshold", "0",
    "-i", "include",
    "-DBUILD_VERSION=0", "-DNDEBUG=1",
]


# ─── Region parsing ───────────────────────────────────────────────────────────

_PERM_ATOM_TAG = "\x00PERM_ATOM\x00"  # sentinel prefix for atom entries


def _collect_content(lines: List[str], start: int) -> Tuple[List[str], int]:
    """
    Consume lines from start up to (but not including) the next PERM_END.
    Lines wrapped in PERM_ATOM / PERM_ATOM_END are joined into a single
    entry tagged with _PERM_ATOM_TAG so the topo-sort treats them as one
    indivisible unit.
    Returns (content_list, index_of_PERM_END_line).
    """
    content: List[str] = []
    i = start
    while i < len(lines):
        if re.search(r'//\s*PERM_END', lines[i]):
            return content, i
        if re.search(r'//\s*PERM_ATOM\b', lines[i]):
            atom_lines: List[str] = []
            i += 1
            while i < len(lines):
                if re.search(r'//\s*PERM_ATOM_END', lines[i]):
                    break
                atom_lines.append(lines[i])
                i += 1
            # Join into one "super-line" with sentinel prefix
            content.append(_PERM_ATOM_TAG + "".join(atom_lines))
        else:
            content.append(lines[i])
        i += 1
    return content, i  # ran off end (malformed markers)


def parse_regions(lines: List[str]):
    """
    Parse PERM_BEGIN/PERM_END regions from lines.

    Returns a list of region tuples:
        (begin_idx, end_idx, name, content, grouped)

    begin_idx : line index of the PERM_BEGIN (or PERM_GROUP) marker
    end_idx   : line index of the final PERM_END marker
    name      : region label
    content   : list of source lines inside the region(s).
                Lines wrapped in PERM_ATOM/PERM_ATOM_END are stored as a
                single joined entry (prefixed with _PERM_ATOM_TAG) so the
                topo-sort moves them as one unit.
    grouped   : True if created by merging blocks under PERM_GROUP

    PERM_GROUP merges adjacent PERM_BEGIN/PERM_END blocks (and any
    PERM_ATOM blocks between them) into one flat pool for the topo-sort,
    allowing lines to cross region boundaries.
    """
    regions = []
    i = 0
    while i < len(lines):
        # ── PERM_GROUP ────────────────────────────────────────────────────────
        if re.search(r'//\s*PERM_GROUP\b', lines[i]):
            group_begin = i
            group_name = f"group{len(regions)}"
            group_content: List[str] = []
            group_end = i
            i += 1
            while i < len(lines):
                stripped = lines[i].strip()
                if not stripped:
                    i += 1
                    continue
                if re.search(r'//\s*PERM_BEGIN\b', lines[i]):
                    sub_content, end_idx = _collect_content(lines, i + 1)
                    group_content.extend(sub_content)
                    group_end = end_idx
                    i = end_idx + 1
                elif re.search(r'//\s*PERM_ATOM\b', lines[i]):
                    atom_lines: List[str] = []
                    i += 1
                    while i < len(lines):
                        if re.search(r'//\s*PERM_ATOM_END', lines[i]):
                            break
                        atom_lines.append(lines[i])
                        i += 1
                    group_content.append(_PERM_ATOM_TAG + "".join(atom_lines))
                    group_end = i
                    i += 1
                elif stripped.startswith('//'):
                    # comment between sub-regions — skip
                    i += 1
                else:
                    break  # hit real code — stop grouping
            if group_end > group_begin:
                regions.append(
                    (group_begin, group_end, group_name, group_content, True))
            continue  # i already advanced

        # ── Normal PERM_BEGIN/PERM_END ────────────────────────────────────────
        if re.search(r'//\s*PERM_BEGIN\b', lines[i]):
            m = re.search(r'//\s*PERM_BEGIN(?:\s+(\w+))?', lines[i])
            name = (m.group(1) if m and m.group(1) else f"region{len(regions)}")
            begin_idx = i
            content, end_idx = _collect_content(lines, i + 1)
            regions.append((begin_idx, end_idx, name, content, False))
            i = end_idx + 1
            continue

        i += 1
    return regions


# ─── Extra mutations (regalloc nudges) ───────────────────────────────────────
#
# These are injected *after* the float-temp expansion but *before* the
# topo-sort, so the ordering search still applies to the augmented lines.
#
# Each mutation is a lightweight text transform on the expanded line list.
# The mutations are stored as a list of (kind, args) tuples per region in
# Candidate.extra_mutations and re-applied every time candidate_to_lines is
# called.
#
# Kinds:
#   ("refer",  idx, var, indent)  — insert  `if (var) {}\n`  after line idx
#   ("self",   idx, var, indent)  — insert  `var = var;\n`   after line idx
#   ("block",  lo, hi, style)     — wrap lines [lo..hi] in if(1){} or do{}while(0)
#   ("comm",   idx)               — swap operands of * or + on line idx
#   ("pad",    idx, name, indent) — insert  `float name = 0.0f;\n`  at idx

# Regex that finds a commutative binary op with two simple operands
# Matches:  lhs = A * B;   or   lhs = A + B;
_COMM_RE = re.compile(
    r'^(\s*(?:this->|float\s+\w+\s*=\s*)?[^=]+=\s*)'
    r'([A-Za-z_]\w*(?:\.\w+|\[\d+\])?)\s*'
    r'([*+])\s*'
    r'([A-Za-z_]\w*(?:[.\[>-][^\s;]*)?)'
    r'(\s*;.*)$'
)


def _local_vars_in(expanded: List[str]) -> List[str]:
    """Return names of all local float vars defined in expanded."""
    result = []
    for line in expanded:
        if line.startswith(_PERM_ATOM_TAG):
            continue
        v = get_defined_var(line)
        if v and v not in _KEYWORDS:
            result.append(v)
    return result


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def make_random_extra_mutations(
    expanded: List[str],
    n_mutations: int,
) -> list:
    """
    Generate up to n_mutations random extra mutations for one region's
    expanded line list. Returns a list of (kind, ...) tuples.
    """
    if not expanded:
        return []

    mutations = []
    real_idxs = [
        i for i, l in enumerate(expanded)
        if not l.startswith(_PERM_ATOM_TAG) and l.strip()
    ]
    if not real_idxs:
        return []

    local_vars = _local_vars_in(expanded)

    for _ in range(n_mutations):
        kind = _rng.choice(["refer", "self", "block", "comm", "pad"])

        if kind in ("refer", "self") and local_vars:
            # Pick a line that defines a local var, insert after it
            definer_idxs = [
                i for i in real_idxs
                if get_defined_var(expanded[i]) in local_vars
            ]
            if not definer_idxs:
                continue
            idx = _rng.choice(definer_idxs)
            var = get_defined_var(expanded[idx])
            indent = _indent_of(expanded[idx])
            mutations.append((kind, idx, var, indent))

        elif kind == "block" and len(real_idxs) >= 2:
            # Skip atom entries as block boundaries
            non_atom_idxs = [
                i for i in real_idxs
                if not expanded[i].startswith(_PERM_ATOM_TAG)
            ]
            if len(non_atom_idxs) < 2:
                continue
            lo = _rng.choice(non_atom_idxs)
            hi = _rng.choice(non_atom_idxs)
            if lo > hi:
                lo, hi = hi, lo
            if lo == hi:
                continue
            # Skip if any atom falls inside the range
            if any(expanded[i].startswith(_PERM_ATOM_TAG)
                   for i in range(lo, hi + 1)):
                continue
            style = _rng.choice(["if1", "do"])
            mutations.append((kind, lo, hi, style))

        elif kind == "comm":
            comm_idxs = [
                i for i in real_idxs
                if _COMM_RE.match(expanded[i])
            ]
            if not comm_idxs:
                continue
            mutations.append((kind, _rng.choice(comm_idxs)))

        elif kind == "pad":
            idx = _rng.choice(real_idxs)
            indent = _indent_of(expanded[idx])
            name = f"fPad{_rng.randint(0, 999)}"
            mutations.append((kind, idx, name, indent))

    return mutations


def apply_extra_mutations(
    expanded: List[str],
    mutations: list,
) -> List[str]:
    """
    Apply a list of extra mutations to an expanded line list.
    Returns a new list with injected/modified lines.
    The topo-sort runs on the result of this function.
    """
    if not mutations:
        return expanded

    lines = list(expanded)

    # Apply in reverse index order so earlier insertions don't shift indices
    # for later ones.  Sort by index descending; block mutations use lo index.
    def _sort_key(m):
        return m[1]  # all tuples have index as second element

    for mut in sorted(mutations, key=_sort_key, reverse=True):
        kind = mut[0]

        if kind == "refer":
            _, idx, var, indent = mut
            if idx < len(lines):
                inject = f"{indent}(void){var}; // PERM_INJECT\n"
                lines.insert(idx + 1, inject)

        elif kind == "self":
            _, idx, var, indent = mut
            if idx < len(lines):
                inject = f"{indent}{var} = {var}; // PERM_INJECT\n"
                lines.insert(idx + 1, inject)

        elif kind == "block":
            _, lo, hi, style = mut
            if hi < len(lines) and lo < hi:
                # Safety: bail if any atom falls inside the range
                if any(lines[i].startswith(_PERM_ATOM_TAG)
                       for i in range(lo, hi + 1)):
                    continue
                block = lines[lo: hi + 1]
                base_indent = _indent_of(lines[lo])
                inner = ["    " + ln for ln in block]
                if style == "do":
                    wrapped = (
                        [f"{base_indent}do {{\n"]
                        + inner
                        + [f"{base_indent}}} while (0);\n"]
                    )
                else:
                    wrapped = (
                        [f"{base_indent}if (1) {{\n"]
                        + inner
                        + [f"{base_indent}}}\n"]
                    )
                lines[lo: hi + 1] = wrapped

        elif kind == "comm":
            _, idx = mut
            if idx < len(lines):
                m = _COMM_RE.match(lines[idx])
                if m:
                    pre, a, op, b, post = (
                        m.group(1), m.group(2),
                        m.group(3), m.group(4), m.group(5),
                    )
                    lines[idx] = f"{pre}{b} {op} {a}{post}\n"

        elif kind == "pad":
            _, idx, name, indent = mut
            if idx <= len(lines):
                lines.insert(idx,
                             f"{indent}float {name} = 0.0f; // PERM_INJECT\n"
                             )

    return lines


# ─── Float temp mutations ─────────────────────────────────────────────────────
#
# We recognise two shapes of eligible line:
#
#   Shape A — binary op:   this->dst = varA * varB->field;
#                          this->dst = varA * field;
#   Shape B — simple copy: this->dst = varB->field;
#                          this->dst = field;
#
# For shape A we offer 4 forms:
#   0 = keep original
#   1 = whole-RHS temp (fused pair, moves together):
#         float fVarN = varA * field;  this->dst = fVarN;
#   2 = field-load temp (fused pair, moves together):
#         float fVarN = field;  this->dst = varA * fVarN;
#   3 = field-load temp SPLIT (two independent permutable entries):
#         [entry A]  float fVarN = field;
#         [entry B]  this->dst = varA * fVarN;
#       entry B carries a dep on entry A via fVarN, so the permuter
#       can hoist the preload far above the store.
# For shape B we offer 2 forms (0=keep, 1=whole-RHS temp).

# Sentinel prefix used in the form string to signal that expand_region
# should add this form as TWO separate independent entries rather than
# one fused multi-line entry.
_PERM_SPLIT_SEP = "\x00PERM_SPLIT\x00"

# Matches:  this->dst = lhs_operand * rhs_operand;
#   where rhs_operand looks like a field access (contains . or -> or [)
_BINOP_FIELD_RE = re.compile(
    r'^(\s*)this->(\S+?)\s*=\s*([A-Za-z_]\w*)\s*\*\s*(.+?)\s*;\s*$'
)

# Matches:  this->dst = any_float_expr;
_FLOAT_ASSIGN_RE = re.compile(
    r'^(\s*)this->(\S+)\s*=\s*(.+?)\s*;\s*$'
)

_FLOAT_RHS_RE = re.compile(r'[+\-\*]|f32|fVar|fv|ft|\.')


def split_forms(line: str, var_name: str) -> List[str]:
    """
    Return a list of all split forms for this line.
    Index 0 is always the original line (a single string).
    Forms 1/2 are multi-line strings (fused pairs that move together).
    Form 3 (shape A only) is a _PERM_SPLIT_SEP-delimited string whose two
    halves expand_region adds as TWO independent permutable entries so the
    preload can be hoisted far above the store.
    Returns [original] if the line is not eligible.
    """
    # Try shape A: binary multiply with a field on the RHS
    m = _BINOP_FIELD_RE.match(line)
    if m:
        indent, dst, rate_var, field_expr = m.group(1), m.group(2), m.group(3), m.group(4)
        # Only bother if field_expr looks like a real field/array access
        if re.search(r'[.\[]|->|f32|fVar', field_expr):
            form1 = f"{indent}float {var_name} = {rate_var} * {field_expr};\n" \
                    f"{indent}this->{dst} = {var_name};\n"
            form2 = f"{indent}float {var_name} = {field_expr};\n" \
                    f"{indent}this->{dst} = {rate_var} * {var_name};\n"
            # Form 3: same as form 2 but the two lines are independent entries
            # in the permutation (separated by the sentinel so expand_region
            # can insert them as two separate rows).
            form3 = (f"{indent}float {var_name} = {field_expr};\n"
                     + _PERM_SPLIT_SEP
                     + f"{indent}this->{dst} = {rate_var} * {var_name};\n")
            return [line, form1, form2, form3]

    # Try shape B: simple float assignment
    m = _FLOAT_ASSIGN_RE.match(line)
    if m:
        indent, dst, rhs = m.group(1), m.group(2), m.group(3)
        if _FLOAT_RHS_RE.search(rhs) and not re.match(r'^[A-Za-z_]\w*$', rhs.strip()):
            form1 = f"{indent}float {var_name} = {rhs};\n" \
                    f"{indent}this->{dst} = {var_name};\n"
            return [line, form1]

    return [line]


def is_splittable(line: str) -> bool:
    # Atoms are never split — they move as a unit
    if line.startswith(_PERM_ATOM_TAG):
        return False
    return len(split_forms(line, "_")) > 1


def expand_region(
    content: List[str],
    form_choices: List[int],   # one int per splittable line: which form to use
    temp_names: List[str],     # one name per splittable line
) -> List[str]:
    """
    Expand content lines according to form_choices.
    Non-splittable lines are passed through unchanged.
    Splittable lines are replaced by 1 or 2 lines depending on the chosen form.
    """
    expanded: List[str] = []
    choice_idx = 0
    for line in content:
        if line.startswith(_PERM_ATOM_TAG):
            # Atom: stored as one entry, written back as multiple lines
            expanded.append(line)
            continue
        forms = split_forms(line, temp_names[choice_idx] if choice_idx < len(temp_names) else "_tmp")
        if len(forms) > 1:
            chosen_form = form_choices[choice_idx] if choice_idx < len(form_choices) else 0
            chosen_form = min(chosen_form, len(forms) - 1)
            raw = forms[chosen_form]
            if _PERM_SPLIT_SEP in raw:
                # Form 3 (split): add the preload and store as two separate
                # independent entries so the permuter can hoist them apart.
                preload, store = raw.split(_PERM_SPLIT_SEP, 1)
                expanded.append(preload)
                expanded.append(store)
            else:
                expanded.extend(raw.splitlines(keepends=True))
            choice_idx += 1
        else:
            expanded.append(line)
    return expanded


# ─── Dependency analysis ──────────────────────────────────────────────────────

_KEYWORDS: Set[str] = frozenset({
    'if', 'else', 'while', 'for', 'do', 'return', 'switch', 'case', 'break',
    'continue', 'new', 'delete', 'true', 'false', 'nullptr', 'NULL', 'this',
    'sizeof', 'static', 'const', 'unsigned', 'signed', 'int', 'float', 'char',
    'short', 'long', 'void', 'class', 'struct', 'enum', 'register', 'volatile',
})


def get_defined_var(line: str) -> Optional[str]:
    # Atoms define nothing that other lines depend on (treat as opaque)
    if line.startswith(_PERM_ATOM_TAG):
        return None
    # Injected helper lines (refer/self/pad) are transparent to dep analysis
    if "// PERM_INJECT" in line:
        return None
    s = line.strip().rstrip(';').strip()
    if not s or s.startswith('//'):
        return None
    lhs = s.split('=')[0].strip() if '=' in s else s
    if '->' in lhs:
        return None
    if re.match(r'.*\[.*\]\s*$', lhs):
        return None
    m = re.match(
        r'^(?:(?:unsigned|signed|const|volatile|register|static)\s+)*'
        r'[\w:<>]+(?:\s*[*&]+)?\s+(\w+)\s*=\s*.+',
        s
    )
    if m:
        var = m.group(1)
        if var not in _KEYWORDS:
            return var
    m = re.match(r'^([A-Za-z_]\w*)\s*=\s*.+', s)
    if m:
        var = m.group(1)
        if var not in _KEYWORDS:
            return var
    return None


def get_used_vars(line: str, local_vars: Set[str]) -> Set[str]:
    # For atoms, scan all text — they may read any local var
    if line.startswith(_PERM_ATOM_TAG):
        text = line[len(_PERM_ATOM_TAG):]
        tokens = set(re.findall(r'\b([A-Za-z_]\w*)\b', text))
        return tokens & local_vars
    s = line.strip().rstrip(';')
    eq = s.find('=')
    rhs = s[eq + 1:] if eq >= 0 else s
    tokens = set(re.findall(r'\b([A-Za-z_]\w*)\b', rhs))
    return tokens & local_vars


def compute_constraints(content_lines: List[str]):
    n = len(content_lines)
    defined_by: Dict[int, Optional[str]] = {
        i: get_defined_var(l) for i, l in enumerate(content_lines)
    }
    local_vars: Set[str] = {v for v in defined_by.values() if v}

    var_defs: Dict[str, List[int]] = {}
    for i, v in defined_by.items():
        if v:
            var_defs.setdefault(v, []).append(i)

    reaching: Dict[str, int] = {}
    reaching_at: Dict[int, Dict[str, int]] = {}
    for i, line in enumerate(content_lines):
        used = get_used_vars(line, local_vars)
        reaching_at[i] = {v: reaching[v] for v in used if v in reaching}
        v = defined_by[i]
        if v:
            reaching[v] = i

    constraints: Dict[int, Set[int]] = {i: set() for i in range(n)}
    for i in range(n):
        for var, def_idx in reaching_at[i].items():
            constraints[i].add(def_idx)
            next_def = next((d for d in var_defs.get(var, []) if d > def_idx), None)
            if next_def is not None:
                constraints[next_def].add(i)

    return constraints, defined_by


# ─── Permutation generation ───────────────────────────────────────────────────

EXHAUSTIVE_THRESHOLD = 8


def _is_topo_valid(perm: Tuple[int, ...], constraints: Dict[int, Set[int]]) -> bool:
    pos = {idx: p for p, idx in enumerate(perm)}
    for i, preds in constraints.items():
        for j in preds:
            if pos[j] >= pos[i]:
                return False
    return True


def exhaustive_valid_perms(n: int, constraints: Dict[int, Set[int]]) -> List[Tuple[int, ...]]:
    return [p for p in itertools.permutations(range(n)) if _is_topo_valid(p, constraints)]


def random_topo_sort(n: int, constraints: Dict[int, Set[int]]) -> Optional[Tuple[int, ...]]:
    successors: Dict[int, List[int]] = {j: [] for j in range(n)}
    for i, preds in constraints.items():
        for j in preds:
            successors[j].append(i)

    in_deg = [len(constraints.get(i, set())) for i in range(n)]
    available = [i for i in range(n) if in_deg[i] == 0]
    result: List[int] = []

    while available:
        chosen = _rng.choice(available)
        available.remove(chosen)
        result.append(chosen)
        for succ in successors[chosen]:
            in_deg[succ] -= 1
            if in_deg[succ] == 0:
                available.append(succ)

    return tuple(result) if len(result) == n else None


# ─── State: the "genome" of one candidate ─────────────────────────────────────
#
# A candidate is fully described by, for each region:
#   - form_choices: List[int]   — which split form each splittable line uses
#   - temp_names:   List[str]   — temp variable names (stable across mutations)
#   - perm:         Tuple[int]  — ordering of expanded lines
#
# We store the expanded lines so we can apply small mutations to the ordering.

class Candidate:
    def __init__(
        self,
        form_choices_per_region: List[List[int]],
        temp_names_per_region: List[List[str]],
        perms_per_region: List[Tuple[int, ...]],
        expanded_per_region: List[List[str]],
        extra_mutations_per_region: Optional[List[list]] = None,
    ):
        self.forms = form_choices_per_region
        self.names = temp_names_per_region
        self.perms = perms_per_region
        self.expanded = expanded_per_region
        # extra_mutations: list of mutation lists, one per region
        self.extra = (
            extra_mutations_per_region
            if extra_mutations_per_region is not None
            else [[] for _ in perms_per_region]
        )

    def copy(self) -> "Candidate":
        return Candidate(
            copy.deepcopy(self.forms),
            copy.deepcopy(self.names),
            [tuple(p) for p in self.perms],
            copy.deepcopy(self.expanded),
            copy.deepcopy(self.extra),
        )


def make_seed_candidate(
    regions,
    splittable_per_region: List[List[int]],
    temp_counter: List[int],
) -> Optional[Candidate]:
    """Create a candidate that represents the current source as-is.

    All split forms = 0 (original), perm = identity (natural order).
    Used as the starting point for --guided so annealing begins at the
    current match % rather than a random scramble.
    """
    forms_list, names_list, perms_list, expanded_list, extra_list = (
        [], [], [], [], []
    )

    for ridx, (_, _, _, content, _) in enumerate(regions):
        n_split = len(splittable_per_region[ridx])
        forms = [0] * n_split  # form 0 = original line, no split

        names = [f"fVar{temp_counter[0] + i}" for i in range(n_split)]
        temp_counter[0] += n_split

        expanded = expand_region(content, forms, names)
        # Identity permutation — preserves the current source order exactly
        perm = tuple(range(len(expanded)))

        forms_list.append(forms)
        names_list.append(names)
        perms_list.append(perm)
        expanded_list.append(expanded)
        extra_list.append([])

    return Candidate(
        forms_list, names_list, perms_list, expanded_list, extra_list
    )


def make_random_candidate(
    regions,
    splittable_per_region: List[List[int]],
    temp_counter: List[int],
    n_extra: int = 0,
) -> Optional[Candidate]:
    """Create a fresh random candidate from scratch.

    n_extra: number of extra mutations to inject per region (0 = disabled).
    """
    forms_list, names_list, perms_list, expanded_list, extra_list = (
        [], [], [], [], []
    )

    for ridx, (_, _, _, content, _) in enumerate(regions):
        n_split = len(splittable_per_region[ridx])
        # Pick a random form for each splittable line
        forms: List[int] = []
        for line_idx in splittable_per_region[ridx]:
            n_forms = len(split_forms(content[line_idx], "_"))
            forms.append(_rng.randint(0, n_forms - 1))

        names = [f"fVar{temp_counter[0] + i}" for i in range(n_split)]
        temp_counter[0] += n_split

        expanded = expand_region(content, forms, names)

        # Generate extra mutations on the base expanded list
        extra = (make_random_extra_mutations(expanded, n_extra)
                 if n_extra > 0 else [])
        mutated = apply_extra_mutations(expanded, extra)

        constraints, _ = compute_constraints(mutated)
        perm = random_topo_sort(len(mutated), constraints)
        if perm is None:
            return None

        forms_list.append(forms)
        names_list.append(names)
        perms_list.append(perm)
        expanded_list.append(mutated)
        extra_list.append(extra)

    return Candidate(
        forms_list, names_list, perms_list, expanded_list, extra_list
    )


def mutate_candidate(
    parent: Candidate,
    regions,
    splittable_per_region: List[List[int]],
    temp_counter: List[int],
    strength: float = 0.0,
    n_extra: int = 0,
) -> Optional[Candidate]:
    """
    Apply mutations to a parent candidate.

    strength (0.0–1.0) controls how aggressive the mutation is:
      0.0 = small: swap 2 random lines in one region
      0.5 = medium: swap several lines + maybe flip a form
      1.0 = large: fully re-randomise one entire region

    n_extra: number of extra regalloc mutations per region.

    At high temperature (early in cycle) call with high strength to explore.
    At low temperature (late in cycle) call with low strength to exploit.
    """
    child = parent.copy()

    # How many regions to touch (1 at low strength, possibly all at high)
    n_regions = len(regions)
    n_touch = max(1, round(strength * n_regions))
    ridxs = _rng.sample(range(n_regions), min(n_touch, n_regions))

    for ridx in ridxs:
        _, _, _, content, _ = regions[ridx]

        if strength > 0.6 or not child.forms[ridx]:
            # High strength: fully re-randomise this region from scratch
            n_split = len(splittable_per_region[ridx])
            forms: List[int] = []
            for line_idx in splittable_per_region[ridx]:
                n_forms = len(split_forms(content[line_idx], "_"))
                forms.append(_rng.randint(0, n_forms - 1))
            new_names = [
                f"fVar{temp_counter[0] + i}" for i in range(n_split)
            ]
            temp_counter[0] += n_split
            child.forms[ridx] = forms
            child.names[ridx] = new_names
            expanded_base = expand_region(content, forms, new_names)
            extra = (make_random_extra_mutations(expanded_base, n_extra)
                     if n_extra > 0 else [])
            child.extra[ridx] = extra
            expanded = apply_extra_mutations(expanded_base, extra)
            child.expanded[ridx] = expanded
            constraints, _ = compute_constraints(expanded)
            perm = random_topo_sort(len(expanded), constraints)
            if perm is None:
                return None
            child.perms[ridx] = perm

        else:
            # Low/medium strength: swap N random pairs + maybe flip a form
            # Also occasionally mutate the extra mutations list
            n_swaps = max(1, round(strength * len(child.perms[ridx])))
            perm = list(child.perms[ridx])
            constraints, _ = compute_constraints(child.expanded[ridx])
            for _ in range(n_swaps * 3):
                i = _rng.randrange(len(perm))
                j = _rng.randrange(len(perm))
                if i == j:
                    continue
                perm[i], perm[j] = perm[j], perm[i]
                if _is_topo_valid(tuple(perm), constraints):
                    break
                perm[i], perm[j] = perm[j], perm[i]
            child.perms[ridx] = tuple(perm)

            # Medium strength: flip one form or mutate extra mutations
            if strength > 0.3 and child.forms[ridx]:
                slot = _rng.randrange(len(child.forms[ridx]))
                line_idx = splittable_per_region[ridx][slot]
                n_forms = len(split_forms(content[line_idx], "_"))
                old_form = child.forms[ridx][slot]
                new_form = _rng.choice(
                    [f for f in range(n_forms) if f != old_form]
                )
                child.forms[ridx][slot] = new_form
                n_split = len(splittable_per_region[ridx])
                new_names = [
                    f"fVar{temp_counter[0] + i}" for i in range(n_split)
                ]
                temp_counter[0] += n_split
                child.names[ridx] = new_names
                expanded_base = expand_region(
                    content, child.forms[ridx], new_names
                )
                extra = (make_random_extra_mutations(expanded_base, n_extra)
                         if n_extra > 0 else [])
                child.extra[ridx] = extra
                expanded = apply_extra_mutations(expanded_base, extra)
                child.expanded[ridx] = expanded
                constraints, _ = compute_constraints(expanded)
                perm = random_topo_sort(len(expanded), constraints)
                if perm is None:
                    return None
                child.perms[ridx] = perm

            elif n_extra > 0:
                # Low strength: just re-roll the extra mutations
                n_split = len(splittable_per_region[ridx])
                expanded_base = expand_region(
                    content, child.forms[ridx], child.names[ridx]
                )
                extra = make_random_extra_mutations(expanded_base, n_extra)
                child.extra[ridx] = extra
                expanded = apply_extra_mutations(expanded_base, extra)
                child.expanded[ridx] = expanded
                constraints, _ = compute_constraints(expanded)
                perm = random_topo_sort(len(expanded), constraints)
                if perm is None:
                    return None
                child.perms[ridx] = perm

    return child


# ─── Build / score ────────────────────────────────────────────────────────────

def unit_to_obj(unit: str) -> str:
    base = unit.replace('\\', '/').removesuffix('.cpp') + '.o'
    return f"build/SLUS-21642-PROTO-070901/src/{base}"


def ninja_build(obj_path: str) -> bool:
    r = subprocess.run(
        ["ninja", "-j1", obj_path],
        capture_output=True,
        cwd=root_dir,
    )
    return r.returncode == 0


def direct_build(src_path: str, obj_path: str) -> bool:
    """Invoke mwccps2 directly, bypassing ninja for speed."""
    abs_obj = os.path.join(root_dir, obj_path)
    os.makedirs(os.path.dirname(abs_obj), exist_ok=True)
    r = subprocess.run(
        [_MWCC_EXE] + _MWCC_CFLAGS + ["-c", src_path, "-o", abs_obj],
        capture_output=True,
        cwd=root_dir,
    )
    return r.returncode == 0


def get_score(unit: str, symbol: str) -> Optional[float]:
    r = subprocess.run(
        [OBJDIFF_CLI, "diff", "-c", "functionRelocDiffs=data_value",
         "-u", unit, "-o", "-", "--format", "json"],
        capture_output=True,
        cwd=root_dir,
    )
    if r.returncode != 0:
        return None
    return _parse_score(r.stdout, symbol)


def get_score_direct(target_obj: str, base_obj: str, symbol: str) -> Optional[float]:
    """Score by comparing two explicit .o files (used in parallel mode)."""
    r = subprocess.run(
        [OBJDIFF_CLI, "diff", "-c", "functionRelocDiffs=data_value",
         "-1", target_obj, "-2", base_obj,
         "-o", "-", "--format", "json"],
        capture_output=True,
        cwd=root_dir,
    )
    if r.returncode != 0:
        return None
    return _parse_score(r.stdout, symbol)


def _parse_score(stdout: bytes, symbol: str) -> Optional[float]:
    data = json.loads(stdout)
    for sym in data.get("left", {}).get("symbols", []):
        name = sym.get("name", "")
        dname = sym.get("demangled_name", "")
        if symbol in name or symbol in dname:
            mp = sym.get("match_percent")
            if mp is not None:
                return mp
    return None


_OBJDUMP = os.path.join(root_dir, "build", "binutils",
                        f"mips-linux-gnu-objdump{EXE}")


def disassemble_symbol(obj_path: str, symbol: str) -> Optional[List[str]]:
    """Disassemble a single symbol from an .o file using mips objdump.

    Returns a list of instruction strings (e.g. ['lwc1 $f0,0($a0)', ...])
    or None if the symbol is not found / objdump fails.
    """
    abs_obj = os.path.join(root_dir, obj_path) if not os.path.isabs(obj_path) else obj_path
    r = subprocess.run(
        [_OBJDUMP, "-d", "--no-show-raw-insn", abs_obj],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    # Find the section for our symbol and collect instruction lines
    lines = r.stdout.splitlines()
    in_sym = False
    instrs: List[str] = []
    # Build a set of name fragments to match against: the full symbol,
    # the bare name after '::' (for demangled→mangled matching), and
    # the mangled prefix derived from the class name.
    bare = symbol.split('::')[-1].split('(')[0]  # e.g. "setup"
    cls  = symbol.split('::')[0] if '::' in symbol else ''
    for line in lines:
        # objdump marks function starts like: "00000000 <__savefpr_14>:"
        if re.match(r'^[0-9a-f]+ <', line):
            if in_sym:
                break  # next symbol started — we're done
            # Match: full symbol string, or bare name at start of mangled name
            sym_part = re.search(r'<([^>]+)>', line)
            if sym_part:
                mangled = sym_part.group(1)
                if (symbol in line
                        or mangled.startswith(bare + '__')
                        or (cls and f'{bare}__{len(cls)}{cls}' in mangled)):
                    in_sym = True
            continue
        if in_sym:
            # instruction lines look like: "   0:   nop"
            m = re.match(r'^\s+[0-9a-f]+:\s+(.+)$', line)
            if m:
                instrs.append(m.group(1).strip())
    return instrs if instrs else None


_record_lock = threading.Lock()


def record_trial(
    record_path: str,
    trial: int,
    score: float,
    symbol: str,
    obj_path: str,
    perm_lines: List[str],
    candidate: "Candidate",
    regions,
) -> None:
    """Append one JSONL record to record_path."""
    instrs = disassemble_symbol(obj_path, symbol)
    # Build a compact source representation: just the PERM region lines
    region_sources = {}
    for ridx, (_, _, name, _, _) in enumerate(regions):
        exp = candidate.expanded[ridx]
        perm = candidate.perms[ridx]
        src_lines = []
        for i in perm:
            entry = exp[i]
            if entry.startswith(_PERM_ATOM_TAG):
                src_lines.extend(entry[len(_PERM_ATOM_TAG):].splitlines())
            else:
                src_lines.append(entry.rstrip('\n'))
        region_sources[name] = src_lines
    entry = {
        "trial": trial,
        "score": round(score, 4),
        "symbol": symbol,
        "regions": region_sources,
        "instructions": instrs,
    }
    with _record_lock:
        with open(record_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


# ─── Apply candidate to file ──────────────────────────────────────────────────

def candidate_to_lines(
    original_lines: List[str],
    regions,
    candidate: Candidate,
) -> List[str]:
    result = list(original_lines)
    for ridx in reversed(range(len(regions))):
        begin_idx, end_idx, _, _, _ = regions[ridx]
        exp = candidate.expanded[ridx]
        perm = candidate.perms[ridx]
        reordered: List[str] = []
        for i in perm:
            entry = exp[i]
            if entry.startswith(_PERM_ATOM_TAG):
                reordered.extend(entry[len(_PERM_ATOM_TAG):].splitlines(keepends=True))
            else:
                reordered.append(entry)
        result[begin_idx + 1 : end_idx] = reordered
    return result


# ─── Pretty helpers ───────────────────────────────────────────────────────────

def eta_str(elapsed: float, done: int, total: int) -> str:
    if done == 0:
        return "?"
    rate = done / elapsed
    rem = (total - done) / rate
    if rem < 60:
        return f"{rem:.0f}s"
    if rem < 3600:
        return f"{rem/60:.1f}m"
    return f"{rem/3600:.1f}h"


def _elapsed_str(elapsed: float) -> str:
    s = int(elapsed)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


# ─── Live dashboard (multi-worker) ────────────────────────────────────────────

class Dashboard:
    """
    Redraws a fixed-height block in the terminal using ANSI cursor movement.

    Layout (n_jobs=4):
    ╔══════════════════════════════════════════════════════════╗
    ║  clsPrfm::setup │ trial 47 │ best 82.10% │ T=1.743      ║
    ╠══════════════════════════════════════════════════════════╣
    ║  W1  82.10%  [accept:better]  f32Speed[0]…              ║
    ║  W2  79.44%  [reject p=0.23]  f32Accele[1]…             ║
    ║  W3   idle                    —                          ║
    ║  W4  81.33%  [accept:worse ]  f32RotateSpeed…           ║
    ╠══════════════════════════════════════════════════════════╣
    ║  52 trials/min │ elapsed 0:54 │ Ctrl+C to stop           ║
    ╚══════════════════════════════════════════════════════════╝
    """

    WIDTH = 100

    def __init__(self, n_jobs: int, symbol: str, total_trials: int) -> None:
        self.n_jobs = n_jobs
        self.symbol = symbol
        self.total_trials = total_trials
        # Per-worker last result
        self.worker_score: List[Optional[float]] = [None] * n_jobs
        self.worker_tag: List[str] = ["idle"] * n_jobs
        self.worker_snippet: List[str] = [" —"] * n_jobs
        # Global state
        self.trial = 0
        self.best = 0.0
        self.temperature = 2.0
        self.t_start = time.time()
        self._drawn = False
        self._lock = threading.Lock()
        # Height: sep + symbol + stats + sep + n_jobs worker rows + sep + footer
        self._height = 1 + 1 + 1 + 1 + n_jobs + 1 + 1

    def update(
        self,
        worker_id: int,
        score: Optional[float],
        tag: str,
        snippet: str,
        trial: int,
        best: float,
        temperature: float,
    ) -> None:
        with self._lock:
            self.worker_score[worker_id] = score
            self.worker_tag[worker_id] = tag.strip()
            self.worker_snippet[worker_id] = snippet
            self.trial = trial
            self.best = best
            self.temperature = temperature
            self._redraw()

    def _redraw(self) -> None:
        W = self.WIDTH
        elapsed = time.time() - self.t_start
        rate = self.trial / elapsed if elapsed > 0.1 else 0.0

        lines: List[str] = []

        # ── Header ────────────────────────────────────────────────────────────
        trial_str = (f"trial {self.trial}/{self.total_trials}"
                     if self.total_trials else f"trial {self.trial}")
        lines.append("─" * W)
        lines.append(f"  {self.symbol}"[:W])
        lines.append(
            f"  {trial_str}"
            f"  │  best {self.best:.2f}%"
            f"  │  T={self.temperature:.3f}"
        )
        lines.append("─" * W)

        # ── Worker rows ───────────────────────────────────────────────────────
        for i in range(self.n_jobs):
            sc = self.worker_score[i]
            is_idle = sc is None
            score_s = "  idle " if is_idle else f"{sc:6.2f}%"
            tag_s = ("" if is_idle else self.worker_tag[i])[:18].ljust(18)
            snip = self.worker_snippet[i][:W - 38]
            lines.append(f"  W{i+1}  {score_s}  {tag_s}  {snip}")

        # ── Footer ────────────────────────────────────────────────────────────
        lines.append("─" * W)
        elapsed_s = _elapsed_str(elapsed)
        rate_s = f"{rate:.0f} trials/min" if rate > 0 else "…"
        lines.append(f"  {rate_s}  │  elapsed {elapsed_s}"
                     f"  │  Ctrl+C to stop")

        # Move cursor up to overwrite previous draw
        if self._drawn:
            n = len(lines)
            sys.stdout.write(f"\033[{n}A\r")

        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()
        self._drawn = True

    def finish(self) -> None:
        """Print a blank line after the dashboard so the prompt is clean."""
        sys.stdout.write("\n")
        sys.stdout.flush()


def save_live_results(
    out_path: str,
    top_results: list,
    regions,
    trial: int,
    total_trials: int,
    unit: str,
    symbol: str,
    float_temps: bool,
    guided: bool,
) -> None:
    """Overwrite out_path with current top results. Called on every new best."""
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(f"# Permuter live results — {timestamp}\n")
        fh.write(f"Unit: `{unit}`  \n")
        fh.write(f"Symbol: `{symbol}`  \n")
        fh.write(f"Trials so far: {trial}"
                 + (f" / {total_trials}" if total_trials else "") + "  \n")
        fh.write(f"Flags: float-temps={'on' if float_temps else 'off'}"
                 f"  guided={'on' if guided else 'off'}  \n\n")
        for rank, (score, candidate, _) in enumerate(top_results, 1):
            fh.write(f"## #{rank}  {score:.2f}%\n\n")
            for ridx, (_, _, name, _, _) in enumerate(regions):
                exp = candidate.expanded[ridx]
                perm = candidate.perms[ridx]
                fh.write(f"**[{name}]** order: `{list(perm)}`\n\n")
                fh.write("```cpp\n")
                for i in perm:
                    entry = exp[i]
                    if entry.startswith(_PERM_ATOM_TAG):
                        fh.write(entry[len(_PERM_ATOM_TAG):])
                    else:
                        fh.write(entry)
                fh.write("```\n\n")


def fmt_candidate(regions, candidate: Candidate) -> str:
    lines = []
    for ridx, (_, _, name, _, _) in enumerate(regions):
        exp = candidate.expanded[ridx]
        perm = candidate.perms[ridx]
        lines.append(f"  [{name}]  order: {list(perm)}")
        for i in perm:
            entry = exp[i]
            if entry.startswith(_PERM_ATOM_TAG):
                lines.append("    // [atom]")
                for al in entry[len(_PERM_ATOM_TAG):].splitlines():
                    lines.append(f"    {al.rstrip()}")
            else:
                lines.append(f"    {entry.rstrip()}")
    return "\n".join(lines)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-u", "--unit", required=True)
    ap.add_argument("-d", "--symbol", required=True,
                    help="Demangled symbol name (e.g. 'clsPrfm::setup')")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--max-trials", type=int, default=0,
                    help="Stop after N trials (default: run until Ctrl+C)")
    ap.add_argument("--apply-best", action="store_true",
                    help="Write the best result back to the source file")
    ap.add_argument("--float-temps", action="store_true",
                    help="Enable float temp introduction mutations (3 forms per eligible line)")
    ap.add_argument("--guided", action="store_true",
                    help="Simulated annealing: mutate from current best, accept worse results "
                         "occasionally to escape local maxima (temperature starts at 2.0, "
                         "cools 0.5%% per trial)")
    ap.add_argument("--direct", action="store_true",
                    help="Invoke mwccps2 directly instead of via ninja "
                         "(faster: skips ninja overhead)")
    ap.add_argument("--jobs", type=int, default=1, metavar="N",
                    help="Number of parallel compile+score workers (default: 1). "
                         "Implies --direct.")
    ap.add_argument("--seed-from-current", action="store_true",
                    help="Start guided annealing from the current source "
                         "ordering instead of a random scramble. Use this "
                         "when the source is already close to matching.")
    ap.add_argument("--extra-mutations", type=int, default=0, metavar="N",
                    help="Number of extra regalloc-nudge mutations per region "
                         "per trial (0 = disabled). Injects dummy if-refs, "
                         "self-assigns, wrapping blocks, commutative swaps, "
                         "and pad vars into each candidate.")
    ap.add_argument("--record", metavar="FILE",
                    help="Append (source, assembly, score) as JSONL to FILE "
                         "for every successful compile. Use this to build a "
                         "dataset for MWCC behaviour analysis.")
    ap.add_argument("--record-threshold", type=float, default=0.0, metavar="PCT",
                    help="Only record trials scoring >= PCT%% (default: 0 = all).")
    args = ap.parse_args()

    src_path = os.path.join(root_dir, "src", args.unit)
    if not os.path.isfile(src_path):
        print(f"Error: source file not found:\n  {src_path}", file=sys.stderr)
        sys.exit(1)

    with open(src_path, "r", encoding="utf-8") as fh:
        original_lines = fh.readlines()

    regions = parse_regions(original_lines)
    if not regions:
        print("No PERM_BEGIN / PERM_END markers found in file.", file=sys.stderr)
        sys.exit(1)

    # ── Identify splittable lines per region ──────────────────────────────────
    splittable_per_region: List[List[int]] = []
    for _, _, name, content, _ in regions:
        idxs = [i for i, line in enumerate(content) if is_splittable(line)] if args.float_temps else []
        splittable_per_region.append(idxs)

    # ── Print region info ─────────────────────────────────────────────────────
    for ridx, (_, _, name, content, grouped) in enumerate(regions):
        s_idxs = splittable_per_region[ridx]
        group_tag = "  [grouped]" if grouped else ""
        print(f"Region [{name}]{group_tag}  —  {len(content)} lines"
              + (f", {len(s_idxs)} splittable" if args.float_temps else ""))
        for i, line in enumerate(content):
            tag = "  [splittable]" if i in s_idxs else ""
            if line.startswith(_PERM_ATOM_TAG):
                atom_lines = line[len(_PERM_ATOM_TAG):].split("\n")
                print(f"  {i+1:2d}. [atom] {atom_lines[0].rstrip()}{tag}")
                for al in atom_lines[1:]:
                    print(f"        {al.rstrip()}")
            else:
                print(f"  {i+1:2d}. {line.rstrip()}{tag}")

    total_trials = args.max_trials  # 0 = run forever
    n_extra = args.extra_mutations
    mode_str = "simulated annealing" if args.guided else "random"
    trials_str = str(total_trials) if total_trials else "∞  (Ctrl+C to stop)"
    live_path = os.path.join(root_dir, "research", "perm_live.md")
    print(f"\nMode: {mode_str}  —  {trials_str} trials")
    if args.float_temps:
        print("Float-temp mutations: enabled "
              "(4 forms: keep / whole-RHS / field-load-fused / field-load-split)")
    if n_extra > 0:
        print(f"Extra mutations: {n_extra} per region "
              "(refer / self-assign / block / commutative / pad)")

    if args.dry_run:
        print("\n-- DRY RUN: sample expansions --")
        temp_counter = [0]
        for ridx, (_, _, name, content, _) in enumerate(regions):
            print(f"\n[{name}]")
            for _ in range(3):
                cand = make_random_candidate(regions, splittable_per_region, temp_counter)
                if cand:
                    exp = cand.expanded[ridx]
                    perm = cand.perms[ridx]
                    print(f"  forms={cand.forms[ridx]}  order={list(perm)}")
                    for i in perm:
                        print(f"    {exp[i].rstrip()}")
        return

    # ── Run loop ──────────────────────────────────────────────────────────────
    obj_path = unit_to_obj(args.unit)
    n_jobs = args.jobs
    use_direct = args.direct or n_jobs > 1

    # top_results: list of (score, candidate, file_lines)
    top_results: List[Tuple[float, Candidate, List[str]]] = []

    temp_counter = [0]
    trial = 0
    t_start = time.time()

    # Simulated annealing state
    sa_current: Optional[Tuple[float, Candidate]] = None
    # When seeding from current source, start cold so we don't immediately
    # scramble away from the known-good state.  After each restart the
    # temperature doubles (up to SA_TEMP_MAX) so later restarts explore wider.
    SA_TEMP_INIT = 0.1 if args.seed_from_current else 2.0
    SA_TEMP_START = SA_TEMP_INIT  # mutable: raised each restart
    SA_COOL = 0.995
    SA_RESTART = 500
    sa_cycle = 0

    # Target .o for scoring (the reference we compare against)
    target_obj = os.path.join(
        root_dir, "build", "SLUS-21642-PROTO-070901", "obj",
        args.unit.replace("/", os.sep).removesuffix(".cpp") + ".o",
    )

    print(f"\nStarting search ({trials_str} trials)"
          + (f"  [{n_jobs} workers]" if n_jobs > 1 else "") + "...")
    print(f"Live results: {live_path}\n")

    # ── Seed from current source if requested ─────────────────────────────────
    if args.seed_from_current and args.guided:
        seed_cand = make_seed_candidate(
            regions, splittable_per_region, temp_counter
        )
        if seed_cand is not None:
            # Score the seed candidate (it's just the current source)
            new_lines = candidate_to_lines(
                original_lines, regions, seed_cand)
            with open(src_path, "w", encoding="utf-8") as fh:
                fh.writelines(new_lines)
            if use_direct:
                build_ok = direct_build(src_path, obj_path)
                seed_score = (
                    get_score_direct(target_obj,
                                     os.path.join(root_dir, obj_path),
                                     args.symbol)
                    if build_ok else None
                )
            else:
                build_ok = ninja_build(obj_path)
                seed_score = (get_score(args.unit, args.symbol)
                              if build_ok else None)
            with open(src_path, "w", encoding="utf-8") as fh:
                fh.writelines(original_lines)
            if seed_score is not None:
                sa_current = (seed_score, seed_cand)
                # Also pre-populate top_results so MT workers mutate from
                # the seed immediately rather than generating random candidates
                seed_lines = candidate_to_lines(
                    original_lines, regions, seed_cand)
                top_results.append((seed_score, seed_cand, seed_lines))
                print(f"  [seed] current source scores {seed_score:.2f}%"
                      f" — annealing from here")
            else:
                print("  [seed] failed to score current source"
                      " — starting from random")

    def _sa_accept(score: float, temperature: float) -> Tuple[bool, str]:
        """Returns (accepted, tag). Updates sa_current in-place via closure."""
        nonlocal sa_current
        if not args.guided:
            return True, ""
        import math
        if sa_current is None:
            sa_current = (score, None)  # placeholder, updated by caller
            return True, " [accept:first]"
        delta = score - sa_current[0]
        if delta >= 0:
            return True, " [accept:better]"
        prob = math.exp(delta / max(temperature, 1e-9))
        if _rng.random() < prob:
            return True, f" [accept:worse p={prob:.2f}]"
        return False, f" [reject p={prob:.2f}]"

    def _process_result(
        score: Optional[float],
        candidate: Candidate,
        new_lines: List[str],
        temperature: float,
    ) -> str:
        nonlocal trial, sa_cycle, sa_current
        sa_tag = ""
        if score is not None and args.guided:
            accepted, sa_tag = _sa_accept(score, temperature)
            if accepted:
                sa_current = (score, candidate)
        if score is not None:
            prev_best = top_results[0][0] if top_results else -1.0
            top_results.append((score, candidate, new_lines))
            top_results.sort(key=lambda x: -x[0])
            del top_results[args.top:]
            if top_results[0][0] > prev_best:
                save_live_results(live_path, top_results, regions, trial,
                                  total_trials, args.unit, args.symbol,
                                  args.float_temps, args.guided)
            if args.record and score >= args.record_threshold:
                record_trial(args.record, trial, score, args.symbol,
                             obj_path, new_lines, candidate, regions)
        elapsed = time.time() - t_start
        score_str = f"{score:7.2f}%" if score is not None else "   FAIL "
        eta = eta_str(elapsed, trial, total_trials) if total_trials else "∞"
        best_str = (f"  best={top_results[0][0]:.2f}%"
                    if top_results else "")
        temp_str = f"  T={temperature:.3f}" if args.guided else ""
        trial_str = (f"{trial}" if not total_trials
                     else f"{trial:>4}/{total_trials}")
        print(f"  [{trial_str}]  {score_str}{best_str}{temp_str}"
              f"{sa_tag}   ETA {eta}", flush=True)
        return sa_tag

    SA_TEMP_MAX = 2.0  # absolute ceiling for strength normalisation

    def _next_candidate(
        force_random: bool = False,
    ) -> Optional[Tuple[Candidate, float]]:
        """Generate next candidate + temperature. Returns None to skip.

        force_random: ignore SA state and generate a fresh random candidate.
        Used in multi-threaded mode where in-flight candidates make SA state
        incoherent — we still accept/reject based on scores, but generate
        from the best known result rather than a chaotic sa_current.
        """
        nonlocal sa_cycle
        temperature = SA_TEMP_START * (SA_COOL ** sa_cycle)

        # Choose parent: for MT use all-time best to avoid race conditions
        if force_random:
            parent = top_results[0][1] if top_results else None
        else:
            parent = sa_current[1] if sa_current is not None else None

        if args.guided and parent is not None:
            # Normalise against the global max so seed runs start with small
            # mutations (strength ≈ 0.05 at T=0.1) instead of full scrambles.
            strength = min(1.0, temperature / SA_TEMP_MAX)
            # Scale extra mutations by strength so seeded runs don't immediately
            # scramble away from the seed: at T=0.1 (strength=0.05) no extra
            # mutations are applied; they ramp in as temperature rises.
            effective_extra = round(strength * n_extra)
            cand = mutate_candidate(
                parent, regions, splittable_per_region,
                temp_counter, strength=strength, n_extra=effective_extra,
            )
        else:
            cand = make_random_candidate(
                regions, splittable_per_region, temp_counter,
                n_extra=n_extra,
            )
        if cand is None:
            return None
        sa_cycle += 1
        return cand, temperature

    if n_jobs <= 1:
        # ── Single-threaded path ──────────────────────────────────────────────
        try:
            while not total_trials or trial < total_trials:
                if args.guided and sa_cycle > 0 and sa_cycle % SA_RESTART == 0:
                    if top_results:
                        sa_current = (top_results[0][0], top_results[0][1])
                    else:
                        sa_current = None
                    sa_cycle = 0
                    # Double restart temperature each cycle (up to SA_TEMP_MAX)
                    # so later restarts explore more aggressively.
                    SA_TEMP_START = min(SA_TEMP_MAX, SA_TEMP_START * 2.0)
                    best_now = (f"{top_results[0][0]:.2f}%"
                                if top_results else "n/a")
                    print(f"  [restart] T={SA_TEMP_START:.3f}  best={best_now}",
                          flush=True)

                result = _next_candidate()
                if result is None:
                    continue
                candidate, temperature = result

                trial += 1
                new_lines = candidate_to_lines(original_lines, regions, candidate)
                with open(src_path, "w", encoding="utf-8") as fh:
                    fh.writelines(new_lines)

                if use_direct:
                    build_ok = direct_build(src_path, obj_path)
                    score = (get_score_direct(target_obj,
                                              os.path.join(root_dir, obj_path),
                                              args.symbol)
                             if build_ok else None)
                else:
                    build_ok = ninja_build(obj_path)
                    score = (get_score(args.unit, args.symbol)
                             if build_ok else None)

                _process_result(score, candidate, new_lines, temperature)

        finally:
            restore_lines = original_lines
            if args.apply_best and top_results:
                best_score, _, best_lines = top_results[0]
                restore_lines = best_lines
                print(f"\nApplying best result ({best_score:.2f}%) to source file.")
            with open(src_path, "w", encoding="utf-8") as fh:
                fh.writelines(restore_lines)
            if not (args.apply_best and top_results):
                print("\nOriginal source file restored.")

    else:
        # ── Multi-threaded path ───────────────────────────────────────────────
        # Each worker gets its own temp .cpp + temp .o so they don't collide.
        work_q: queue.Queue = queue.Queue(maxsize=n_jobs * 2)
        result_q: queue.Queue = queue.Queue()
        stop_event = threading.Event()

        dash = Dashboard(n_jobs, args.symbol, total_trials)

        # Create per-worker temp files (persistent so we don't re-create each trial)
        worker_tmps = []
        for _ in range(n_jobs):
            tf = tempfile.NamedTemporaryFile(
                suffix=".cpp", dir=os.path.join(root_dir, "src"),
                delete=False, mode="w", encoding="utf-8",
            )
            tf.close()
            tmp_src = tf.name
            tmp_obj = tmp_src.replace(
                os.path.join(root_dir, "src"),
                os.path.join(root_dir, "build",
                             "SLUS-21642-PROTO-070901", "src"),
            ).removesuffix(".cpp") + ".o"
            worker_tmps.append((tmp_src, tmp_obj))

        def worker(wid: int, tmp_src: str, tmp_obj: str) -> None:
            while not stop_event.is_set():
                try:
                    item = work_q.get(timeout=0.1)
                except queue.Empty:
                    continue
                if item is None:
                    break
                candidate, new_lines, temperature = item
                with open(tmp_src, "w", encoding="utf-8") as fh:
                    fh.writelines(new_lines)
                build_ok = direct_build(tmp_src, tmp_obj)
                if build_ok:
                    abs_tmp_obj = (os.path.join(root_dir, tmp_obj)
                                   if not os.path.isabs(tmp_obj) else tmp_obj)
                    score = get_score_direct(target_obj, abs_tmp_obj,
                                             args.symbol)
                else:
                    score = None
                result_q.put((wid, score, candidate, new_lines, temperature, tmp_obj))
                work_q.task_done()

        threads = [
            threading.Thread(target=worker,
                             args=(i,) + tmps, daemon=True)
            for i, tmps in enumerate(worker_tmps)
        ]
        for t in threads:
            t.start()

        def _process_mt(
            wid: int,
            score: Optional[float],
            candidate: Candidate,
            new_lines: List[str],
            temperature: float,
            worker_obj: str,
        ) -> None:
            nonlocal trial, sa_current
            sa_tag = ""
            if score is not None and args.guided:
                accepted, sa_tag = _sa_accept(score, temperature)
                if accepted:
                    sa_current = (score, candidate)
            if score is not None:
                prev_best = top_results[0][0] if top_results else -1.0
                top_results.append((score, candidate, new_lines))
                top_results.sort(key=lambda x: -x[0])
                del top_results[args.top:]
                if top_results[0][0] > prev_best:
                    save_live_results(live_path, top_results, regions, trial,
                                      total_trials, args.unit, args.symbol,
                                      args.float_temps, args.guided)
                if args.record and score >= args.record_threshold:
                    record_trial(args.record, trial, score, args.symbol,
                                 worker_obj, new_lines, candidate, regions)
            best = top_results[0][0] if top_results else 0.0
            # Build a short snippet from the first reordered line
            snippet = " —"
            if candidate.expanded:
                exp = candidate.expanded[0]
                perm = candidate.perms[0]
                if exp and perm:
                    snippet = exp[perm[0]].strip()[:35]
            dash.update(wid, score, sa_tag, snippet,
                        trial, best, temperature)

        try:
            pending = 0
            while not total_trials or trial < total_trials:
                # Restart check
                if (args.guided and sa_cycle > 0
                        and sa_cycle % SA_RESTART == 0):
                    if top_results:
                        sa_current = (top_results[0][0], top_results[0][1])
                    else:
                        sa_current = None
                    sa_cycle = 0
                    # Double restart temperature each cycle (up to SA_TEMP_MAX)
                    SA_TEMP_START = min(SA_TEMP_MAX, SA_TEMP_START * 2.0)

                # Drain completed results
                while not result_q.empty():
                    wid, score, cand, lines, temp, wobj = result_q.get_nowait()
                    trial += 1
                    pending -= 1
                    _process_mt(wid, score, cand, lines, temp, wobj)

                # Top up the work queue
                while pending < n_jobs * 2:
                    if total_trials and trial + pending >= total_trials:
                        break
                    result = _next_candidate(force_random=True)
                    if result is None:
                        continue
                    cand, temperature = result
                    new_lines = candidate_to_lines(
                        original_lines, regions, cand)
                    work_q.put((cand, new_lines, temperature))
                    pending += 1

                # Block until at least one result arrives
                if pending > 0 and result_q.empty():
                    try:
                        wid, score, cand, lines, temp, wobj = result_q.get(
                            timeout=0.5)
                        trial += 1
                        pending -= 1
                        _process_mt(wid, score, cand, lines, temp, wobj)
                    except queue.Empty:
                        pass  # loop back and retry

        except KeyboardInterrupt:
            pass  # fall through to finally for clean shutdown
        finally:
            stop_event.set()
            for _ in threads:
                try:
                    work_q.put_nowait(None)
                except queue.Full:
                    pass
            for t in threads:
                t.join(timeout=3)
            dash.finish()
            # Clean up temp files
            for tmp_src, tmp_obj in worker_tmps:
                for f in (tmp_src, tmp_obj):
                    try:
                        os.remove(f)
                    except OSError:
                        pass

            restore_lines = original_lines
            if args.apply_best and top_results:
                best_score, _, best_lines = top_results[0]
                restore_lines = best_lines
                print(f"\nApplying best result ({best_score:.2f}%) to source.")
            with open(src_path, "w", encoding="utf-8") as fh:
                fh.writelines(restore_lines)
            if not (args.apply_best and top_results):
                print("\nOriginal source file restored.")

    # ── Report ────────────────────────────────────────────────────────────────
    if not top_results:
        print("\nNo successful builds — nothing to report.")
        return

    print(f"\n{'=' * 64}")
    print(f"TOP {min(args.top, len(top_results))} RESULTS  (out of {trial} trials)")
    print(f"{'=' * 64}")

    for rank, (score, candidate, _) in enumerate(top_results, 1):
        print(f"\n#{rank}  {score:.2f}%")
        print(fmt_candidate(regions, candidate))

    # ── Save to research/perm_results.md ──────────────────────────────────────
    research_dir = os.path.join(root_dir, "research")
    os.makedirs(research_dir, exist_ok=True)
    out_path = os.path.join(research_dir, "perm_results.md")

    import datetime
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(f"# Permuter results — {timestamp}\n")
        fh.write(f"Unit: `{args.unit}`  \n")
        fh.write(f"Symbol: `{args.symbol}`  \n")
        fh.write(f"Trials: {trial} / {total_trials}  \n")
        fh.write(f"Flags: float-temps={'on' if args.float_temps else 'off'}"
                 f"  guided={'on' if args.guided else 'off'}  \n\n")

        for rank, (score, candidate, _) in enumerate(top_results, 1):
            fh.write(f"## #{rank}  {score:.2f}%\n\n")
            for ridx, (_, _, name, _, _) in enumerate(regions):
                exp = candidate.expanded[ridx]
                perm = candidate.perms[ridx]
                fh.write(f"**[{name}]** order: `{list(perm)}`\n\n")
                fh.write("```cpp\n")
                for i in perm:
                    entry = exp[i]
                    if entry.startswith(_PERM_ATOM_TAG):
                        fh.write(entry[len(_PERM_ATOM_TAG):])
                    else:
                        fh.write(entry)
                fh.write("```\n\n")

    print("\nResults saved to: research/perm_results.md")
    print("To write the best result to the source file, add --apply-best.")


if __name__ == "__main__":
    main()
