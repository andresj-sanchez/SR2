#!/usr/bin/env python3
"""Reorder .cpp stub functions into source-line order.

Two modes:

  Auto (recommended — derive order from line info):
    python tools/reorder_stubs.py src/.../Foo.cpp

  Manual (explicit order):
    python tools/reorder_stubs.py src/.../Foo.cpp Class::Method1 Class::Method2 ...

In auto mode the tool queries the same symbol/line-info data that stub_guard uses,
sorts all anchored functions (those with known source line numbers) into ascending
order, and writes the file back in place.  Unanchored functions are appended after
the anchored block in their original relative order.

Handles both real implementations and commented-out Ghidra output blocks.
Uses the same _DEF_RE as stub_guard so both tools agree on what counts as a
function definition.
"""
import os
import re
import sys
from collections import OrderedDict
from typing import List, Optional, Tuple

# Ensure tools/ is on the path so _common imports work when run from repo root
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from _common import get_non_weak_funcs, sym_lineno  # noqa: E402

# Same pattern as stub_guard._DEF_RE — requires Class::method(
_DEF_RE = re.compile(r'\b(\w+)::(~?\w+)\s*\(')


def get_name(text: str) -> Optional[str]:
    """Return the fully-qualified function name from a block, or None."""
    for line in text.split('\n'):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        matches = list(_DEF_RE.finditer(line))
        if matches:
            # Last match avoids return-type class prefixes, e.g.:
            #   const clsPrfm::stcData* clsPrfm::getDataPtr() → getDataPtr
            m = matches[-1]
            return f"{m.group(1)}::{m.group(2)}"
    return None


def parse(text: str) -> Tuple[str, List[Tuple[Optional[str], List[str]]]]:
    """Return (prefix_text, [(full_name, block_lines), ...])."""
    lines = text.split('\n')
    prefix_lines: List[str] = []
    funcs: List[Tuple[Optional[str], List[str]]] = []
    brace = 0
    found_first = False
    cur: List[str] = []

    for line in lines:
        stripped = line.strip()
        count = line.count('{') - line.count('}')

        is_func_start = (
            brace == 0
            and _DEF_RE.search(line) is not None
            and not stripped.endswith(';')
            and not stripped.startswith('#')
        )

        if not found_first:
            if is_func_start:
                found_first = True
                cur = [line]
                brace += count
                if brace == 0 and any('{' in l for l in cur):
                    funcs.append((get_name('\n'.join(cur)), cur[:]))
                    cur = []
            else:
                prefix_lines.append(line)
                brace += count
        else:
            if cur:
                cur.append(line)
                brace += count
                if brace == 0 and any('{' in l for l in cur):
                    funcs.append((get_name('\n'.join(cur)), cur[:]))
                    cur = []
            else:
                if not stripped:
                    pass  # skip blank lines between functions
                elif is_func_start:
                    cur = [line]
                    brace += count
                    if brace == 0 and any('{' in l for l in cur):
                        funcs.append((get_name('\n'.join(cur)), cur[:]))
                        cur = []
                else:
                    # Preserve top-level constructs the Class::method matcher does
                    # not understand, such as namespace free-function stub blocks.
                    cur = [line]
                    brace += count
                    if brace == 0:
                        funcs.append((None, cur[:]))
                        cur = []

    if cur:
        funcs.append((get_name('\n'.join(cur)), cur[:]))

    return '\n'.join(prefix_lines), funcs


def reorder(text: str, desired: List[str]) -> str:
    """Return the file text with functions reordered per *desired*.

    Functions not in *desired* are appended after the anchored block in their
    original relative order.
    """
    prefix, funcs = parse(text)

    groups: OrderedDict = OrderedDict()
    for name, block in funcs:
        groups.setdefault(name, []).append(block)

    desired_set = set(desired)
    new_order = (
        [n for n in desired if n in groups] +
        [n for n in groups if n not in desired_set]
    )

    seen: set = set()
    deduped: List[str] = []
    for n in new_order:
        if n not in seen:
            seen.add(n)
            deduped.append(n)

    blocks = ['\n'.join(bl) for n in deduped for bl in groups[n]]
    return prefix.rstrip('\n') + '\n\n' + '\n\n'.join(blocks) + '\n'


def derive_order(path: str) -> List[str]:
    """Query line-info data and return the anchored function names in correct order.

    Uses the same logic as stub_guard's order checker so both tools agree.
    Unanchored functions are not included — reorder() will append them at the end.
    """
    with open(path, encoding='utf-8', errors='replace') as f:
        text = f.read()
    _prefix, funcs = parse(text)

    # Collect unique class names in file order
    classes: List[str] = []
    seen_cls: set = set()
    for name, _block in funcs:
        if name:
            cls = name.split('::')[0]
            if cls not in seen_cls:
                seen_cls.add(cls)
                classes.append(cls)

    # Build method → source line-number map
    method_linenos: dict = {}
    for cls in classes:
        for sym_line, _mangled, demangled in get_non_weak_funcs(cls):
            before_paren = demangled.split('(')[0].strip()
            parts = before_paren.rsplit('::', 1)
            method_name = parts[1].strip() if len(parts) == 2 else before_paren.strip()
            lineno = sym_lineno(sym_line)
            if lineno != 2**31:
                method_linenos[f"{cls}::{method_name}"] = lineno

    # Sort anchored functions by source line number
    names_in_file = [name for name, _block in funcs if name]
    anchored = sorted(
        [n for n in names_in_file if n in method_linenos],
        key=lambda n: method_linenos[n],
    )
    return anchored


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage:\n"
            "  python tools/reorder_stubs.py src/.../Foo.cpp          # auto\n"
            "  python tools/reorder_stubs.py src/.../Foo.cpp Cls::m1 Cls::m2 ...",
            file=sys.stderr,
        )
        sys.exit(1)

    path = sys.argv[1]
    desired = sys.argv[2:]

    with open(path, encoding='utf-8') as f:
        text = f.read()

    if not desired:
        desired = derive_order(path)
        if not desired:
            print(f'{path}: no anchored functions found — nothing to reorder')
            sys.exit(0)

    out = reorder(text, desired)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(out)
    if out == text:
        print(f'{path}: already in correct order ({len(desired)} anchored stubs)')
    else:
        print(f'Reordered {path} ({len(desired)} anchored stubs)')


if __name__ == '__main__':
    main()
