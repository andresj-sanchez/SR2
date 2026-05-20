#!/usr/bin/env python3
"""Fix raw scalar types in .hpp/.cpp files to use SR2 typedefs.

Replaces all raw C++ scalar types with SR2 typedefs, handling compound types
like 'unsigned int', 'unsigned char', etc. atomically so they don't get
partially replaced (e.g. 'unsigned char' must become 'u8', not 'unsigned c8').

Order of replacements matters: multi-word types must be processed before
their constituent single-word types.
"""

import argparse
import re
import sys

# Multi-word types first, then single-word. Each tuple is (regex_pattern, replacement).
# We use a single pass with alternation to avoid partial replacements.
PATTERN = re.compile(
    r"\b"
    r"(?:"
    r"unsigned long long"
    r"|signed long long"
    r"|unsigned int"
    r"|signed int"
    r"|unsigned short"
    r"|signed short"
    r"|unsigned char"
    r"|signed char"
    r"|unsigned long"
    r"|signed long"
    r"|long long"
    r"|signed long"
    r"|unsigned"
    r"|int"
    r"|char"
    r"|float"
    r"|double"
    r"|short"
    r"|long"
    r")"
    r"\b"
)

# Map from matched word to SR2 typedef
TYPE_MAP = {
    "unsigned long long": "u64",
    "signed long long": "s64",
    "unsigned int": "u32",
    "signed int": "s32",
    "unsigned short": "u16",
    "signed short": "s16",
    "unsigned char": "u8",
    "signed char": "s8",
    "unsigned long": "u32",
    "signed long": "s32",
    "long long": "s64",
    "unsigned": "u32",
    "int": "s32",
    "char": "c8",
    "float": "f32",
    "double": "f64",
    "short": "s16",
    "long": "s32",
}


def fix_file(path: str) -> int:
    with open(path, "r") as f:
        content = f.read()

    original = content

    # Process multi-word types first (they contain single words, so must come first)
    multi_word = [
        ("unsigned long long", "u64"),
        ("signed long long", "s64"),
        ("unsigned int", "u32"),
        ("signed int", "s32"),
        ("unsigned short", "u16"),
        ("signed short", "s16"),
        ("unsigned char", "u8"),
        ("signed char", "s8"),
        ("unsigned long", "u32"),
        ("signed long", "s32"),
        ("long long", "s64"),
    ]

    for raw, typedef in multi_word:
        content = re.sub(r"\b" + re.escape(raw) + r"\b", typedef, content)

    # Then single-word types
    single_word = [
        ("unsigned", "u32"),
        ("int", "s32"),
        ("char", "c8"),
        ("float", "f32"),
        ("double", "f64"),
        ("short", "s16"),
        ("long", "s32"),
    ]

    for raw, typedef in single_word:
        content = re.sub(r"\b" + re.escape(raw) + r"\b", typedef, content)

    if content != original:
        with open(path, "w") as f:
            f.write(content)
        print(f"  Fixed: {path}")
        return 1
    print(f"  Clean: {path}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Fix raw scalar types to SR2 typedefs")
    parser.add_argument("files", nargs="+", help="Files to fix")
    args = parser.parse_args()

    any_fixed = False
    for path in args.files:
        if fix_file(path):
            any_fixed = True

    sys.exit(1 if any_fixed else 0)


if __name__ == "__main__":
    main()
