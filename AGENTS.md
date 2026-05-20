# SR2 Decompilation — Agent Guide

## Project

Sonic Riders: Zero Gravity (PS2) decompilation. Version: `SLUS-21642-PROTO-070901`

```sh
python configure.py && ninja   # first run downloads tools/compilers/binutils
```

## Naming & Formatting

- Naming conventions: `docs/naming-conventions.md` (prefixes, type codes)
- Architecture notes: `docs/architecture.md` (task framework, Obj/Task split, CRTP usage)
- Format touched C/C++ files only with `clang-format -i <file>` (C++03, LLVM-based, 4-space indent).
- Do not run `clang-format` on Python, Markdown, TOML, YAML, JSON, notes files, or tool scripts.

---

## Key Tools

### decomp-diff.py — Diff & symbol overview

```sh
# Overview
python tools/decomp-diff.py -u <unit.cpp>
python tools/decomp-diff.py -u <unit.cpp> -s nonmatching -t function
python tools/decomp-diff.py -u <unit.cpp> -s missing -t function
python tools/decomp-diff.py -u <unit.cpp> --search clsPrfm

# Diff (always use demangled name: clsPrfm::reset, not reset__7clsPrfmFv)
python tools/decomp-diff.py -u <unit.cpp> -d "clsPrfm::reset" --unified
python tools/decomp-diff.py -u <unit.cpp> -d "clsPrfm::setup" --unified -C 5
python tools/decomp-diff.py -u <unit.cpp> -d "clsPrfm::setup" --reloc-diffs all
python tools/decomp-diff.py -u <unit.cpp> -d "clsPrfm::setup" -C 5          # side-by-side
```

Filters: `-t function,object`, `-s missing|matching|nonmatching|extra`, `--section .text`, `--search <pattern>`
Unified format: `-` = original, `+` = decomp. `@@ 0xOFFSET -N +N @@` = hunk location and instruction counts. Equal counts = register/offset rename; unequal = structural diff. Mismatched args in `{}`.

### decomp-workflow.py — Primary agent wrapper

Prefer this over manually chaining `decomp-context.py`, `decomp-diff.py`, `decomp-status.py`.

```sh
# Scaffold
python tools/decomp-workflow.py scaffold -c ClassName --deps-deep
python tools/decomp-workflow.py scaffold -c ClassName --deps-deep --no-line-lookup --enum enmStatus
python tools/decomp-workflow.py scaffold-queue --skip-prefixes hk,Nn,Pf
python tools/decomp-workflow.py scaffold-next --skip-prefixes hk,Nn,Pf

# Unit overview
python tools/decomp-workflow.py unit -u <unit.cpp>
python tools/decomp-workflow.py unit -u <unit.cpp> --search clsPrfm --limit 20

# Function work (preferred entrypoint — bundles source, objdiff, Ghidra)
python tools/decomp-workflow.py function -u <unit.cpp> -f "clsPrfm::setup"
python tools/decomp-workflow.py function -u <unit.cpp> -f "clsPrfm::setup" --brief
python tools/decomp-workflow.py diff -u <unit.cpp> -d "clsPrfm::setup"
python tools/decomp-workflow.py verify -u <unit.cpp> -f "clsPrfm::setup"
python tools/decomp-workflow.py dwarf -u <unit.cpp> -f "clsPrfm::setup"

# Build
python tools/decomp-workflow.py build -u <unit.cpp>

# Targeted validation (no Ninja; avoids broad guard-stamp refresh after tool edits)
python tools/decomp-workflow.py validate <file-or-unique-basename> [...]
python tools/decomp-workflow.py validate <file-or-unique-basename> --no-related

# Next target
python tools/decomp-workflow.py next --category game --limit 10
python tools/decomp-workflow.py next --unit <unit.cpp> --limit 5

# Health check (run first on new/updated worktree)
python tools/decomp-workflow.py health
python tools/decomp-workflow.py health --full <unit.cpp>
python tools/decomp-workflow.py health --full <unit.cpp> --timings
```

**Key behaviors**:
- `verify` fails unless BOTH objdiff instruction match AND normalized DWARF are exact
- `dwarf` shows normalized DWARF diff + range source ownership — use when `verify` fails
- `function --brief` trims suggested commands but keeps core status/diff/source data
- `next` strategies: `balanced` (default), `impact` (largest unmatched bytes first), `quick-wins` (low-match functions)
- `health`: if it reports missing `objdiff.json`/`build.ninja`, run `python configure.py` first
- `-u` flag accepts short filename, partial path, or full canonical form everywhere
- `validate` runs only direct checks for selected files (`source_guard`, `clang_check`, `stub_guard`, `c_guard`, `py_compile`) and does not invoke Ninja; use it after guard/tool edits or small scaffold changes before any full object build

**Work target bias**: getting 0%→80% is faster and higher leverage than 90%→100%. Bias toward low-match, high-remaining functions. Leave 85%+ polish for deliberate cleanup passes.

### Code Search

Use **ripgrep (`rg`)** for all text searches. Never use `grep`, `findstr`, or `Select-String` — they are slower and produce noisier output.

```sh
# Find a class definition or usage across headers
rg "clsPlayerTask" include/

# Find a function definition in source files
rg "clsPrfm::setup" src/

# Search for a type or member across both src and include
rg "stcSetDataDetail" include/ src/

# Case-insensitive search (e.g. for a symbol with unknown casing)
rg -i "survivalrelay" include/ src/

# List only file names that contain a pattern (no line content)
rg -l "clsPlayerTask" include/

# Restrict to a file type
rg "NNS_VECTOR" --type cpp include/

# Multiline / context: show 2 lines around each match
rg -C 2 "m_u32Flags" include/Develop/Projects/SR2/pgm/src/Task/
```

Use **ripgrep (`rg`)** for all text searches. Never use `grep`, `findstr`, or `Select-String` — they are slower and produce noisier output.

```sh
# Find a class definition or usage across headers
rg "clsPlayerTask" include/

# Find a function definition in source files
rg "clsPrfm::setup" src/

# Search for a type or member across both src and include
rg "stcSetDataDetail" include/ src/

# Case-insensitive search (e.g. for a symbol with unknown casing)
rg -i "survivalrelay" include/ src/

# List only file names that contain a pattern (no line content)
rg -l "clsPlayerTask" include/

# Restrict to a file type
rg "NNS_VECTOR" --type cpp include/

# Multiline / context: show 2 lines around each match
rg -C 2 "m_u32Flags" include/Develop/Projects/SR2/pgm/src/Task/
```

### Other tools

```sh
# Symbol lookup (see .github/skills/lookup/SKILL.md)
python tools/lookup.py struct clsPrfm
python tools/find-symbol.py clsPrfm --type class

# Line ownership (see .github/skills/line_lookup/SKILL.md)
# Accepts both 0xADDR: and bare ADDR: formats; works on symbols/debug_lines.txt

# String/rodata by virtual address
python tools/elf_lookup.py 0x5F2210
python tools/elf_lookup.py 0x5F2210 --mode bytes --length 32
python tools/elf_lookup.py 0x5F2210 --game ps2

# Progress
python tools/decomp-status.py
python tools/decomp-status.py --category game
python tools/decomp-status.py --unit <unit.cpp>
ninja build/SLUS-21642-PROTO-070901/report.json progress

# Demangle
build/tools/dtk demangle 'reset__7clsPrfmFv'
```

### Build commands

```sh
python tools/decomp-workflow.py validate <file-or-unique-basename> [...]  # focused guards/checks, no Ninja
ninja build/SLUS-21642-PROTO-070901/src/<path>.o     # build one object
python tools/ninja-errors.py                         # full build — prints ONLY failed blocks on failure (preferred)
python tools/ninja-errors.py build/SLUS-21642-PROTO-070901/src/<path>.o  # single object with clean error output
python tools/ninja-errors.py | rg "Fix:"            # pipe to rg to search across many errors — no tee needed
```
If "nothing to do" after header edit: `python -c "import os; os.utime('src/<path>.cpp', None)"` then rebuild.

If `tools/stub_guard.py`, `tools/source_guard.py`, `tools/clang_check.py`, or `tools/c_guard.py` changed, prefer `decomp-workflow.py validate` first. A Ninja build will correctly rerun stale guard/check stamps across many TUs because those scripts are implicit dependencies.

---

## Sub-Agent Usage

Sub-agents: **read-only exploration only** (search, inspect, gather context from tools).
Sub-agents must **not** write or edit any files.
All file changes done by main worker after reviewing findings.
**Limit: never run more than 5 sub-agents concurrently.**

---

## Forbidden Changes

Do **not** edit these files under any circumstances:
- `config/SLUS-21642-PROTO-070901/symbol_addrs.txt`
- `config/SLUS-21642-PROTO-070901/sonic.yaml`
- `configure.py`

Do **not** cheat objdiff/progress metrics in any way. The goal is to improve real decompilation output.

**Never** copy, overwrite, or symlink a compiled `.o` into `build/SLUS-21642-PROTO-070901/obj/` — that directory contains the original reference objects from the retail binary. Replacing them produces a false 100% match.

---

## Source Guard

Every `.hpp` under `include/Develop/Projects/SR2/pgm/src/` is auto-checked as a ninja pre-compile step. Three enforced rules:

1. **No raw scalar types** in struct/class members — use SR2 typedefs: `u8`/`s8`, `u16`/`s16`, `u32`/`s32`, `u64`/`s64`, `f32`, `f64` (from `#include "types.h"`)
2. **No `namespace clsFoo` or `namespace stcFoo`** — `cls`/`stc` prefix means class/struct; declare with correct keyword
3. **No redefinition** of shared types already in canonical headers (e.g. `NNS_VECTOR`, `NNS_MATRIX`)

Manual check: `python tools/source_guard.py include/Develop/Projects/SR2/pgm/src/Foo/Bar.hpp` — exit 0 = clean, exit 1 = errors with fix suggestions.
Run `source_guard.py` on one file per invocation; multi-file invocations are rejected because the optional second argument is reserved for Ninja stamp output.

---

## Scaffold Workflow

See `.github/skills/scaffold/SKILL.md`. **Re-read it at the start of any scaffold session and immediately after any compaction checkpoint** — compaction discards the detailed rules.

---

## Decompilation Workflow

See `.github/skills/implement/SKILL.md`.

---

## Key Paths

| | Path |
|-|------|
| Source stubs | `src/Develop/` (C++), `src/usr/` (C) |
| Headers | `include/Develop/` (C++), `include/usr/` (C) |
| ASM reference | `build/SLUS-21642-PROTO-070901/asm/` |
| DWARF type info | `symbols/Dwarf/` |
| Compiled objects | `build/SLUS-21642-PROTO-070901/src/` |
| Reference objects | `build/SLUS-21642-PROTO-070901/obj/` |

---

## Notes

- Compiler: MWCCPS2 3.0.1b198-051011 (via wibo on Linux/Mac)
- `MWCIncludes` warning is harmless — ignore
- MWCC enum scoping: same enum name can appear at global scope AND nested inside a class as independent declarations — do NOT assume they are aliases. The `[v USE THIS]` tag in scaffold identifies the correct body per class; the correct body for a specific function is only confirmed during decompilation.
- Use `const_cast` or C-style cast when returning non-const from a const member

---

## Matching Philosophy & Patterns

See `.github/skills/implement/SKILL.md`.
