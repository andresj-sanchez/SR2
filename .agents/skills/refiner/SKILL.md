---
name: refiner
description: Workflow for resolving stubborn instruction mismatches in a function that the standard implementer has already attempted. Use when a function is stuck at 80–99% match and the obvious approaches have already been tried. Assumes the function compiles cleanly, a diff exists, and the implementer has already made one or more passes.
---

# Refiner Workflow

Your goal is to close the remaining instruction mismatches in a function that is partially
matching. The implementer has already made a pass. You must **not** repeat the same
approaches that were tried before — instead, apply systematic lateral analysis.

## Starting assumptions

- The function already compiles.
- A diff is available (`decomp-workflow.py diff -u <TU> -d <func>`).
- The "obvious" translation from Ghidra has been attempted.
- You have been given the current source code and the diff.

## Phase 1: Read the full diff without collapsing

Preferred shortcut:

```sh
python tools/decomp-workflow.py diff -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -d "clsPrfm::setup" --no-collapse
```

If the shared unit object is missing, the wrapper now rebuilds it automatically before
running `diff`.

Read every instruction pair. Categorize each mismatch:

| Category | Symptom | Strategy |
|---|---|---|
| **Branch inversion** | Entire blocks swapped, branch condition inverted | Invert the `if` condition and swap the two bodies |
| **Register pressure** | Same ops, different register allocation | Reorder source expressions; introduce/remove a named temp |
| **Stack frame size** | Wrong frame size in prologue (`addiu $sp, $sp, -N`) | Count locals in DWARF; remove temporaries not in DWARF |
| **Float vs int sequence** | Unexpected `mtc1`/`mfc1` sequences | Check field type in DWARF; verify cast (`int` vs `unsigned int`) |
| **`mul.s` operand order** | `mul.s $fX, $fX, $fY` vs `mul.s $fX, $fY, $fX` | Try `v *= fY` vs `fY * v` explicitly |
| **Relocation offset** | `@stringBase0` or data offset differs | More string literals will shift this; add them in order. Use `python tools/elf_lookup.py 0xADDR` to confirm |
| **Virtual vs direct call** | `jalr` through vtable vs `jal` direct | Check const-qualifier; virtual = vtable load + `jalr` |
| **Inline vs outlined** | Extra `jal` to helper vs inlined sequence | Force inline by rewriting the expression without calling the helper |
| **Loop structure** | Guarded `do/while` from Ghidra or mismatched loop branches | Rewrite to the natural `for` loop suggested by the control flow |

## Phase 2: Systematic permutation strategies

Try these **in order**, rebuilding and diffing after each:

When an edit only needs syntax/guard feedback, run targeted validation before rebuilding:

```bash
python tools/decomp-workflow.py validate Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp
```

This avoids triggering Ninja's broad guard-stamp refresh after guard/check tool edits. Use the normal build/diff path when you need updated MWCC output for objdiff.

### 2a. Temporaries

Remove any named temporary that is **not** in the DWARF, or add one that **is**.
Temporaries affect register allocation significantly.

```bash
python tools/lookup.py ./symbols/Dwarf function 0xADDR   # check for temps in DWARF
```

### 2b. Expression decomposition

Split or merge compound expressions. MWCC often schedules arithmetic differently when
sub-expressions are named:

```cpp
// Try decomposed:
float a = foo->x * bar;
float b = a + baz->y;
result = b;

// vs composed:
result = foo->x * bar + baz->y;
```

### 2c. Const-correctness

Check every method call in the diff against the DWARF. A const method resolves to a
different symbol than its non-const overload. Even one wrong const qualifier causes
a `jal` mismatch.

```bash
python tools/lookup.py ./symbols/Dwarf struct ClassName
```

### 2d. Constructor initialization placement

Only do this for constructors. Compare which members are initialized in the
initializer list versus the function body, and in what order. Initializer-list use
often stabilizes store order, but forcing every member into the initializer list can
also make the match worse.

### 2e. Cast type

`static_cast<int>` vs `static_cast<unsigned int>` can produce different instruction
sequences. Check all casts against the DWARF type.

## Phase 3: DWARF verification

After any instruction match, verify the DWARF also matches. The function is not done
until both objdiff and normalized DWARF are exact.

Preferred shortcut:

```bash
python tools/decomp-workflow.py verify -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
```

If the combined gate fails because of DWARF, inspect the DWARF diff directly with:

```bash
python tools/decomp-workflow.py dwarf -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
```

This gives you a normalized DWARF match percentage plus a diff-like report of what still
differs between the original and rebuilt DWARF blocks for that function.

DWARF mismatches to watch for:

- Extra or missing local variables (temporaries in DWARF = they must exist in source)
- Wrong parameter types or qualifiers
- Wrong return type
- Missing inlined function records (means an inline call was outlined)

## Phase 4: Report

Summarize:

- Final match % and instruction count
- What was blocking the match (the root cause category from Phase 1)
- The specific source change that resolved it
- Any new generalizable assembly pattern discovered
- DWARF match status and whether `verify` passes
- If still not matching: the exact diff lines that remain and your best theory
