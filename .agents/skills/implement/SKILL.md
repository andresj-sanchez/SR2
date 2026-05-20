---
name: implement
description: Workflow for decompiling and iterating on a function.
---

# Function Implementation Workflow

Your goal is to decompile a specific function: writing C++ source that compiles to byte-identical object code against the original retail binary, verified via `decomp-diff.py`.

A function is not done until it is exact in both objdiff and normalized DWARF.

## Phase 1: Gather Context

Collect data from **all** of these sources in parallel where possible.

If the function was not already chosen for you, pick it with the ranking wrapper first:

```sh
python tools/decomp-workflow.py next --unit Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp --limit 10
python tools/decomp-workflow.py next --category game --limit 10
```

Prefer low-match, high-remaining targets here. Do not default to near-finished cleanup
functions unless the user explicitly wants a cleanup/refiner pass.

Use the wrapper flow first throughout this skill. Drop to raw `decomp-context.py` or
`decomp-diff.py` only when the wrapper is missing a specific flag or you are debugging.

On a new, suspicious, or recently updated worktree, start with:

```sh
python tools/decomp-workflow.py health --full Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp
```

Add `--timings` when you need to understand why wrapper/tool startup or the shared build
smoke is slow.

### 1a. decomp-context.py

Use `function` for initial context — it shows the **complete original assembly** (no
truncation), DWARF, Ghidra decompile, and source snippet all at once. Do this once at
the start, before writing any code.

```sh
python tools/decomp-workflow.py function -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
python tools/decomp-workflow.py function -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup" --brief
```

`diff` shows a git-style diff with hunk merging — use it in Phase 4 to track progress,
**not** as a substitute for `function` during context gathering.

```sh
python tools/decomp-workflow.py diff -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -d "clsPrfm::setup"
```

If the shared unit object is missing, the wrapper now rebuilds it automatically before
running `next --unit` / `function` / `diff`.

If you only need the PS2 Ghidra view (default), omit `--ghidra-version`. Add
`--ghidra-version gc` only if you have a Wii build set up.

The wrapper defaults to compact DWARF signatures. Add `--lookup-mode full` when you
need the full DWARF body with locals and nested inline info.

Add `--brief` when you want a shorter helper view; it trims suggested commands and
related-source hints while keeping the core source/status/diff context.

### 1b. Lookup skill

Reference the skill for the usage. It gives info based on the virtual address of the function.

### 1c. Existing source and header

- Read the headers for class layout, member types, field offsets and the source files for existing implementations and includes.
- Check parent class headers for inherited members/methods used in the function.
- Before adding any new declaration, check whether the type already exists with `python tools/find-symbol.py <TypeName>` (searches both `src/` and `include/`).
- If a repo header already exists for the type, include that header instead of introducing a local forward declaration.
- Preserve the original `class` vs `struct` kind. Verify the type kind from DWARF before writing a local declaration.
- Preserve real member names and field types. Do not introduce `pad`, `unk`, or `field_XXXX` members; verify from DWARF and leave a TODO when something is still uncertain.

### 1e. Assembly reference

If these don't provide enough detail, check the generated assembly. Use the Read tool
to open the relevant `.s` file:

```
build/SLUS-21642-PROTO-070901/asm/Develop/Projects/SR2/pgm/src/Object/Player/Performance.s
```

Search for the function label (mangled name) to navigate directly to its section.

### 1f. Related functions

If the function calls helpers or accesses types you're unfamiliar with, check their
declarations and any existing implementations for usage patterns.

## Phase 2: Analyze the Original

Before writing any code, understand what the original does by studying the Ghidra decompile
and assembly:

1. **Control flow** — identify switch/if-else structure, loops, early returns
2. **Function calls** — note which methods are called (`jal` = direct, `jalr` through
   vtable = virtual)
3. **Field access patterns** — trace `lw`/`lwc1`/`lbu`/`lb` at `offset($rN)` to identify
   which class members are read/written
4. **Stack frame** — `addiu $sp, $sp, -N` gives the frame size; count locals
5. **Calling convention** — `$a0`=this, `$a1`-`$a3`=int args, `$f12`/`$f14`=float args,
   `$v0`=return value; struct returns use `$a0` as hidden result pointer
6. **Bitfield operations** — `andi`/`ori`/`xori` with masks, or `sll`/`srl` + `andi`
   for packing/unpacking specific bits
7. **Const vs non-const** — affects which overload the linker resolves, visible as
   different `jal` targets in the diff

## Phase 3: Write the Implementation

### Placement in source file

Utilize the DWARF information that you get from the lookup skill heavily.

Don't add explanatory comments during implementation unless you need to document a remaining DWARF mismatch.

Don't use any temporary local variables that don't exist in the DWARF.

Always use the `f` suffix because the game doesn't use doubles.

Replace `if (upperBound > 0) {do {...} while(i < upperBound);}` with a simple `for` loop if it comes up.

Be aware that namespace info might be inconsistent between Ghidra and the DWARF; the DWARF often omits it.

Don't be confused by the local variables of inlines seen in the DWARF dump.

## Phase 4: Build, Diff, and Iterate

### Initial build

Before a Ninja build, run targeted validation when you changed headers, stubs, or guard/check tools:

```sh
python tools/decomp-workflow.py validate Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp
```

This does not invoke Ninja. It runs direct validators for the selected file and its counterpart, avoiding broad guard-stamp refresh during edit loops.

Rebuild the shared object the normal way before diffing. If you just need the
standard context flow, prefer
`python tools/decomp-workflow.py function -u <unit> -f <FunctionName>`.
For a rebuild plus a standardized diff run, use:

```sh
python tools/decomp-workflow.py build -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp
python tools/decomp-workflow.py diff -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -d "clsPrfm::setup"
python tools/decomp-workflow.py verify -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
```

If the build fails, fix compilation errors first.

If a guard/check tool changed, avoid repeatedly starting object builds: Ninja will rerun many stale guard/check stamps because those scripts are implicit dependencies. Use `decomp-workflow.py validate` until you need MWCC/objdiff output.

### Check the diff

```sh
# Quick status
python tools/decomp-workflow.py diff -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp --search "clsPrfm::setup" --limit 20

# Full instruction diff
python tools/decomp-workflow.py diff -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -d "clsPrfm::setup"
```

### Interpreting the diff (unified format)

- `-` lines = original binary, `+` lines = your decomp
- Args in `{}` show the specific mismatch within an instruction
- Context lines shown around each mismatch hunk
- Equal `- / +` counts in a hunk = register/offset rename; unequal = structural difference

### Fixing mismatches

After each meaningful edit/build iteration, run the combined verification gate first:

```sh
python tools/decomp-workflow.py verify -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
```

This fails unless both the instruction diff and normalized DWARF are exact.

If the verify gate fails because of DWARF, inspect the DWARF block diff directly:

```sh
python tools/decomp-workflow.py dwarf -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -f "clsPrfm::setup"
```

Pay attention to the `Range source ownership` summary. File mismatches are strong evidence
that an inline body came from the wrong header or owner file.

### Iterate

Repeat the build-diff cycle until the diff shows 100% match:

```sh
python tools/decomp-workflow.py build -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp
python tools/decomp-workflow.py diff -u Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp -d "clsPrfm::setup"
```

Every mismatched instruction is a signal — don't settle for "close enough".
Reaching 100% instruction matching is not enough. Stay in the loop until `verify`
passes, which means the DWARF of the function also matches after normalization.

## Phase 5: Report & Commit

Summarize:

- Final match status (percentage, instruction count)
- Final DWARF status (exact or remaining mismatch summary)
- What the function does (brief description)
- Key decisions or tricky patterns used to achieve the match
- If not fully matching, document remaining mismatches and theories

Commit each improvement separately — never batch milestones. Check progress first:

```sh
python tools/decomp-status.py --unit <unit.cpp>
```

Format: `42.1%: match clsPrfm::reset`

---

## Matching Philosophy

A function is done **only** when BOTH objdiff instruction match AND normalized DWARF are exact. 100% instruction match with DWARF mismatch = unfinished work.

Start from Ghidra output: get it to compile, verify DWARF, then hunt binary-level differences. Never dismiss a diff as "close enough" — every mismatched instruction means the source doesn't perfectly represent the original.

If you exhaust all options on a DWARF mismatch, add a comment to the function so future agents don't repeat the same dead ends.

Inlines at the bottom of a DWARF TU are emitted by usage, not by definition — their body belongs in the header, not `.cpp`.

When you notice a clear, safe workflow or tooling improvement, implement it rather than leaving the paper cut. Favor small surgical tuning to wrappers, helpers, error messages, and context-gathering defaults.

---

## Matching Tips

**Write like a human**: original code was written by humans. Natural C++ matches more often than compiler-optimized rewrites. Don't use temporaries absent from DWARF.

**Ghidra branch inversion**: Ghidra almost always inverts `if` branch logic — fix by inverting the condition and swapping the two code paths.

**DWARF locals as ground truth**: every DWARF local must exist, named exactly as shown. Every local NOT in DWARF is a spurious temporary — remove it.

**Store ordering**: MWCC reorders stores. Try different sequences. Initializer lists make store order deterministic — if order is wrong, move initializations to function body instead.

**Virtual vs direct calls**:
- `jal` to fixed address = non-virtual call
- `lw + jalr` through vtable pointer = virtual dispatch
- Wrong call kind in diff → `const` qualifier on method or object pointer is wrong — check DWARF

**Register allocation**: MWCC is sensitive to expression decomposition. Try splitting or merging sub-expressions to change intermediate register usage.

**Inlines**: body belongs in header. Use `line_lookup` skill to find which header owns it.

---

## Discovered Matching Patterns

Add entries when a source-level trick achieves a non-obvious match. TU-specific dead ends do not belong here — only generalizable wins.

Format: `### ShortDescription` / `TU: path | Function: name` / description

<!-- Add new entries below this line -->
