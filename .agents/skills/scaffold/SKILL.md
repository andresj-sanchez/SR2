---
name: scaffold
description: Workflow for creating accurate .hpp/.cpp stubs from DWARF data.
---

# Class Scaffolding Workflow

## Discovery

**Always use the queue. `scaffold-next` is for manual/ad-hoc use only — do not use it in agent loops.**

### Step 1 — Check `docs/scaffold-queue.md` (required)

Read `docs/scaffold-queue.md`. Find the first `[ ]` row where `Deps = 0`. Run its `Command` verbatim.

After scaffolding, update the queue atomically:
- Mark the scaffolded row `[x]`.
- For every `[~]` row that lists this class in **Blocking Deps**: if ALL its deps are now `[x]`, change it to `[ ]` and set `Deps` to `0`.

When no `[ ]` Deps=0 rows remain, regenerate and then continue:
```sh
python tools/decomp-workflow.py scaffold-queue --skip-prefixes hk,Nn,Pf
```
Regenerating resets Status but already-scaffolded classes are excluded automatically.

`--skip-prefixes hk,Nn,Pf` limits **root discovery** to game/SR2 classes. If a queued
game class depends on a skipped-prefix type, the queue may still include that
`hk`/`Nn`/`Pf` type as a dependency row. Scaffold that dependency first when it is
listed by the queue; do not skip the game class or fake the dependency locally.

### `scaffold-next` — manual/ad-hoc only

Do **not** call `scaffold-next` in an agent loop. It ignores the queue's dependency ordering and progress tracking. Use it only for one-off lookups or searching:

```sh
python tools/decomp-workflow.py scaffold-next --skip-prefixes hk,Nn,Pf
python tools/decomp-workflow.py scaffold-next --skip-prefixes hk,Nn,Pf --simple-first
python tools/decomp-workflow.py scaffold-next --limit 1 --command-only --skip-prefixes hk,Nn,Pf
python tools/decomp-workflow.py scaffold-next --skip-prefixes hk,Nn,Pf --show-no-dwarf
python tools/decomp-workflow.py scaffold-next --skip-prefixes hk,Nn,Pf --stats-only
python tools/decomp-workflow.py scaffold-next --skip-prefixes hk,Nn,Pf --search clsFoo
```
`--search`: prints table row if found, or reason: `already scaffolded` / `no non-weak symbols` / `no DWARF struct` / `filtered by --skip-prefixes`.
Always pass `--skip-prefixes hk,Nn,Pf` for manual root discovery. This does not forbid scaffolding skipped-prefix dependency rows emitted by `scaffold-queue`.

---

## Phase 1: Gather Information

```sh
python tools/decomp-workflow.py scaffold -c ClassName --deps-deep
python tools/decomp-workflow.py scaffold -c ClassName --deps-deep --no-line-lookup   # skip slow line step
python tools/decomp-workflow.py scaffold -c ClassName --sections 1,2,5               # specific sections only
```
Always use `--deps-deep` — recursively resolves all nested struct types in one pass.

> **Ghidra bridge required for vtable (section 7) lookups.** Run once before scaffolding:
> ```sh
> ghidra start
> ```
> Success: `Bridge started on port 61780`. Already running: `Bridge is already running for project: ...` (both are fine).
> If section 7 shows no vtable data, the bridge is not running — start it and re-run the scaffold command.

**If section 3 has no DWARF struct**: skip during normal queue scaffolding. If a no-DWARF candidate must be scaffolded manually, gather context from `symbol_addrs.txt` and line info instead of inventing layouts:

```sh
python tools/no_dwarf_context.py nspGoalAnnounce2D
python tools/no_dwarf_context.py clsBackLineEffect_Begin_Task
python tools/no_dwarf_context.py --all
```

Use the output as follows:
- `Symbols` lists functions, globals, and vtables owned by the class/namespace via the MWCC owner suffix.
- `TU Candidates` gives likely `.cpp`/`.hpp` ownership from close source-line matches.
- `Line-Info References` shows call/reference sites from `symbols/sr2_line_info.nothpp`.
- Do not infer class member layout from no-DWARF data. For classes with only vtable/constructor/destructor/function symbols, declare only the inheritance and methods needed to compile, plus members proven by other sources.
- For namespace-only symbols, declare globals/functions in the owning header and define them in the owning `.cpp`.

### Middleware / External Dependency Rows

Havok/NNS/platform types are scaffolded only when they are required by a queued
game class. When this happens:

- Run the dependency row's `Command` exactly like any other queue row.
- Use the exact `.hpp`/`.cpp` paths from section 8's **Write these files:** block.
- Do not add new definitions to broad catch-all headers such as `Havok.hpp` or
  `NNS.hpp` unless section 8 says that specific TU owns the type.
- Prefer existing SDK sub-headers for already-declared NNS types; only create or
  fill project headers when DWARF/section 8 points there.
- If the type is only used through a pointer/reference and a forward declaration
  compiles, do not scaffold extra middleware classes just to make the queue move.

### Output Sections

| # | Section | What to extract |
|---|---------|----------------|
| 1 | Codebase Search | Class already exists → include that header instead |
| 2 | Symbol List | non-weak → `.cpp`; weak/inline → header body; statics → `static` in header + define in `.cpp` |
| 3 | DWARF Struct | Field names, types, offsets, sizes (this class only; inherited fields not repeated) |
| 3b | Base Class Summary | Parent size/fields/slot count. `⚠ PLACEHOLDER` → scaffold base first |
| 4 | Enum Ownership | Use body tagged `[v USE THIS]` |
| 5 | Dependency Check | Already declared / needs adding / `NOT IN DWARF` (forward-declare) / `⚠ PLACEHOLDER` (scaffold first) |
| 6 | Line Ownership | Read **`TU source file`** summary at section end — exact `.cpp`/`.hpp` paths (authoritative even when class name differs from TU filename) |
| 7 | Vtable | Slot order; slots 0–1 = null RTTI — skip |
| 8 | sonic.yaml | `asmtu` ≠ skip scaffolding — still create `.cpp`/`.hpp`. **`Write these files:`** block = exact paths to use |

### Section 2: Symbol List

**Vtable status line** — read before writing any signature:
- `⚠ NO VTABLE` → do NOT add `virtual` anywhere (section 3b base slot count is the BASE's vtable, not this class's)
- `✓ Vtable found` → only `[new]` and `[override]` slots from section 7 get `virtual`

**Non-weak functions** → full definitions in `.cpp`. `→ type` = DWARF return type; `→ (unknown)` = determine from ASM.

**Parameter naming**:
- DWARF names shown (e.g. `pcHitPlayer`, `fFrame`) → use exactly as-is in both `.hpp` and `.cpp` (`stub_guard` enforces this)
- No DWARF name → Hungarian prefix + `ParamN` (1-based): `s32Param1`, `u8Param1`, `pcParam1`, `pParam1`
- Partial DWARF: annotated params get DWARF names at their exact positions; remainder get Hungarian names
- Base class declaration and any override must use the same names (base takes precedence)

**clsTask-chain constructors**: copy the `// stub (...)` line verbatim. Do NOT define in both header and `.cpp` — causes redefinition error.

- When the immediate base is `clsTask`, the stub uses `(0, 0)` (task type + kind).
- When the immediate base is another `_Task` subclass, the stub forwards the derived constructor's param names. Always verify the forwarding call compiles — the base may have **extra** parameters beyond what the derived constructor receives (e.g. a trailing `f32WaitFrame = 0.0f`). Add those with their zero/default values.
- **Never** add base-class method stubs (e.g. `BaseClass::draw() {}`) to a derived-class TU — those are already defined in the base TU. `stub_guard` only requires stubs for symbols *owned by* the classes defined in the current `.cpp`.

**Weak destructors**: inline in header only. Do NOT define in `.cpp`.

**Weak/inline functions**: go in header body. Size hints (`// likely: ...`) are machine-derived — always verify against ASM:

| Size | Pattern | Hint emitted |
|------|---------|-------------|
| 8 | member load at offset | `return m_field;` / `return &m_field;` / `return m_composite.m_nested;` |
| 8 | inherited field offset | `return /* this[+0xXX] — likely inherited field */;` |
| 8 | addiu const | `return N;` |
| 8 | float pass-through | `return param;` |
| 8 | zero store | `m_field = nullptr;` / `m_field = 0;` |
| 12 | global/singleton (lui+lw) | `return SymbolName;` / `return /* global @ 0xXXXXXXXX */;` |
| 12 | two-hop pointer (lw+lw) | `return m_pcPtr->m_field;` / fallbacks with `?` for unresolved offsets |
| 16 | equality test | `return m_field == N;` |
| 16 | flag-test boolean | `return (m_field & param) != 0;` |
| 16 | increment/decrement | `m_field++;` / `m_field--;` |
| 20 | read-modify-write | `m_field += param;` / `m_field -= param;` |

Verify via ASM file `build/SLUS-21642-PROTO-070901/asm/<path>/<ClassName>.s` or `ghidra disasm <address> -n <count> -o compact`.

**Statics/globals**: `static <type> <name>;` in class body; `<type> ClassName::<name>;` in `.cpp`. Scalar values decoded from ELF shown inline (float literals, decimal integers with hex comment if ≥256, bool). Struct-typed statics with ≤16 fields show `fields (TypeName): field = value (offset 0xXX)`.

### Section 7: Vtable

> If section 7 is empty or missing, run `ghidra start` to start the bridge, then re-run the scaffold command.

Slots 0–1 are always null (RTTI) — do not declare them.

| Tag | Action |
|-----|--------|
| `[new]` | Declare `virtual` in header |
| `[override of BaseClass::method]` | Declare `virtual` in header |
| *(no tag)* | Inherited unchanged — do NOT redeclare |

### Section 4: Enums

Use the `[v USE THIS]` body (DWARF cross-referenced). Multiple bodies with same name = independent declarations. Placement is provisional — confirm during decompilation.

**Namespaced enums** (e.g. `nspGear::enmGearCtrl`): declare inside `namespace nspGear { ... }`.

**`Q2`-qualified type resolution** (e.g. `clsPack::stcBinInfo`):
- `cls` prefix → `class` — forward-declare as `class clsPack;` (**never** `namespace clsPack {}` — compile error)
- `stc` prefix → `struct` — forward-declare as `struct stcFoo;`
- `nsp` prefix → `namespace` — declare as `namespace nspFoo { ... }`

**MWCC scoping warning** (section 5): if a `Q2`-qualified inner name also appears at global scope in DWARF → nest inner type inside outer class body.

**Enum name collisions**: same name in another header with different values → nest local variant inside class body with `// TODO` noting ambiguity.

---

## Phase 2: Write the Header

Reference: `docs/naming-conventions.md` (member/static/parameter prefixes, type codes).
Pattern: `git log --oneline --diff-filter=A -- 'include/**/*.hpp' | head -5` then `git show <hash> -- '*.hpp'`

| Rule | Detail |
|------|--------|
| Include guard | Derive from path under `include/Develop/Projects/SR2/pgm/src/`, uppercase, separators→`_`, append `_HPP`. Example: `Object/Player/Key/Foo.hpp` → `OBJECT_PLAYER_KEY_FOO_HPP` |
| Full include paths | `#include "Develop/Projects/SR2/pgm/src/2D/MsgWnd2D.hpp"` — full path from `include/` root everywhere. Exceptions: `"types.h"` and `"usr/local/sega/..."` NNS sub-headers |
| `struct` vs `class` | No visibility modifiers in DWARF → `struct`; any `public`/`private` → `class` |
| Scalar types | Only SR2 typedefs: `u8`,`s8`,`u16`,`s16`,`u32`,`s32`,`u64`,`s64`,`f32`,`f64` (add `#include "types.h"`). Raw types → `source_guard.py` fails the build |
| Members | Preserve DWARF names, types, order, offset comments exactly. Gaps → `// TODO: gap 0xXX–0xYY` (never `pad`/`unk`/`field_XXXX`) |
| Foreign types | `find-symbol.py` first; if declared → include that header; if not → create dedicated header at canonical path (never inline foreign class body) |
| NNS sub-headers | `nnvector.h` (NNS_VECTOR/QUATERNION/TRS/SPHERE/CAPSULE), `nnobject.h` (NNS_NODE/OBJECT/MOTION/SUBMOTION), `nntexture.h` (_NNS_TEXLIST), `nndrawprim.h`, `nncamera.h`, `nnmorph.h`; `Object/ModelTypes.hpp` (clsModelType_OB_TX etc.) |
| Multi-class TUs | Two classes in same TU with cross-type method signatures → both in same `.hpp` in dependency order. Forward-declare only for pointer/reference params with no nested-type access |
| Paths | Always use exact paths from `Write these files:` in section 8 — never re-derive |

---

## Phase 3: Create Files and Build

SR2 does **not** use jumbo builds — each `.cpp` compiles directly.
**Use exact paths from `Write these files:` in section 8.**

1. **Create `.hpp`** and **`.cpp`** stub (empty function bodies + static definitions at file scope). Empty placeholders may already exist — write directly.
2. **Reorder stubs** (mandatory for touched scaffold `.cpp` files — always run even if order looks correct):
   ```sh
   python tools/reorder_stubs.py src/Develop/Projects/SR2/pgm/src/<path>.cpp
   ```
3. **Format touched C/C++ files only** (run after reorder). Use only for `.cpp`, `.c`, `.hpp`, `.h`, `.cc`, and `.hh` files:
   ```sh
   clang-format -i include/Develop/Projects/SR2/pgm/src/<path>.hpp src/Develop/Projects/SR2/pgm/src/<path>.cpp
   ```
   Do **not** run `clang-format` on Python, Markdown, TOML, YAML, JSON, notes files, or tool scripts.
4. **Fix scalar types** (only for touched scaffold C++ headers/sources):
   ```sh
   python tools/fix_scalar_types.py include/Develop/Projects/SR2/pgm/src/<path>.hpp src/Develop/Projects/SR2/pgm/src/<path>.cpp
   ```
5. **Targeted validation** — run direct guards/checks for touched files before invoking Ninja:
   ```sh
   python tools/decomp-workflow.py validate include/Develop/Projects/SR2/pgm/src/<path>.hpp src/Develop/Projects/SR2/pgm/src/<path>.cpp
   ```
   This runs `source_guard.py`, `clang_check.py`, `stub_guard.py`, `c_guard.py`, and `py_compile` as applicable without refreshing Ninja guard stamps. Use it especially after editing guard/check tools.
6. **sonic.yaml**: never edit. `asmtu` = still create `.cpp`/`.hpp` at the same path.

   For **commented-out entries**, check first:
   ```sh
   python tools/decomp-workflow.py build -u <Foo>.cpp
   ```
   - **Case A** (succeeds / "no work to do"): active entry exists → create `.hpp` + `.cpp` normally. Append note to `notes/pending-sonic-yaml.md`.
   - **Case B** ("not found in objdiff.json"): all entries commented out →
     - Create `.hpp` only; leave `.cpp` empty with `// TODO: add stubs when TU is uncommented`
     - Add to `docs/scaffold-skip.txt`: `clsFoo   # TU fully commented-out YYYY-MM-DD`
     - Append to `notes/pending-sonic-yaml.md`: `[ALL ENTRIES COMMENTED-OUT] path — Human action needed: uncomment entry in sonic.yaml`

7. **Build** — use `ninja-errors.py`; it discards `[N/M]` progress lines and prints only `FAILED` blocks with diagnostics. Never run the compiler directly.
   ```sh
   python tools/ninja-errors.py build/SLUS-21642-PROTO-070901/src/Develop/Projects/SR2/pgm/src/<path>.o
   ```
   The workflow wrapper resolves the ninja target automatically and is equivalent:
   ```sh
   python tools/decomp-workflow.py build -u <path>.cpp
   ```
   If "nothing to do" after a header edit — touch the `.cpp` to force recompile:
   ```sh
   python -c "import os; os.utime('src/Develop/Projects/SR2/pgm/src/<path>.cpp', None)"
   python tools/ninja-errors.py build/SLUS-21642-PROTO-070901/src/Develop/Projects/SR2/pgm/src/<path>.o
   ```
   > **Note:** The underlying command is `ninja <target>`. Raw `ninja -v 2>&1` is only needed when you specifically want to inspect compiler flags — never for reading errors.
   If a guard/check tool changed, expect Ninja to rerun many stale guard/check stamps. Do not repeatedly start object builds in that state; use targeted validation until you need MWCC output.
8. Fix compile errors and rebuild.

---

## Phase 4: Commit

```sh
git add include/<path>/<ClassName>.hpp src/<path>/<ClassName>.cpp
git commit -m "scaffold: add clsClassName stub"
```
Stage only the new/modified header and stub — not unrelated files.

## Phase 5: Report

```sh
python tools/decomp-workflow.py unit -u <unit>.cpp
```
The `-u` flag accepts short filename, partial path, or full canonical form.
Summarize: match status, list of unimplemented functions, any extra symbols needing attention.

## Notes

- Use **ripgrep (`rg`)** for all text searches. Never use `grep`, `findstr`, or `Select-String` — they are slower and produce noisier output.
