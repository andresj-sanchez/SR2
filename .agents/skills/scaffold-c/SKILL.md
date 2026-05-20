# Skill: scaffold-c

# Pure-C SDK Scaffold Workflow

Use this skill when filling missing declarations for SDK/library C headers under `include/usr/local/...`.

This workflow is for declarations only. Do not implement functions from this queue unless the user separately asks for C implementation work.

## Queue First

Read `docs/scaffold-c-queue.md`. Prefer the first unchecked row in `## Function Prototype Queue` unless the user named a specific symbol/header. When no function rows remain, continue with `## Data And Type Declaration Queue`.

Regenerate the queue when needed:

```sh
python tools/decomp-workflow.py scaffold-c-queue
```

The generator is report-only. It does not edit headers.

## Phase 1: Gather Information

The C++ class scaffold command is not the right entrypoint for function rows, but it can be useful as an extra layout/dependency probe for struct/class rows:

```sh
python tools/decomp-workflow.py scaffold -c ClassName --deps-deep
python tools/decomp-workflow.py scaffold -c ClassName --deps-deep --no-line-lookup
python tools/decomp-workflow.py scaffold -c ClassName --sections 1,2,3,5,8 --no-line-lookup
```

Use it only for SDK C `class`/`struct` queue rows when you want a quick DWARF layout and dependency summary. Do not follow its C++ next steps literally: it may suggest `include/<path>/<ClassName>.hpp`, C++ `class`, `public:`, and `.cpp` stub work. For pure-C SDK work, the canonical destination remains the queue's `include/usr/local/...` header and DWARF `class` must become C `struct`.

Do not use `scaffold -c` for function rows. It expects a DWARF struct/class and will usually report `NO DWARF STRUCT` for a C function. For functions, use `lookup.py function` and the queue's unit/header evidence instead.

For each C SDK row, gather evidence with C-compatible tools instead:

```sh
rg "\bSYMBOL\b" include/usr/local src/usr/local
python tools/lookup.py function SYMBOL
python tools/lookup.py struct SYMBOL
python tools/lookup.py enum SYMBOL
python tools/elf_lookup.py 0xADDRESS
```

Use only the lookup commands that match the row kind. For example, function rows normally need `rg` plus `lookup.py function`; struct/class rows need `rg` plus `lookup.py struct`; globals with non-zero addresses may also need `elf_lookup.py`.

If the queue row points at a specific source unit, inspect nearby source and validation ownership through the suggested validation command. If an address needs source-line ownership, use the line-lookup skill/tooling.

Future tool idea: a dedicated `scaffold-c-info` command could bundle the queue row, existing declaration search, DWARF lookup, and ELF initializer evidence. Until that exists, use the commands above.

## Scope

Canonical declaration targets are pure-C SDK/library headers under:

- `include/usr/local/sega/`
- `include/usr/local/cri/`
- `include/usr/local/sce/`
- `include/usr/local/metrowerks/`

Likely source validation units live under matching `src/usr/local/...` paths.

## Rules

- Treat DWARF as evidence, not ground truth.
- Confirm each row against nearby source, existing headers, and DWARF before editing.
- Keep SDK headers C-compatible: no `class`, no `public:`, no `private:`, no C++ references, no namespaces.
- If DWARF says `class Foo` for an SDK C header, declare it as `struct Foo` in the C header.
- Use existing SDK typedef style in the target header. Do not force SR2 C++ naming conventions into vendor headers.
- Do not duplicate a declaration that already exists in another canonical SDK header. Include or move only when ownership is clear.
- Prefer forward declarations for pointer-only uses when layout is not needed.
- Preserve existing include guard and formatting style in the target header.

## Evidence Checklist

For each queue row, gather enough evidence before editing:

```sh
python tools/lookup.py struct SYMBOL
python tools/lookup.py enum SYMBOL
python tools/lookup.py function SYMBOL
python tools/elf_lookup.py 0xADDRESS
```

Use the commands that match the row kind. For globals with non-zero addresses, `elf_lookup.py` can confirm initializer bytes or strings.

Search current declarations before adding anything:

```sh
rg "\bSYMBOL\b" include/usr/local src/usr/local
```

## Declaration Guidance

### Structs

- Convert DWARF `class` to C `struct`.
- Preserve member order, names, offsets, and sizes from DWARF when layout is needed.
- Add gap comments only when needed to explain unknown storage.
- Use types already used by nearby SDK headers where possible.

### Enums

- Add the enum to the canonical header suggested by the queue only after checking for same-name enums elsewhere.
- If values are ambiguous or multiple variants exist, leave a `TODO` comment and do not merge variants blindly.

### Typedefs

- Keep typedefs C-compatible.
- Prefer canonical SDK names over project-local aliases.

### Globals

- Header declarations should normally be `extern` unless the existing SDK header uses another convention.
- Confirm non-zero addresses and initializer evidence when available.
- Do not declare local statics in public headers.

### Functions

- Add prototypes only when the function belongs in a public/internal SDK header.
- Match DWARF parameter and return types as closely as possible, but adapt C++-only DWARF spelling to C-compatible spelling.
- Avoid adding C++ overloaded/operator/destructor symbols to C headers.

## Validation

After editing headers, run targeted formatting and validation for touched C/C++ files only:

```sh
clang-format -i include/usr/local/path/to/header.h
python tools/decomp-workflow.py validate include/usr/local/path/to/header.h src/usr/local/path/to/unit.c
```

If the queue row suggests a validation command, run that command.

Regenerate the queue after a batch:

```sh
python tools/decomp-workflow.py scaffold-c-queue
```

Then run:

```sh
git diff --check
git status --short
```

## Marking Progress

When a row is fully handled and validated, mark `[ ]` as `[x]` in `docs/scaffold-c-queue.md`. The generator preserves checked rows by the hidden `scaffold-c:` key when the same candidate remains.

If a row is a false positive, add a short note near the row or leave it unchecked and mention why in the final report. Do not add bogus declarations just to clear the queue.
