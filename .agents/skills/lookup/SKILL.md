---
name: game-lookup
description: Query structs, enums, functions, globals, typedefs from DWARF dump. Use before writing any type, offset, or signature — never guess layouts.
---

# lookup.py — Symbol Queries

## Data Source: `./symbols/Dwarf`

- `globals.nothpp` — structs, enums, typedefs, global variable declarations
- `functions.nothpp` — function bodies with address annotations

## Commands

```sh
python tools/lookup.py struct clsPrfm
python tools/lookup.py enum eCtrlMode
python tools/lookup.py enum clsPrfm::eState          # nested: StructName::EnumName
python tools/lookup.py function 0x001E1410           # hex address; matches start or end of Range annotation
python tools/lookup.py global g_pfSystem
python tools/lookup.py typedef stcData

python tools/lookup.py <folder> <kind> <query>       # alternate folder
python tools/lookup.py --file <path> <kind> <query>  # single combined file
```

Valid kinds: `struct`, `enum`, `function`, `global`, `typedef`

Multiple struct variants (forward decl vs full def) are printed separated by blank lines — use the one with full field layout.

## Rules

**Before declaring any symbol** — always run `find-symbol.py` first:
```sh
python tools/find-symbol.py clsPrfm
python tools/find-symbol.py clsPrfm --type class
python tools/find-symbol.py eCtrlMode --type enum
python tools/find-symbol.py stcData --type typedef
```
- Found in `./src/` → include that header, **do NOT redeclare**
- "Safe to declare" → declare using DWARF as source of truth

This applies to all: `struct`/`class`, `enum`/`enum class`, global variables, `typedef`, any named type.

**`struct` vs `class`**: no visibility modifiers in DWARF → `struct`; any `public:`/`private:`/`protected:` → `class`.

**Never guess field offsets or sizes** — always look them up.

**Function addresses**: always include `0x` prefix.

**Do not load entire files into context** — fetch only the symbol you need.

## Errors

| Error | Fix |
|-------|-----|
| `struct 'Foo' not found` | Try `_Foo`, `clsFoo`, or check if it is a typedef |
| `function '0x...' not found` | Confirm address; try end address instead of start |
| `enum 'Bar' not found` | Try `SomeStruct::Bar` (nested enum) |
| `'...' is not a directory` | Add `--file` flag |
| `a folder path is required` | Add folder arg or use `--file` |
