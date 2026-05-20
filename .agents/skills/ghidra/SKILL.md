---
name: ghidra
description: Ghidra CLI tool reference
---

# Ghidra CLI

The project contains two programs:

- `SLUS_216.42` — PS2 build (primary). Use this for all current decompilation work.
- `main.dol` — Wii build (future). Not yet usable — PowerPC language pack not installed.

Switch between them with `--program <name>`. Default is PS2 (`SLUS_216.42`).

Use `-o compact` for shorter output in the CLI. Use `-o json` for machine-readable output when scripting.

```sh
ghidra set-default project SR2          # set default project
ghidra decompile 0x001E1EC0 -o compact  # decompile function at address
ghidra find function "clsPrfm"          # search by name
ghidra type get "clsPrfm"               # struct layout
ghidra disasm 0x001E1EC0 -n 30 -o compact  # raw disassembly
```

Note: Ghidra uses short demangled names (e.g. `clsPrfm` matches all methods on that class).
Use the address from `config/SLUS-21642-PROTO-070901/symbol_addrs.txt` for precise lookups.

**Important:** Ghidra has no concept of `const`. All pointers, references, and member
functions appear non-const in Ghidra output. Never infer const-qualification (or lack
thereof) from Ghidra decompilation — use the DWARF info from the `lookup` skill instead.

#### Disassembly

Ghidra's disassembly output is fine for quick reference, but it's better to reference
the ASM files in `build/SLUS-21642-PROTO-070901/asm/` which contain more information
(symbol names, relocation targets, data values) and are easily grepable.
