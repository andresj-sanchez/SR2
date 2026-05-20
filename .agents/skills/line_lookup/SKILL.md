---
name: line-lookup
description: Use this skill when an SR2 decompilation task needs source ownership evidence for a concrete text address. Trigger when the user gives a hex address, asks which file owns a function/inline/class, or when existing workflow output asks for manual line-info confirmation. Do not use it as the default path for scaffold-c queue rows; those already carry DWARF unit-path evidence.
---

# SR2 Address-Line Lookup

`tools/line_lookup.py` reads SR2 objdump line-number output and shows source annotations around an address. It is useful for address-level ownership questions, especially when inlined code points back to a header.

For normal workflows, prefer the higher-level tools first:

- `python tools/decomp-workflow.py scaffold -c ClassName --deps-deep` already runs line lookup unless `--no-line-lookup` is passed.
- `python tools/decomp-workflow.py function -u <unit.cpp> -f "Func"` and `dwarf`/`verify` use existing unit/function context.
- `docs/scaffold-c-queue.md` already groups C SDK rows by DWARF unit paths, so line lookup is only a fallback if you need extra address-level confirmation.

## When To Use

Use line lookup when you have an address and need to answer one of these:

- Which source or header file is annotated at this instruction?
- Is this instruction from an inline expanded out of a header?
- Do nearby addresses point to the same translation unit?
- Does a source path from DWARF/source ownership look plausible?

Do not use it to guess struct layouts or function signatures. Use DWARF lookup for that.

## Command

```sh
python tools/line_lookup.py symbols/sr2_line_info.nothpp 0x100234
python tools/line_lookup.py symbols/sr2_line_info.nothpp 100234
```

The script prints 50 entries before and 50 entries after the closest source-annotated address. Exact matches are marked with `>>>`. Multiple `>>>` entries at the same address mean multiple source annotations, usually due to inlines.

## Input File

The SR2 line-info file is:

```sh
symbols/sr2_line_info.nothpp
```

It is objdump interleaved disassembly with line numbers for `SLUS-21642-PROTO-070901`.

The script also supports rebuilt temporary line-info files produced by project tools, for example during health checks or DWARF comparisons.

## Reading Output

Focus on SR2-relevant source paths:

- `C:/Develop/Projects/SR2/pgm/src/...` maps to `src/Develop/Projects/SR2/pgm/src/...` for source files and `include/Develop/Projects/SR2/pgm/src/...` for headers.
- `C:/usr/local/...` maps to SDK/library paths under `src/usr/local/...` or `include/usr/local/...`.
- Repeated nearby paths usually identify the owning translation unit.
- Header paths at the exact address often identify an inline source location.
- Middleware/STL/runtime paths may be support code, not the game owner; check nearby SR2 paths too.

If the closest address is not exact, try another instruction address inside the same function. Some instructions have no source annotation.

## Example

```sh
python tools/line_lookup.py symbols/sr2_line_info.nothpp 0x13D000
```

Use this when a function/DWARF row shows an address such as `0x13D000 -> 0x13D0AC` and you need to inspect source annotations around that range.

## Relationship To Scaffold-C

For `docs/scaffold-c-queue.md`, do not run line lookup by default. The queue already uses `symbols/DwarfByUnit/index.json` unit paths and suggests a validation source. Use line lookup only if a row has conflicting evidence or if an address-level source annotation would resolve ambiguity.
