#!/usr/bin/env python3
"""Pre-build clang diagnostics check for .hpp and .cpp files.

Runs clang's syntax/type checker on the given files to catch
errors (wrong return types, unknown types, etc.) BEFORE MWCC compiles.
MWCC error messages are often cryptic and cascade — clang gives precise
diagnostics that point to the real issue.

Usage:
    python tools/clang_check.py include/path/to/File.hpp
    python tools/clang_check.py include/path/to/File.hpp src/path/to/File.cpp
    python tools/clang_check.py -I include/ include/path/to/File.hpp
"""

import argparse
import subprocess
import sys
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INCLUDE_ROOT = PROJECT_ROOT / "include"


def _clean_path(note: str) -> str:
    """Force absolute paths into repository-relative paths."""
    # 1. Extract the absolute path and the line/col numbers
    match = re.search(r'^(.+?):(\d+):(\d+):', note)
    if not match:
        return note

    abs_path_str, line, col = match.groups()
    try:
        # 2. Convert to Path object and find its position relative to PROJECT_ROOT
        abs_path = Path(abs_path_str).resolve()
        # This creates a path like 'src/Develop/...' or 'include/Develop/...'
        rel_path = abs_path.relative_to(PROJECT_ROOT.resolve())

        # 3. Extract the actual message (the part after the last colon of the path info)
        msg_parts = note.split(':', 4)
        msg = msg_parts[-1].strip() if len(msg_parts) > 4 else ""

        # 4. Return the format that helps the AI Agent the most
        return f"{rel_path}({line}, {col}): {msg}"
    except (ValueError, RuntimeError):
        # If the file isn't under PROJECT_ROOT, just return the filename
        return f"{Path(abs_path_str).name}({line}, {col}): {note.split(':', 4)[-1].strip()}"


def _is_allowed_mwccps2_bitfield_diag(error: str) -> bool:
    """Allow MWCCPS2 GS-register bitfields that host Clang rejects."""
    return (
        "include\\usr\\local\\sce\\ee\\lib\\eestruct.h" in error
        or "include/usr/local/sce/ee/lib/eestruct.h" in error
    ) and "width of bit-field" in error and "exceeds the size of its type" in error


def check_file(file_path: str, is_cpp: bool = False) -> int:
    """Run clang diagnostics on a .hpp or .cpp file. Returns 0 if clean, 1 if errors."""
    fpath = Path(file_path)
    if not fpath.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 2

    # Build clang command: syntax + type check, no code generation
    cmd = [
        "clang++",
        "-fsyntax-only",
        "-std=c++03",
        "-xc++",
        f"-I{INCLUDE_ROOT}",
        # NNS headers live under include/usr/local/sega/
        f"-I{INCLUDE_ROOT.parent / 'usr' / 'local' / 'sega'}",
        # OO lib headers
        f"-I{INCLUDE_ROOT.parent.parent / 'lib'}",
        # Source include path (for #include "Develop/..." in .cpp files)
        f"-I{Path.cwd() / 'src'}",
        # MWCC-compatible: no RTTI, no exceptions
        "-fno-rtti",
        "-fno-exceptions",
        # Treat warnings as errors for common issues
        "-Werror=return-type",
        "-Werror=unknown-types",
        "-Werror=implicit-int",
        "-Werror=member_decl_does_not_match",
        # Extra checks
        "-Wall",
        "-Wextra",
        str(fpath),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        # Parse clang output into diagnostic groups: each error may have
        # associated "note:" lines pointing to related locations.
        raw_lines = result.stderr.splitlines()
        diagnostics = []
        current_diag = None

        for line in raw_lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Start a new diagnostic group on error/fatal lines
            if "error:" in stripped.lower() or "fatal error" in stripped.lower():
                if current_diag:
                    diagnostics.append(current_diag)
                current_diag = {"error": stripped, "notes": []}
            elif current_diag and ": note:" in stripped.lower():
                # Note with file location: "file.hpp:100:9: note: previous declaration is here"
                current_diag["notes"].append(stripped)
            elif current_diag and stripped.lower().startswith("note:"):
                # Bare note: "note: previous declaration is here"
                current_diag["notes"].append(stripped)
            elif current_diag and line.startswith("line "):
                # Source line context: "line 3: void clsCamCtrl::countUpTime() {}"
                current_diag["notes"].append(stripped)

        if current_diag:
            diagnostics.append(current_diag)

        diagnostics = [
            diag
            for diag in diagnostics
            if not _is_allowed_mwccps2_bitfield_diag(diag["error"])
        ]

        if diagnostics:
            print(f"=== clang diagnostics for {fpath.name} ===")
            for diag in diagnostics:
                error = diag["error"]
                error_lower = error.lower()

                # --- EXPLICIT ERROR FORMATTERS FOR AI AGENT ---

                # 1. REDEFINITION
                if "redefinition" in error_lower and "enumerator" not in error_lower:
                    sym_match = re.search(r"redefinition of '([^']+)'", error)
                    sym = f"'{sym_match.group(1)}'" if sym_match else "symbol"

                    print(f"  [REDEFINITION] Conflict for {sym}")
                    print(f"  {_clean_path(error)}: Error occurred here")

                    for note in diag["notes"]:
                        if "previous" in note.lower():
                            print(f"  {_clean_path(note)}: Previous definition is here")
                        else:
                            print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 2. MEMBER INITIALIZER (Base class / member mismatch)
                if "member initializer" in error_lower and "does not name" in error_lower:
                    mem_match = re.search(r"member initializer '([^']+)'", error)
                    mem = f"'{mem_match.group(1)}'" if mem_match else "symbol"

                    print(f"  [INIT ERROR] {mem} is not a valid base class or class member")
                    print("  -> FIX SUGGESTION: Check if the base class name is misspelled or if its header is missing.")
                    print(f"  {_clean_path(error)}: Error occurred here")

                    for note in diag["notes"]:
                        print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 3. SCOPE RESOLUTION (No type named X in Y)
                if "no type named" in error_lower and "in" in error_lower:
                    type_match = re.search(r"no type named '([^']+)' in '([^']+)'", error)
                    if type_match:
                        print(f"  [SCOPE ERROR] No type '{type_match.group(1)}' inside '{type_match.group(2)}'")
                    else:
                        print("  [SCOPE ERROR] Unknown nested type")

                    suggest_match = re.search(r"did you mean '([^']+)'", error)
                    if suggest_match:
                        print(f"  -> FIX SUGGESTION: Just use '{suggest_match.group(1)}' instead of the scoped version")

                    print(f"  {_clean_path(error)}: Error occurred here")

                    for note in diag["notes"]:
                        print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 4. VIRTUAL OVERRIDE RETURN TYPE MISMATCH
                if "different return type" in error_lower and "override" in error_lower:
                    func_match = re.search(r"virtual function '([^']+)'", error_lower)
                    func = f"'{func_match.group(1)}'" if func_match else "function"

                    print(f"  [VIRTUAL OVERRIDE ERROR] Return type mismatch for {func}")
                    print("  -> FIX SUGGESTION: The derived class must use the exact same return type as the base class.")
                    print(f"  {_clean_path(error)}: Derived class error here")

                    for note in diag["notes"]:
                        if "overridden virtual function" in note.lower() or "overridden" in note.lower():
                            print(f"  {_clean_path(note)}: Base class truth is here")
                        else:
                            print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 5. OUT-OF-LINE DEFINITION MISMATCH (.cpp vs .hpp)
                if "out-of-line definition" in error_lower and "differs" in error_lower:
                    func_match = re.search(r"out-of-line definition of '([^']+)'", error)
                    func = f"'{func_match.group(1)}'" if func_match else "function"

                    print(f"  [DECLARATION MISMATCH] Return type in .cpp does not match .hpp for {func}")
                    print("  -> FIX SUGGESTION: Ensure the .cpp implementation has the exact same return type as the header.")
                    print(f"  {_clean_path(error)}: Error in .cpp here")

                    for note in diag["notes"]:
                        if "previous declaration" in note.lower() or "declared here" in note.lower():
                            print(f"  {_clean_path(note)}: Header declaration is here")
                        else:
                            print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 6. TEMPLATE ARITY ERROR
                if "template arguments" in error_lower and "arity" in error_lower:
                    tpl_match = re.search(r"class template '([^']+)'", error)
                    tpl = f"'{tpl_match.group(1)}'" if tpl_match else "template"

                    print(f"  [TEMPLATE ARITY ERROR] Too few/many template arguments for {tpl}")
                    print("  -> FIX SUGGESTION: Check the template definition to ensure you are providing the correct number of types.")
                    print(f"  {_clean_path(error)}: Usage error here")

                    for note in diag["notes"]:
                        if "declared here" in note.lower():
                            print(f"  {_clean_path(note)}: Template is declared here")
                        else:
                            print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 7. MISSING DEFAULT CONSTRUCTOR (Base class initialization)
                if "explicitly initialize the base class" in error_lower:
                    base_match = re.search(r"base class '([^']+)'", error)
                    base = f"'{base_match.group(1)}'" if base_match else "the base class"

                    print(f"  [CTOR INITIALIZATION ERROR] {base} requires explicit initialization")
                    print("  -> FIX SUGGESTION: The base class does not have a default constructor. You must call it in the initialization list.")
                    print(f"  {_clean_path(error)}: Constructor error here")

                    for note in diag["notes"]:
                        if "declared here" in note.lower():
                            print(f"  {_clean_path(note)}: Base class is declared here")
                        else:
                            print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 8. UNDECLARED IDENTIFIER
                if "use of undeclared identifier" in error_lower:
                    id_match = re.search(r"use of undeclared identifier '([^']+)'", error)
                    identifier = f"'{id_match.group(1)}'" if id_match else "symbol"

                    print(f"  [UNDECLARED ERROR] Identifier {identifier} was not found in this scope")
                    print("  -> FIX SUGGESTION: Check for typos, missing header includes, or missing 'this->' for member variables.")
                    print(f"  {_clean_path(error)}: Usage error here")

                    suggest_match = re.search(r"did you mean '([^']+)'", error)
                    if suggest_match:
                        print(f"  -> FIX SUGGESTION: Did you mean '{suggest_match.group(1)}'?")

                    for note in diag["notes"]:
                        print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 9. EMPTY SCALAR INITIALIZER
                if "scalar initializer cannot be empty" in error_lower:
                    print("  [SYNTAX ERROR] Scalar initializer cannot be empty")
                    print("  -> FIX SUGGESTION: MWCC/C++03 does not allow empty braces '{}' for scalars. Use '0' or explicit values.")
                    print(f"  {_clean_path(error)}: Error occurred here")

                    for note in diag["notes"]:
                        print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 10. ENUMERATOR REDEFINITION
                if "redefinition of enumerator" in error_lower:
                    enum_match = re.search(r"redefinition of enumerator '([^']+)'", error)
                    enum_val = f"'{enum_match.group(1)}'" if enum_match else "enumerator"

                    print(f"  [ENUM CONFLICT] Redefinition of {enum_val}")
                    print("  -> FIX SUGGESTION: Ensure this enum name is unique across all included headers.")
                    print(f"  {_clean_path(error)}: Current definition here")

                    for note in diag["notes"]:
                        if "previous" in note.lower():
                            print(f"  {_clean_path(note)}: Previous definition was here")
                        else:
                            print(f"  {_clean_path(note)}")
                    print()
                    continue

                # 11. INCOMPLETE TYPE (Forward declaration used but not defined)
                if "incomplete type" in error_lower:
                    type_match = re.search(r"variable has incomplete type '([^']+)'", error)
                    type_name = f"'{type_match.group(1)}'" if type_match else "type"

                    print(f"  [TYPE ERROR] {type_name} is only forward-declared but its size is needed.")
                    print("  -> FIX SUGGESTION: Include the header that defines this struct/class.")
                    print(f"  {_clean_path(error)}: Error occurred here")

                    for note in diag["notes"]:
                        # This will catch the "forward declaration of..." note
                        print(f"  {_clean_path(note)}")
                    print()
                    continue
                # ----------------------------------------------------

                # Detect and extract "(fix available)" suggestions for standard errors
                if "(fix available)" in error:
                    base_msg = error.replace(" (fix available)", "")
                    print(f"  {_clean_path(base_msg)}")
                else:
                    print(f"  {_clean_path(error)}")

                # Extract "did you mean '...'" suggestions from the error
                suggest_match = re.search(r"did you mean '([^']+)'", error)
                if suggest_match:
                    print(f"  -> clang suggests: {suggest_match.group(1)}")

                for note in diag["notes"]:
                    print(f"  {_clean_path(note)}")
                print()

            print("Fix the above before running MWCC build.")
            return 1

    print(f"  {fpath.name}: clean (no clang errors)")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Pre-build clang diagnostics check for .hpp and .cpp files"
    )
    parser.add_argument("files", nargs="+", help=".hpp and/or .cpp file(s) to check")
    args = parser.parse_args()

    any_failed = False
    for file_path in args.files:
        is_cpp = file_path.lower().endswith(".cpp")
        rc = check_file(file_path, is_cpp)
        if rc != 0:
            any_failed = True

    sys.exit(1 if any_failed else 0)


if __name__ == "__main__":
    main()
