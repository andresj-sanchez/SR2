#!/usr/bin/env python3
"""ninja-errors.py — Run ninja and print only error blocks.

Usage:
    python tools/ninja-errors.py [ninja args...]

On success : prints the final progress/summary lines only.
On failure : prints each FAILED block with its diagnostics, numbered.
             Exits with ninja's exit code.

Why this exists:
    ninja output buries error messages inside hundreds of [N/M] progress
    lines.  Searching with tail/grep is fragile.  This wrapper captures
    everything, discards noise, and presents a clean, numbered error list
    so agents (and humans) get directly actionable output.
"""

import re
import subprocess
import sys


def run_ninja(args):
    proc = subprocess.Popen(
        ["ninja"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    all_lines = []
    failed_blocks = []  # list of (failed_header, [diag_lines])

    current_header = None
    current_diag = []
    in_failed = False

    for raw in proc.stdout:
        line = raw.rstrip("\n")
        all_lines.append(line)

        is_progress = bool(re.match(r"^\[[\d ]+/[\d ]+\]", line))

        if in_failed:
            if is_progress:
                failed_blocks.append((current_header, current_diag))
                current_header = None
                current_diag = []
                in_failed = False
            else:
                current_diag.append(line)

        if line.startswith("FAILED:"):
            in_failed = True
            current_header = line
            current_diag = []

    # Capture a trailing failed block not followed by a progress line
    if in_failed and current_header:
        failed_blocks.append((current_header, current_diag))

    proc.wait()
    return proc.returncode, all_lines, failed_blocks


def main():
    rc, all_lines, failed_blocks = run_ninja(sys.argv[1:])

    if not failed_blocks:
        # Success — show just the summary tail (progress lines, report, etc.)
        tail = [l for l in all_lines[-12:] if l.strip()]
        for line in tail:
            print(line)
        return rc

    # Failure — print each error block, clearly separated
    print(f"\n{'=' * 62}")
    print(f"BUILD FAILED — {len(failed_blocks)} error(s)")
    print("=" * 62)

    for i, (header, diag) in enumerate(failed_blocks, 1):
        print(f"\n--- Error {i}/{len(failed_blocks)} ---")
        print(header)
        for line in diag:
            if line.strip():
                print(line)

    print("\n" + "=" * 62)
    return rc


if __name__ == "__main__":
    sys.exit(main())
