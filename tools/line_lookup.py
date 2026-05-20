#!/usr/bin/env python3
"""
Address lookup tool: given a hex address, finds the closest entry in a map file
and returns 50 lines before and 50 lines after it.

Usage:
    python tools/line_lookup.py <mapfile> <address>

Example:
    python tools/line_lookup.py symbols/sr2_line_info.nothpp 0x100234
    python tools/line_lookup.py symbols/sr2_line_info.nothpp 100234

The map file must be objdump interleaved disassembly output produced with:
    objdump -m mips:5900 --line-numbers --debugging -d <ELF> > mapfile

Format recognised:
  Source annotation (no leading whitespace, ends with :LINE_NUMBER):
      C:\\Develop\\path\\to\\file.cpp:326
  Instruction line (leading whitespace, address 5+ hex digits, tab after colon):
        100234:	0080282d 	move	a1,a0

Multiple consecutive source annotations before one instruction indicate inlined
functions; all are emitted as separate entries for that address.
"""

import sys
import re
import bisect


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_map_file(filepath):
    """Parse an objdump interleaved disassembly + line-number file.

    Returns a list of (address, display_line) tuples in address order.
    Instructions without any preceding source annotation are skipped.
    """
    entries = []
    pending = []  # source annotations accumulated since the last instruction

    # Instruction: leading whitespace, 5+ hex digits (rules out C:\\ drive
    # letters), followed by optional spaces, colon, then a tab.
    re_insn = re.compile(r'^\s+([0-9A-Fa-f]{5,})\s*:\t')

    # Source annotation: must start at column 0 (non-whitespace), must end
    # with :DIGITS (and nothing else after).  Greedy match so Python finds the
    # LAST colon-digits pair, giving us the line number even when the path
    # itself contains colons (Windows drive letters handled naturally because
    # the group before is also greedy).
    re_src = re.compile(r'^(\S[^\r\n]*)\:(\d+)\s*$')

    with open(filepath, 'r', errors='replace') as f:
        for raw in f:
            line = raw.rstrip('\n')

            m = re_src.match(line)
            if m:
                pending.append(f'{m.group(1)} (line {m.group(2)})')
                continue

            m = re_insn.match(line)
            if m:
                addr = int(m.group(1), 16)
                for src in pending:
                    entries.append((addr, f'0x{addr:08X}: {src}'))
                pending = []
                continue

    return entries


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def find_closest_index(entries, target_addr):
    """Binary-search for the entry whose address is closest to target_addr.

    Assumes entries are sorted by address (objdump outputs in address order).
    Returns (index, distance).
    """
    addrs = [e[0] for e in entries]
    pos = bisect.bisect_left(addrs, target_addr)

    candidates = []
    if pos < len(entries):
        candidates.append(pos)
    if pos > 0:
        candidates.append(pos - 1)

    best = min(candidates, key=lambda i: abs(entries[i][0] - target_addr))
    return best, abs(entries[best][0] - target_addr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    if len(sys.argv) == 3 and sys.argv[2] == "--dump-all":
        mapfile = sys.argv[1]
        try:
            entries = parse_map_file(mapfile)
        except FileNotFoundError:
            print(f"Error: File '{mapfile}' not found.", file=sys.stderr)
            sys.exit(1)
        if not entries:
            print("Error: No valid address entries found in the file.", file=sys.stderr)
            sys.exit(1)
        for _, display_line in entries:
            print(display_line)
        return

    if len(sys.argv) != 3:
        print("Usage: python line_lookup.py <mapfile> <address>")
        print("       python line_lookup.py <mapfile> --dump-all  (write all entries to stdout)")
        print("Example: python line_lookup.py symbols/sr2_line_info.nothpp 0x100234")
        print("Example: python line_lookup.py symbols/sr2_line_info.nothpp --dump-all > symbols/debug_lines.txt")
        sys.exit(1)

    mapfile = sys.argv[1]
    raw_addr = sys.argv[2]

    try:
        target_addr = int(raw_addr, 16)
    except ValueError:
        print(f"Error: '{raw_addr}' is not a valid hex address.")
        sys.exit(1)

    try:
        entries = parse_map_file(mapfile)
    except FileNotFoundError:
        print(f"Error: File '{mapfile}' not found.")
        sys.exit(1)

    if not entries:
        print("Error: No valid address entries found in the file.")
        sys.exit(1)

    idx, diff = find_closest_index(entries, target_addr)
    matched_addr = entries[idx][0]

    if diff == 0:
        print(f"Exact match found: 0x{matched_addr:08X}")
    else:
        print(
            f"No exact match for 0x{target_addr:08X}. "
            f"Closest address: 0x{matched_addr:08X} (off by {diff} / 0x{diff:X})"
        )

    print("-" * 80)

    start = max(0, idx - 50)
    end = min(len(entries), idx + 51)

    print(f"Showing entries [{start}:{end}] (total {end - start}):\n")
    for i in range(start, end):
        # Mark ALL entries at the matched address, not just the first one
        # (multiple entries at one address = inlined functions)
        marker = " >>> " if entries[i][0] == matched_addr else "     "
        print(f"{marker}{entries[i][1]}")


if __name__ == "__main__":
    main()
