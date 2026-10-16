#!/usr/bin/env python3
"""Structure of the third interpreter level in a Luraph v15 sample.

SCOPE / TRUST
-------------
Exploratory mapper, not a verified tool. Its output splits into two very
different confidence levels:

  RELIABLE     the binary-search bound groups and the census of micro-handler
               names referenced by the closure. Both are read straight out of
               the source text and are exact.

  NOT EMITTED   per-opcode ranges. An earlier version inferred them and they
               were wrong: the dispatch is nested `if/elseif/else/end`, and the
               parser desynchronised on nested `end` consumption, producing
               ranges like `[14, 9]` and mapping every opcode >= 25 to a single
               handler. Those numbers were deleted rather than left in place,
               because a plausible-looking wrong table is worse than no table.

For authoritative opcode ranges, read the dispatch tree verbatim in handler
`B:T` of the target (look for `local c={[B.ep]=function`).

Usage:
    python tools/map_level3.py <script.txt>
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import luatok  # noqa: E402

BOUNDS = re.compile(r"\b(?:el)?if\s+t<=(\d+)\s+then")
CALL = re.compile(r"B:(\w+)\(")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("script", type=pathlib.Path)
    args = ap.parse_args()

    src = args.script.read_text(encoding="utf-8", errors="surrogateescape")

    found = luatok.find_function(src, "T")
    if not found:
        raise SystemExit("FAIL: handler `T` not found")
    T = found[0]

    anchor = T.find("[B.ep]=function")
    if anchor < 0:
        raise SystemExit("FAIL: handler `T` does not build a `[B.ep]` closure")
    tail = T[anchor:]
    if "while a do" not in tail:
        raise SystemExit("FAIL: no dispatch loop after [B.ep]")
    region = tail[tail.index("while a do"):]

    print(f"source            : {args.script}")
    print(f"handler T         : {len(T):,} chars")
    print(f"closure dispatch  : {len(region):,} chars\n")

    groups = [int(m.group(1)) for m in BOUNDS.finditer(region)]
    runs, cur = [], []
    prev = None
    for g in groups:
        if prev is None or g < prev:
            cur = [g]
        else:
            cur.append(g)
        prev = g
        runs.append(cur)
    # re-split into maximal decreasing runs
    runs, cur, prev = [], [], None
    for g in groups:
        if prev is not None and g >= prev:
            runs.append(cur)
            cur = []
        cur.append(g)
        prev = g
    if cur:
        runs.append(cur)

    print("=== binary-search bound groups (exact) ===")
    for r in runs:
        print("   " + " -> ".join(str(x) for x in r))

    names = sorted(set(CALL.findall(region)))
    print(f"\n=== {len(names)} micro-handlers referenced by the closure ===")
    for i in range(0, len(names), 10):
        print("   " + " ".join(names[i:i + 10]))

    op = re.search(r"(?<![A-Za-z0-9_])Op=function\(B\)return true,(\d+)", src)
    if op:
        first = BOUNDS.search(region)
        leaf = CALL.search(region[first.start():first.start() + 400]) if first else None
        print("\n=== entry state ===")
        print(f"   B:Op() -> true, {op.group(1)}, nil*14")
        if leaf:
            print(f"   deepest chain: t<={first.group(1)} -> B:{leaf.group(1)}")
        head = region[first.end():first.end() + 300] if first else ""
        nxt = BOUNDS.search(head)
        if nxt and leaf:
            nxtleaf = CALL.search(head[nxt.start():nxt.start() + 300])
            print(f"   then: t<={nxt.group(1)} -> B:{nxtleaf.group(1) if nxtleaf else '?'}")
        print(f"   (entry state {op.group(1)} lands in the second band)")

    print("\n=== not emitted ===")
    print("   per-opcode ranges: earlier inference was wrong (nested `end` desync).")
    print("   Read the dispatch tree verbatim in handler `B:T` instead.")
    return 0


if __name__ == "__main__":
    sys.exit(main())