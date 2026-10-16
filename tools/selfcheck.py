#!/usr/bin/env python3
"""Repository hygiene checks that do not require the protected target.

Run in CI. Fails non-zero on any violation.

  1. no protected payload is tracked (script.txt, *.bin, instrumented copies)
  2. every tracked .py compiles
  3. every receipt parses as JSON
  4. README code fences are balanced
  5. docs do not assert an unverified universal offset base
  6. docs do not reference tool files that no longer exist
"""
from __future__ import annotations

import json
import pathlib
import py_compile
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent

# Anything matching these must never be tracked.
FORBIDDEN = [
    re.compile(r"(^|/)script\.txt$"),
    re.compile(r"\.bin$"),
    re.compile(r"script_(A_probe|A_trace|offsets|level3_trace)\.luau$"),
    re.compile(r"^run_(probe|trace|offsets).*\.luau$"),
    re.compile(r"^probe_out.*\.txt$"),
    re.compile(r"^capture_.*\.txt$"),
]

# Claims that outrun the evidence and must not appear as assertions.
OVERCLAIM = [
    # the base is fitted from block 1 only
    (re.compile(r"stage1_offset\s*=\s*srcoff\s*\+\s*1274"), "universal +1274 offset claim"),
    (re.compile(r"(?i)offset base is\s+1274"), "universal offset-base claim"),
]


def tracked() -> list[str]:
    out = subprocess.run(["git", "-C", str(REPO), "ls-files"],
                         capture_output=True, check=True)
    return [x for x in out.stdout.decode("utf-8").split("\n") if x.strip()]


def main() -> int:
    problems: list[str] = []
    files = tracked()

    # 1. payload leak
    for f in files:
        for pat in FORBIDDEN:
            if pat.search(f):
                problems.append(f"PAYLOAD TRACKED: {f}  (matches {pat.pattern})")

    # 2. python compiles
    for f in files:
        if not f.endswith(".py"):
            continue
        try:
            with tempfile.NamedTemporaryFile(suffix=".pyc", delete=True):
                py_compile.compile(str(REPO / f), cfile=tempfile.mktemp(suffix=".pyc"),
                                   doraise=True)
        except py_compile.PyCompileError as e:
            problems.append(f"SYNTAX ERROR: {f}: {e}")

    # 3. receipts parse
    for f in files:
        if f.startswith("receipts/") and f.endswith(".json"):
            try:
                json.loads((REPO / f).read_text(encoding="utf-8"))
            except Exception as e:
                problems.append(f"BAD JSON: {f}: {e}")

    # 4. README fences balanced
    readme = REPO / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        n = len(re.findall(r"^```", text, re.M))
        if n % 2:
            problems.append(f"README.md has {n} ``` markers (odd = unbalanced)")
        if re.search(r"^```\s*$[\r\n]+\s*text\s*$", text, re.M):
            problems.append("README.md has a bare `text` line after a fence")

    # 5. no unverified universal claims in docs
    for f in files:
        if not (f.startswith("docs/") or f == "README.md"):
            continue
        p = REPO / f
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.split("\n"):
            if line.lstrip().startswith(("#", "*", ">")) or "not" in line.lower():
                continue          # headings / bullets / explicit denials
            for pat, why in OVERCLAIM:
                if pat.search(line):
                    problems.append(f"OVERCLAIM in {f}: {why}\n    {line.strip()}")

    # 6. docs reference existing tools only
    names = set(files)
    for f in files:
        if not f.startswith("docs/"):
            continue
        p = REPO / f
        if not p.exists():
            continue
        for m in re.finditer(r"`(tools/[\w./-]+)`", p.read_text(encoding="utf-8",
                                                                 errors="replace")):
            if m.group(1) not in names:
                problems.append(f"STALE REF in {f}: `{m.group(1)}` does not exist")

    if problems:
        print("FAILED\n")
        for x in problems:
            print("  - " + x)
        print(f"\n{len(problems)} problem(s)")
        return 1

    print(f"selfcheck OK  ({len(files)} tracked files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())