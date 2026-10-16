#!/usr/bin/env python3
"""
build_and_run_probe.py - assemble the Roblox-shim + probe harness and execute it
with a local Luau CLI, then report the [A...] markers.

Usage:
  python build_and_run_probe.py <luau.exe> <probe.luau> <shim.luau> [-o run.luau] [--build-only]
"""
import io, os, re, subprocess, sys, argparse


def strip_trailing_return(src: str) -> str:
    """The shim ends with `return shim`; once inlined that ends the chunk."""
    lines = src.split("\n")
    while lines and (not lines[-1].strip() or lines[-1].strip().startswith("--")):
        lines.pop()
    if lines and lines[-1].strip().startswith("return "):
        lines.pop()
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("luau")
    ap.add_argument("probe")
    ap.add_argument("shim")
    ap.add_argument("-o", "--out", default="run_probe.luau")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--build-only", action="store_true",
                    help="assemble the harness but do not execute Luau")
    args = ap.parse_args()

    shim = strip_trailing_return(io.open(args.shim, encoding="utf-8").read())
    probe = io.open(args.probe, encoding="utf-8", errors="surrogateescape").read()

    prelude = """
local function vec3(x, y, z) return { X = x or 0, Y = y or 0, Z = z or 0, x = x or 0, y = y or 0, z = z or 0 } end
Vector2 = Vector2 or { new = function(x, y) return { X = x or 0, Y = y or 0, x = x or 0, y = y or 0 } end }
Vector3 = Vector3 or { new = vec3 }
if type(setfenv) ~= "function" then setfenv = function(f, env) return f end end
if type(getfenv) ~= "function" then getfenv = function(...) return _G end end
"""
    harness = '\nprint("[runner] === probe start ===")\ndo\n'
    postlude = '\nend\nprint("[runner] === probe returned normally ===")\n'

    src = (prelude + "\n" + shim + harness + probe + postlude).lstrip("\ufeff")
    with io.open(args.out, "w", encoding="utf-8", newline="\n", errors="surrogateescape") as fh:
        fh.write(src)
    print(f"[build] wrote {args.out}  ({len(src):,} chars)")
    if args.build_only:
        print("[build] build-only: Luau execution skipped")
        return

    r = subprocess.run([args.luau, args.out], capture_output=True, text=True,
                       errors="replace", timeout=args.timeout)
    out = r.stdout or ""
    err = r.stderr or ""
    io.open(args.out + ".out", "w", encoding="utf-8", errors="replace").write(out)
    print(f"[run] exit={r.returncode}  stdout={len(out):,}B  stderr={len(err):,}B")

    print("\n=== markers ===")
    for pat in ("[A99]", "[A321]", "[A438]", "[A365]", "[AFINALMETA]", "[AFINALLEN]", "[AFINALENTRY]", "[AFINAL11]", "[L3CHUNK]", "[L3VP8]", "[L3TAIL]", "[L3TERM]", "[runner]"):
        hits = [ln for ln in out.split("\n") if ln.startswith(pat)]
        for h in hits[:6]:
            print("  " + h)
        if not hits:
            print(f"  {pat:<6} (never reached)")

    print(f"\n[A228] executions: {sum(1 for ln in out.split(chr(10)) if ln.startswith('[A228]'))}")
    if "[A228]" in out:
        a228 = [ln for ln in out.split("\n") if ln.startswith("[A228]")]
        print(f"  first: {a228[0]}")
        print(f"  last : {a228[-1]}")

    if err.strip():
        print("\n=== stderr (Luau error) ===")
        print(err.strip()[:2000])
    print("\n=== last stdout lines ===")
    for ln in out.rstrip("\n").split("\n")[-6:]:
        print("  " + ln)


if __name__ == "__main__":
    main()