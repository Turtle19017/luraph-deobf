#!/usr/bin/env python3
"""Instrument the B:A dispatcher to trace real successors after A321.

The tracer is dormant until state 321 selects its continuation. It logs the
next A-layer state at the top of each dispatcher iteration while suppressing
the hot LCG-XOR loop states 99/323/228/321 so the trace budget is not consumed
by byte-by-byte decoding.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(src: str, old: str, new: str, label: str) -> str:
    n = src.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {n}")
    return src.replace(old, new, 1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("script", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("script_A_trace.luau"))
    ap.add_argument("--budget", type=int, default=600)
    args = ap.parse_args()
    if args.budget <= 0:
        raise SystemExit("--budget must be positive")

    src = args.script.read_text(encoding="utf-8")

    a_head_old = "A=function(B,P,c)local I={[2]=P};"
    a_head_new = (
        "A=function(B,P,c)"
        f"B.__atrace=false;B.__abudget={args.budget};"
        "local I={[2]=P};"
    )
    src = replace_once(src, a_head_old, a_head_new, "B:A header")

    loop_old = "while z do if C<=256 then"
    loop_new = (
        "while z do "
        "if B.__atrace and B.__abudget>0 and C~=99 and C~=323 and C~=228 and C~=321 then "
        "print('(C)',C);B.__abudget=B.__abudget-1;end;"
        "if C<=256 then"
    )
    src = replace_once(src, loop_old, loop_new, "B:A dispatcher loop")

    a321_old = (
        "if z<=321 then local j,X=r[4],B[117](k,0);"
        "local y,A=X<128 and 145 or 410,Y[1];"
        "return y,j,Y[2],A,c,{},X,v,J,a;"
    )
    a321_new = (
        "if z<=321 then local j,X=r[4],B[117](k,0);"
        "local y,A=X<128 and 145 or 410,Y[1];"
        "B.__atrace=true;"
        "print('[A321]','len',buffer.len(k),'first',X,'next',y);"
        "return y,j,Y[2],A,c,{},X,v,J,a;"
    )
    src = replace_once(src, a321_old, a321_new, "A321/B:Zy")

    args.out.write_text(src, encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
