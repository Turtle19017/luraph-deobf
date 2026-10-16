#!/usr/bin/env python3
"""Build a minimal A-layer census probe for this Luraph v15 sample.

The protected target remains local. This generator injects only two markers:

  [A99]  seed_in, seed0, size, and source-base q/J for every LCG-XOR block
  [A321] first byte and the common continuation state

Every anchor is sample-specific and fail-closed: exactly one match is required.
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
    ap.add_argument("-o", "--out", type=Path, default=Path("script_A_probe.luau"))
    args = ap.parse_args()

    src = args.script.read_text(encoding="utf-8")

    q99_old = (
        "else local z,a,J,k=(I+240)%256,B[15](c),c-1,1+0;"
        "local B=0-k;local c,I={J+0,k,B,P,nil},r[1];"
        "return 323,c,r[2],I,z,240,93,155,a,v;"
    )
    q99_new = (
        "else local __seed_in,__size,__src=I,c,J;"
        "local z,a,J,k=(I+240)%256,B[15](c),c-1,1+0;"
        "local B=0-k;local c,I={J+0,k,B,P,nil},r[1];"
        "print('[A99]','seed_in',__seed_in,'seed0',z,'size',__size,'src',__src);"
        "return 323,c,r[2],I,z,240,93,155,a,v;"
    )
    src = replace_once(src, q99_old, q99_new, "A99/B:Q")

    a321_old = (
        "if z<=321 then local j,X=r[4],B[117](k,0);"
        "local y,A=X<128 and 145 or 410,Y[1];"
        "return y,j,Y[2],A,c,{},X,v,J,a;"
    )
    a321_new = (
        "if z<=321 then local j,X=r[4],B[117](k,0);"
        "local y,A=X<128 and 145 or 410,Y[1];"
        "print('[A321]','len',buffer.len(k),'first',X,'next',y);"
        "return y,j,Y[2],A,c,{},X,v,J,a;"
    )
    src = replace_once(src, a321_old, a321_new, "A321/B:Zy")

    args.out.write_text(src, encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
