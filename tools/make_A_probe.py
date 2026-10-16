#!/usr/bin/env python3
"""Create a local runtime probe without committing the protected target.

This intentionally requires the analyst's own ``script.txt``.  It inserts five
logging calls at uniquely identified handlers/states used by the current B:A
reachable-path investigation and writes a separate instrumented Luau file.

Fail-closed: every replacement must occur exactly once or no output is written.
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

    replacements = [
        (
            "local u=(A*X+y)%256;B[2](T,C,(B[121](u,177,(B[117](Y,C+z)))));",
            "local u=(A*X+y)%256;print('[A228]','seed',A,'inc',y,'mult',X,'xor',177,'src',z,'key',u,'cipher',B[117](Y,C+z));B[2](T,C,(B[121](u,177,(B[117](Y,C+z)))));",
            "A228",
        ),
        (
            "local j,X=r[4],B[117](k,0);local y,A=X<128 and 145 or 410,Y[1];return y,j,Y[2],A,c,{},X,v,J,a;",
            "local j,X=r[4],B[117](k,0);local y,A=X<128 and 145 or 410,Y[1];print('[A321]','len',buffer.len(k),'first',X,'next',y);return y,j,Y[2],A,c,{},X,v,J,a;",
            "A321",
        ),
        (
            "local c,X,y=k+(Y+2097152*(c-c%128))+J+Z,4+I,P[1];return 79,P[2],y,X,j,r,z;",
            "local c,X,y=k+(Y+2097152*(c-c%128))+J+Z,4+I,P[1];print('[A438]','decoded',c,'cursor',X);return 79,P[2],y,X,j,r,z;",
            "A438",
        ),
        (
            "local c,I,J=Z+(B+r)+(Y+P),4+z,v[1];return 365,v[2],J,I,a,c;",
            "local c,I,J=Z+(B+r)+(Y+P),4+z,v[1];print('[A365]','offset',c);return 365,v[2],J,I,a,c;",
            "A365",
        ),
    ]

    for old, new, label in replacements:
        src = replace_once(src, old, new, label)

    # A99 is intentionally injected by a wider, target-specific marker because
    # the handler's register names are shuffled.  Keep the marker small enough
    # to audit but fail if this sample drifts.
    old = "local z,X,y,A,T,C=Z+1,93,155,(v+177)%256,B[15](16),0;"
    new = "local z,X,y,A,T,C=Z+1,93,155,(v+177)%256,B[15](16),0;print('[A99]','src',z,'mult',X,'inc',y,'seed',A);"
    src = replace_once(src, old, new, "A99")

    args.out.write_text(src, encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
