#!/usr/bin/env python3
"""Build a bounded runtime trace for the first level-3 c[B.ep] invocation.

The probe logs only the first closure invocation, batches 32 interpreter states
per line, forces stdout flush with padding, and emits a focused vp/state-8 marker
showing the actual buffer/cursor/byte used by the entry branch.

The protected target remains local. Every anchor is sample-specific and
fail-closed for the known target SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

TARGET_SHA256 = "02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"

CLOSURE = (
    "[B.ep]=function(I,r)local a,J,k,Y,Z,j,X,y,A,T,C,u,o,R,q=B:Op();"
    "local t,h,Q,f,V,K,S,b,s,L,w,H,F,x,W,O=J,k,I,r,Y,Z,j,X,y,A,T,C,u,o,R,q;"
    "while a do"
)

VP8 = (
    "elseif r<=8 then local r=v[0][z];local z,v=P[1][r],P[2];"
    "local P=v[7];local X,A=B[117](P,z),1+z;"
    "return not(86>=X)and 210 or 204,r,z,v,0,P,X,I,c,Z,a;"
)

UP_TERMINAL = "elseif o==2 then return V;end;"

PAD = "print((' '):rep(4096));"


def replace_once(src: str, old: str, new: str, label: str) -> str:
    n = src.count(old)
    if n != 1:
        raise SystemExit(f"FAIL: {label} expected exactly one anchor, got {n}")
    return src.replace(old, new, 1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("script", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("script_level3_trace.luau"))
    ap.add_argument("--budget", type=int, default=2048)
    args = ap.parse_args()
    if args.budget <= 0:
        raise SystemExit("FAIL: --budget must be positive")

    raw = args.script.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != TARGET_SHA256:
        raise SystemExit(f"FAIL: target SHA mismatch: {digest}")
    src = raw.decode("utf-8")

    closure_new = (
        "[B.ep]=function(I,r)"
        "B.__l3runs=(B.__l3runs or 0)+1;"
        "local __l3trace=B.__l3runs==1;"
        f"local __l3budget={args.budget};local __l3n=0;local __l3buf='';"
        "local a,J,k,Y,Z,j,X,y,A,T,C,u,o,R,q=B:Op();"
        "local t,h,Q,f,V,K,S,b,s,L,w,H,F,x,W,O=J,k,I,r,Y,Z,j,X,y,A,T,C,u,o,R,q;"
        "while a do "
        "if __l3trace and __l3n<__l3budget then "
        "__l3n=__l3n+1;__l3buf=__l3buf..t..',';"
        "if __l3n==1 or __l3n%32==0 then "
        "print('[L3CHUNK]','run',B.__l3runs,'n',__l3n,'states',__l3buf);"
        + PAD +
        "__l3buf='';end;end;"
    )
    src = replace_once(src, CLOSURE, closure_new, "level3 closure")

    vp8_new = (
        "elseif r<=8 then local r=v[0][z];local z,v=P[1][r],P[2];"
        "local P=v[7];local X,A=B[117](P,z),1+z;"
        "if B.__l3runs==1 then "
        "print('[L3VP8]','proto',r,'cursor',z,'byte',X,'buflen',buffer.len(P),'buf',tostring(P));"
        + PAD +
        "end;"
        "return not(86>=X)and 210 or 204,r,z,v,0,P,X,I,c,Z,a;"
    )
    src = replace_once(src, VP8, vp8_new, "vp/state8")

    terminal_new = (
        "elseif o==2 then "
        "if __l3trace and #__l3buf>0 then "
        "print('[L3TAIL]','run',B.__l3runs,'n',__l3n,'states',__l3buf);"
        + PAD +
        "__l3buf='';end;"
        "if __l3trace then print('[L3TERM]','run',B.__l3runs,'n',__l3n);"
        + PAD +
        "end;"
        "return V;end;"
    )
    src = replace_once(src, UP_TERMINAL, terminal_new, "up terminal")

    args.out.write_text(src, encoding="utf-8", newline="\n")
    print(f"target sha256 : {digest}")
    print("anchors       : closure=1 vp8=1 terminal=1")
    print(f"budget        : {args.budget}")
    print(f"wrote         : {args.out} ({len(src):,} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
