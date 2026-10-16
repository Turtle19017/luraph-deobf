#!/usr/bin/env python3
"""Instrument the reachable mode233 pc3784 R177 mega-call.

The probe is intentionally narrow:
  * target SHA must match the known Luraph sample,
  * the exact mode233 opcode21 source anchor must occur once,
  * instrumentation only fires when l == 3784,
  * it snapshots scalar/type/equality facts immediately before the call,
  * executes the original call exactly once,
  * snapshots the packed return and R88 side effect,
  * aborts intentionally with __R177_DONE__ before the next VM instruction.

Generated Luau targets are local-only and must not be committed.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

TARGET_SHA256 = "02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"

ANCHOR = (
    "elseif t==21 then N,a,p=s[l],w[l],H[l];g=N+a;n=BR[g];i=n[J];"
    "M=a+i-1;n[J]=M;k(n,1,i,a,n);k(BR,N+1,g-1,1,n);"
    "BR[N]=Y(BR[N](Z(n,1,n[J])));else BR[s[l]]=BR[H[l]]<w[l];end;"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("script", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("script_R177_probe.luau"))
    args = ap.parse_args()

    raw = args.script.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != TARGET_SHA256:
        raise SystemExit(f"FAIL: target SHA mismatch: {digest}")

    src = raw.decode("utf-8")
    count = src.count(ANCHOR)
    if count != 1:
        raise SystemExit(f"FAIL: opcode21 anchor expected once, got {count}")

    patch = (
        "elseif t==21 then N,a,p=s[l],w[l],H[l];g=N+a;n=BR[g];i=n[J];"
        "M=a+i-1;n[J]=M;k(n,1,i,a,n);k(BR,N+1,g-1,1,n);"
        "if l==3784 then "
        "print('[R177PRE]',"
        "'pc',l,"
        "'R88',BR[88],"
        "'R121',BR[121],"
        "'R86',BR[86],"
        "'R177_type',type(BR[177]),"
        "'eq_R61',BR[177]==BR[61],"
        "'eq_R117',BR[177]==BR[117],"
        "'eq_R155',BR[177]==BR[155],"
        "'eq_R50',BR[177]==BR[50],"
        "'eq_R59',BR[177]==BR[59],"
        "'eq_R10',BR[177]==BR[10],"
        "'argpack_n',rawget(n,J));"
        "end;"
        "BR[N]=Y(BR[N](Z(n,1,n[J])));"
        "if l==3784 then "
        "local __pack=BR[177];"
        "local __first=type(__pack)=='table' and rawget(__pack,1) or nil;"
        "print('[R177POST]',"
        "'R88',BR[88],"
        "'R177_type',type(__pack),"
        "'return_n',type(__pack)=='table' and rawget(__pack,'n') or -1,"
        "'ret1_type',type(__first),"
        "'ret1_scalar',(type(__first)=='number' or type(__first)=='boolean' or type(__first)=='string') and __first or '<non-scalar>');"
        "print((' '):rep(4096));"
        "error('__R177_DONE__');"
        "end;"
        "else BR[s[l]]=BR[H[l]]<w[l];end;"
    )

    out = src.replace(ANCHOR, patch, 1)
    args.out.write_text(out, encoding="utf-8", newline="\n")

    print(f"target sha256 : {digest}")
    print("opcode21 anchor: 1")
    print(f"wrote          : {args.out} ({len(out):,} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
