#!/usr/bin/env python3
"""Instrument the outer J9 -> B:A handoff to snapshot finalized VM lanes.

The probe runs after the outer B:A object has fully deserialized/finalized but
before its dispatch method (block1: B[68]) is called.

It prints:
  * indirect-key descriptors and resolved dispatch/mode/entry/stack fields
  * the 8 runtime instruction lanes at entry_pc
  * the finalized bootstrap slots entry_pc..entry_pc+18
  * the same 8 lanes at pc=11
  * sequence-prefix lengths (the # operator; auxiliary lanes may be sparse)

Arbitrary lane values are rendered with a side-effect-free scalar formatter.
This intentionally avoids tostring(table/userdata), because a __tostring
metamethod can re-enter protected VM code while the probe is only inspecting it.

Then it aborts intentionally with __AFINAL_DONE__ so the returned B[68] closure
is never executed.

Generated instrumented targets remain local and must not be committed.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

TARGET_SHA256 = "02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"

ANCHOR = (
    "Z=B:A(z,c);return 4,B[Z[Z[1]]](B,nil,B.y,Z),r,c,J;"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("script", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("script_A_final_lane_probe.luau"))
    args = ap.parse_args()

    raw = args.script.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != TARGET_SHA256:
        raise SystemExit(f"FAIL: target SHA mismatch: {digest}")

    src = raw.decode("utf-8")
    n = src.count(ANCHOR)
    if n != 1:
        raise SystemExit(f"FAIL: outer handoff anchor expected once, got {n}")

    patch = (
        "Z=B:A(z,c);"
        "local function __safe(x)local t=type(x);"
        "if x==nil then return 'nil' end;"
        "if t=='number' or t=='boolean' or t=='string' then return tostring(x) end;"
        "return '<'..t..'>' end;"
        "local __dk=Z[1];local __pk=Z[6];local __mk=Z[7];local __sk=Z[9];"
        "local __dispatch=Z[__dk];local __pc=Z[__pk];"
        "local __mode=Z[__mk];local __stack=Z[__sk];"
        "local __op=Z[Z[10]];local __S=Z[Z[12]];local __w=Z[Z[13]];"
        "local __H=Z[Z[8]];local __av=Z[Z[15]];local __aI=Z[Z[11]];"
        "local __aV=Z[Z[16]];local __aK=Z[Z[14]];"
        "print('[AFINALMETA]','dispatch_key',__dk,'dispatch',__dispatch,"
        "'pc_key',__pk,'pc',__pc,'mode_key',__mk,'mode',__mode,"
        "'stack_key',__sk,'stack',__stack);"
        "print('[AFINALLEN]','op_seq',#__op,'S_seq',#__S,'w_seq',#__w,'H_seq',#__H,"
        "'av_seq',#__av,'aI_seq',#__aI,'aV_seq',#__aV,'aK_seq',#__aK);"
        "print('[AFINALHELPER]','B3_type',type(B[3]),'B3',__safe(B[3]));"
        "print('[AFINALENTRY]','pc',__pc,"
        "'op',__safe(__op[__pc]),'S',__safe(__S[__pc]),"
        "'w',__safe(__w[__pc]),'H',__safe(__H[__pc]),"
        "'av',__safe(__av[__pc]),'aI',__safe(__aI[__pc]),"
        "'aV',__safe(__aV[__pc]),'aK',__safe(__aK[__pc]));"
        "local __last=math.min(__pc+18,#__op);"
        "for __i=__pc,__last do "
        "print('[AFINALSLOT]','pc',__i,"
        "'op',__safe(__op[__i]),'S',__safe(__S[__i]),"
        "'w',__safe(__w[__i]),'H',__safe(__H[__i]),"
        "'av',__safe(__av[__i]),'aI',__safe(__aI[__i]),"
        "'aV',__safe(__aV[__i]),'aK',__safe(__aK[__i]));end;"
        "print('[AFINAL11]','pc',11,"
        "'op',__safe(__op[11]),'S',__safe(__S[11]),"
        "'w',__safe(__w[11]),'H',__safe(__H[11]),"
        "'av',__safe(__av[11]),'aI',__safe(__aI[11]),"
        "'aV',__safe(__aV[11]),'aK',__safe(__aK[11]));"
        "print((' '):rep(4096));error('__AFINAL_DONE__');"
    )

    out = src.replace(ANCHOR, patch, 1)
    args.out.write_text(out, encoding="utf-8", newline="\n")

    print(f"target sha256 : {digest}")
    print("handoff anchor : 1")
    print(f"wrote          : {args.out} ({len(out):,} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
