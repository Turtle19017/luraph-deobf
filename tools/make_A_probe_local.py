#!/usr/bin/env python3
"""
make_A_probe_local.py - corrected probe generator for THIS target.

tools/make_A_probe.py from Turtle19017/luraph-deobf fails closed on this sample:
its A438 anchor

    local c,X,y=k+(Y+2097152*(c-c%128))+J+Z,4+I,P[1];return 79,P[2],y,X,j,r,z;

does not exist here (the 21-bit-limb handler that feeds state 365 in this build
is mW with shuffled register names and it returns 365 *directly*, not 79).

This generator derives every anchor from the target itself and is fail-closed:
an anchor must match exactly once or nothing is written.
"""
import sys, glob, io, os, argparse, hashlib

A99  = 'local z,a,J,k=(I+240)%256,B[15](c),c-1,1+0;'
A228 = 'local X=(c+P*J)%256;B[2](I,Z,(B[121](X,r,(B[117](a,Y+Z)))));'
A321 = 'local j,X=r[4],B[117](k,0);local y,A=X<128 and 145 or 410,Y[1];return y,j,Y[2],A,c,{},X,v,J,a;'
A438 = 'local j,X,y=(J-128)*128+(r-128+k*16384),c+3,v[1];return 365,v[2],y,Y,X,I,j;'
A365 = 'local c,I,J=Z+(B+r)+(Y+P),4+z,v[1];return 365,v[2],J,I,a,c;'

PATCH = [
    (A99,  A99  + "print('[A99]','seed_in',I,'xor',240,'scratch',c,'cursor',J,'key0',k);"),
    (A228, A228 + "print('[A228]','mult',P,'inc',c,'state',J,'xor',r,'srcoff',Y+Z,'key',X,'cipher',B[117](a,Y+Z));"),
    (A321, 'local j,X=r[4],B[117](k,0);local y,A=X<128 and 145 or 410,Y[1];'
           "print('[A321]','len',buffer.len(k),'first',X,'next',y);return y,j,Y[2],A,c,{},X,v,J,a;"),
    (A438, 'local j,X,y=(J-128)*128+(r-128+k*16384),c+3,v[1];'
           "print('[A438]','J',J,'r',r,'k',k,'decoded',j,'cursor',X);return 365,v[2],y,Y,X,I,j;"),
    (A365, 'local c,I,J=Z+(B+r)+(Y+P),4+z,v[1];'
           "print('[A365]','off',c,'next_cursor',J);return 365,v[2],J,I,a,c;"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("-o", "--out", default="script_A_probe.luau")
    args = ap.parse_args()

    src = io.open(args.script, encoding="utf-8", errors="surrogateescape").read()
    print(f"target sha256 : {hashlib.sha256(src.encode('utf-8','surrogateescape')).hexdigest()}")
    print(f"target chars  : {len(src):,}")

    for lab, anchor in zip(("A99", "A228", "A321", "A438", "A365"), (A99, A228, A321, A438, A365)):
        print(f"  anchor {lab:<5} matches = {src.count(anchor)}")
        if src.count(anchor) != 1:
            raise SystemExit(f"FAIL: {lab} anchor is not unique (got {src.count(anchor)})")

    for old, new in PATCH:
        src = src.replace(old, new, 1)

    io.open(args.out, "w", encoding="utf-8", errors="surrogateescape").write(src)
    print(f"wrote {args.out}  ({len(src):,} chars)")


if __name__ == "__main__":
    main()