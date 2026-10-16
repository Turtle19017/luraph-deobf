#!/usr/bin/env python3
"""
make_offsets_probe.py - decisive probe: print the source base of every LCG-XOR
block exactly once.

Handler `B:Sy` (opcode 228) writes into the scratch buffer at cursor `Z`:

    B[2](I, Z, B[121](X, r, B[117](a, Y+Z)))

`Y+Z` is the source offset in the decode buffer `a`.  For a fresh block the
scratch cursor Z starts at 0, so gating on `Z==0` prints the block base once and
only once -- instead of 20,936 times per block.

Combined with the known lengths and seeds this yields every block offset in a
single run, with no guessing and no brute force.
"""
import argparse, io, hashlib

# B:Sy(228) -- the LCG-XOR byte loop
SY = 'local X=(c+P*J)%256;B[2](I,Z,(B[121](X,r,(B[117](a,Y+Z)))));'
# B:Zy(322) -- block setup, gives length and seed
ZY = 'local z,a,J,k=(I+240)%256,B[15](c),c-1,1+0;'

PAD = "print((' '):rep(4096));"   # force a stdout flush after each marker

PATCH = [
    (ZY, ZY + "print('[BLK]','seed_in',I,'len',c,'srcoff_base',J);" + PAD),
    (SY, "if Z==0 then print('[SRC]','srcoff',Y+Z);" + PAD + "end "
            "local X=(c+P*J)%256;B[2](I,Z,(B[121](X,r,(B[117](a,Y+Z)))));"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("-o", "--out", default="script_offsets.luau")
    args = ap.parse_args()

    src = io.open(args.script, encoding="utf-8", errors="surrogateescape").read().lstrip("\ufeff")
    print(f"target sha256 : {hashlib.sha256(src.encode('utf-8', 'surrogateescape')).hexdigest()}")

    for lab, (old, _new) in zip(("ZY-228-setup", "SY-228-loop"), PATCH):
        n = src.count(old)
        print(f"  anchor {lab:<16} matches = {n}")
        if n != 1:
            raise SystemExit(f"FAIL: {lab} anchor not unique (got {n})")

    for old, new in PATCH:
        src = src.replace(old, new, 1)

    src = "ATENTER=0\n" + src
    with io.open(args.out, "w", encoding="utf-8", newline="\n", errors="surrogateescape") as fh:
        fh.write(src)
    print(f"wrote {args.out} ({len(src):,} chars)")


if __name__ == "__main__":
    main()