#!/usr/bin/env python3
"""Verify the stage1.bin offset base for an LCG-XOR block, fail-closed.

Two things this asserts, both of which are easy to get wrong:

1. `srcoff` reported by the live [A228] probe is **buffer-relative**, not a
   `stage1.bin` offset.  For this sample the mapping is

       stage1_offset = srcoff + BASE,      BASE = 1274

   Using `srcoff` directly yields output whose entropy still sits at ~7.99,
   i.e. it looks like a plausible result while being entirely wrong.

2. The cipher is

       key[0]   = (seed_in + 240) % 256
       key[n+1] = (155 + key[n] * 93) % 256
       plain[n] = cipher[n] XOR key[n+1] XOR 240

Usage:
    python tools/verify_block1_offset_base.py <stage1.bin>

Exit status is non-zero unless the decrypted block matches the reference
SHA-256, so this doubles as a regression test.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import math
import pathlib
import sys

BASE = 1274
BLOCKS = [
    # (srcoff, length, seed_in, expected sha256 or None)
    (35915, 20936, 164,
     "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"),
]


def keystream(seed_in: int, n: int) -> bytes:
    k = (seed_in + 240) % 256
    out = bytearray(n)
    for i in range(n):
        k = (155 + k * 93) % 256
        out[i] = k ^ 240
    return bytes(out)


def entropy(b: bytes) -> float:
    n = len(b)
    if n == 0:
        return 0.0
    return -sum((v / n) * math.log2(v / n)
                for v in collections.Counter(b).values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage1", type=pathlib.Path)
    args = ap.parse_args()

    data = args.stage1.read_bytes()
    print(f"stage1        : {len(data):,} bytes")
    print(f"offset base   : {BASE}   (stage1_offset = srcoff + {BASE})\n")

    failures = 0
    for srcoff, ln, seed, expect in BLOCKS:
        off = srcoff + BASE
        if off + ln > len(data):
            print(f"  srcoff={srcoff:<8} len={ln:<6} seed_in={seed:<5} "
                  f"OFFSET OUT OF RANGE")
            failures += 1
            continue

        cipher = data[off:off + ln]
        ks = keystream(seed, ln)
        plain = bytes(c ^ k for c, k in zip(cipher, ks))
        sha = hashlib.sha256(plain).hexdigest()
        low = sum(1 for b in plain if b < 0x10) * 100 // ln
        zero = plain.count(0) * 100 // ln

        if expect is None:
            status = f"ok (unverified) sha={sha[:16]}"
        elif sha == expect:
            status = "VERIFIED"
        else:
            status = f"*** SHA MISMATCH (got {sha[:16]}) ***"
            failures += 1

        print(f"  srcoff={srcoff:<8} -> off={off:<8} len={ln:<6} seed_in={seed:<5}")
        print(f"      H(cipher)={entropy(cipher):.4f}  H(plain)={entropy(plain):.4f}"
              f"  low={low}%  zero={zero}%")
        print(f"      {status}")

        if expect is not None and sha == expect:
            print("\n      first 64 bytes of plaintext:")
            for o in range(0, 64, 16):
                row = plain[o:o + 16]
                print("        " + " ".join(f"{b:02x}" for b in row))

    if failures:
        print(f"\nFAILED ({failures})")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())