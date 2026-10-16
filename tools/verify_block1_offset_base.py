#!/usr/bin/env python3
"""Locate LCG-XOR block 1 in stage1.bin and derive its offset base. Fail-closed.

SCOPE
-----
This tool verifies **block 1 only**. It does not establish an offset mapping for
the other ten blocks, and its output must not be read as one.

The `srcoff` printed by the live probes is *buffer-relative*. For block 1 in this
sample the mapping happens to be

    block1_stage1_offset = block1_srcoff + 1274

That constant was fitted from a single observation and reproduces block 1's
reference SHA-256 exactly. It is **not** evidence that the other ten blocks share
it: the decode source buffer may differ per block, and five of the eleven
candidate offsets decrypted from `srcoff + 1274` produced a byte profile unlike
the verified block. Use `tools/derive_lcg_manifest.py` for the offline offset
derivation instead.

METHOD
------
Rather than trusting the constant, this searches stage1.bin for the offset whose
LCG-XOR decryption reproduces the reference digest, then reports the base that
implies. If no offset matches, the tool exits non-zero.

Usage:
    python tools/verify_block1_offset_base.py <stage1.bin> [--from srcoff]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import math
import pathlib
import sys

BLOCK1_REF_SHA = "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"
BLOCK1_SRCOFF = 35915
BLOCK1_LEN = 20936
BLOCK1_SEED_IN = 164

# Widest window we are willing to attribute to this block. Anything outside it
# means the constant above is wrong for this sample.
SEARCH_SPAN = 4096


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


def try_offset(data: bytes, off: int, ln: int, seed_in: int) -> bytes | None:
    if off < 0 or off + ln > len(data):
        return None
    ks = keystream(seed_in, ln)
    cipher = data[off:off + ln]
    return bytes(c ^ k for c, k in zip(cipher, ks))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage1", type=pathlib.Path)
    ap.add_argument("--from", dest="srcoff", type=int, default=BLOCK1_SRCOFF,
                    help="srcoff reported by the probe for block 1 "
                         f"(default {BLOCK1_SRCOFF})")
    args = ap.parse_args()

    data = args.stage1.read_bytes()
    ks = keystream(BLOCK1_SEED_IN, BLOCK1_LEN)

    print(f"stage1                : {len(data):,} bytes")
    print(f"block 1 srcoff        : {args.srcoff}   (buffer-relative)")
    print(f"block 1 length        : {BLOCK1_LEN}")
    print(f"block 1 seed_in       : {BLOCK1_SEED_IN}")
    print(f"reference sha256      : {BLOCK1_REF_SHA}")
    print()

    hit = None
    for delta in range(-SEARCH_SPAN, SEARCH_SPAN + 1):
        off = args.srcoff + delta
        if off < 0 or off + BLOCK1_LEN > len(data):
            continue
        cipher = data[off:off + BLOCK1_LEN]
        plain = bytes(c ^ k for c, k in zip(cipher, ks))
        if hashlib.sha256(plain).hexdigest() == BLOCK1_REF_SHA:
            hit = (off, delta, plain, cipher)
            break

    if hit is None:
        print(f"FAIL: no offset within +-{SEARCH_SPAN} of srcoff reproduces "
              f"the reference digest for block 1.")
        print("      Either the seed/length/srcoff inputs are wrong for this")
        print("      sample, or the LCG parameters differ.")
        return 1

    off, delta, plain, cipher = hit
    low = sum(1 for b in plain if b < 0x10) * 100 // BLOCK1_LEN
    zero = plain.count(0) * 100 // BLOCK1_LEN

    print("VERIFIED block 1")
    print(f"  stage1 offset        : {off}")
    print(f"  implied base         : {off - args.srcoff}   "
          f"(stage1_offset - srcoff)")
    print(f"  H(cipher)            : {entropy(cipher):.4f}")
    print(f"  H(plain)             : {entropy(plain):.4f}")
    print(f"  bytes < 0x10         : {low}%")
    print(f"  zeros                : {zero}%")
    print()
    print("  SCOPE: this constant is fitted from block 1 alone. It is NOT")
    print("  established for the other ten blocks, whose decode source buffer")
    print("  may differ. Do not generalise it.")

    print()
    print("  first 64 bytes of plaintext:")
    for o in range(0, 64, 16):
        row = plain[o:o + 16]
        print("    " + " ".join(f"{b:02x}" for b in row))
    return 0


if __name__ == "__main__":
    sys.exit(main())