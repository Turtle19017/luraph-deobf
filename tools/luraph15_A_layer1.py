#!/usr/bin/env python3
"""Reconstruct the first observed B:A LCG-XOR block (entry/seed 164).

Historical note: this file originally tried to continue the static successor
chain past A321 and produced a false 121->9->438->365 path. That continuation
was wrong for this build and has been removed. This tool now does one thing
only: reproduce block #1 byte-for-byte from the J9/A handoff artifacts.

Runtime tracing later established that this is block 1 of 11 total LCG-XOR
blocks, not a complete inner layer. See docs/005-multiblock-lcg.md.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path

EXPECTED_Z4_164 = 35911
EXPECTED_SRC_OFF = 35915
EXPECTED_SIZE = 20936
EXPECTED_SEED_IN = 164
EXPECTED_SEED0 = 148
EXPECTED_MULT = 93
EXPECTED_INC = 155
EXPECTED_XOR = 240
EXPECTED_SHA256 = "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"
EXPECTED_HEAD = bytes.fromhex(
    "011a160018171b1ed1e6021c1113122041e90e8c0e0e4243324c016f2e940e0f"
    "1f181c1a016f3c022e0a042e2e0000000000002ce90e8c0e090a0d0b113e0700"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    n = len(data)
    counts = collections.Counter(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values()) if n else 0.0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--handoff", type=Path, default=Path("luraph_j9_handoff.json"))
    ap.add_argument("--z7", type=Path, default=Path("luraph_j9_z_7.bin"))
    ap.add_argument("-o", "--out", type=Path, default=Path("luraph_A_block01_seed164.bin"))
    ap.add_argument("--receipt", type=Path, default=Path("luraph_A_block01_seed164.receipt.json"))
    args = ap.parse_args()

    handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
    z4 = {int(k): v for k, v in handoff["z_summary"]["4"].items()}
    cipher = args.z7.read_bytes()

    if handoff["A_c"] != EXPECTED_SEED_IN:
        raise ValueError(f"unexpected A_c: {handoff['A_c']}")
    if z4[EXPECTED_SEED_IN] != EXPECTED_Z4_164:
        raise ValueError(f"unexpected z4[164]: {z4[EXPECTED_SEED_IN]}")

    q = 1 + z4[EXPECTED_SEED_IN]
    b0, b1, b2 = cipher[q], cipher[q + 1], cipher[q + 2]
    if (b0, b1, b2) != (0xA3, 0xC8, 0x01):
        raise ValueError(f"unexpected block-1 length bytes: {(b0, b1, b2)!r}")

    size = (b0 - 128) * 128 + (b1 - 128) + 16384 * b2
    src = q + 3
    if size != EXPECTED_SIZE or src != EXPECTED_SRC_OFF:
        raise ValueError(f"unexpected block-1 layout: size={size}, src={src}")
    if src + size > len(cipher):
        raise ValueError("block-1 range exceeds cipher buffer")

    key = (EXPECTED_SEED_IN + 240) & 0xFF
    if key != EXPECTED_SEED0:
        raise AssertionError(key)

    plain = bytearray(size)
    for i, b in enumerate(cipher[src:src + size]):
        key = (EXPECTED_INC + key * EXPECTED_MULT) & 0xFF
        plain[i] = b ^ key ^ EXPECTED_XOR

    plain = bytes(plain)
    digest = sha256(plain)
    if digest != EXPECTED_SHA256:
        raise ValueError(f"block-1 SHA mismatch: {digest}")
    if plain[:64] != EXPECTED_HEAD:
        raise ValueError("block-1 head mismatch")

    args.out.write_bytes(plain)
    receipt = {
        "scope": "FIRST_OBSERVED_BLOCK_ONLY__1_OF_11",
        "seed_in": EXPECTED_SEED_IN,
        "seed0": EXPECTED_SEED0,
        "source_offset": src,
        "decoded_size": size,
        "lcg": {"inc": EXPECTED_INC, "mult": EXPECTED_MULT, "xor": EXPECTED_XOR},
        "sha256": digest,
        "entropy_bits_per_byte": entropy(plain),
        "head64_hex": plain[:64].hex(),
        "runtime_post_block_observation": {"first": 1, "next": 145},
        "note": "Do not infer the successor chain beyond A321 from this tool; use the corrected trace tooling and docs/005-multiblock-lcg.md.",
    }
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
