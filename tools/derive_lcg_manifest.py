#!/usr/bin/env python3
"""Derive source offsets for the 11 observed A-layer LCG blocks offline.

This uses the J9/A handoff's z[4] index and the exact length-parser path before
A99 in this sample:

  Gy(245): ptr = z4[seed] + 1; read b0
    b0 < 128  -> state 462 -> A99, size=b0
    b0 >=128  -> state 405; read b1
      b1 <128 -> state 13 -> A99, size=128*(b0-128)+b1
      b1>=128 -> state 439; read b2 -> state 300 -> A99,
                   size=128*(b0-128)+(b1-128)+16384*b2

All 11 runtime-observed block sizes fit these 1/2/3-byte cases. The tool fails
closed if a fourth limb is required or if a parsed size differs from the trace
census.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

EXPECTED = [
    (164, 20936),
    (325, 186),
    (229, 462),
    (129, 7397),
    (305, 2479),
    (339, 231),
    (347, 640),
    (281, 578),
    (187, 738),
    (283, 250),
    (211, 3693),
]


def parse_length(buf: bytes, ptr: int) -> tuple[int, int, list[int]]:
    if ptr < 0 or ptr >= len(buf):
        raise ValueError(f"length pointer {ptr} outside buffer len={len(buf)}")
    b0 = buf[ptr]
    if b0 < 128:
        return b0, 1, [b0]

    if ptr + 1 >= len(buf):
        raise ValueError("truncated 2-byte length")
    b1 = buf[ptr + 1]
    if b1 < 128:
        return 128 * (b0 - 128) + b1, 2, [b0, b1]

    if ptr + 2 >= len(buf):
        raise ValueError("truncated 3-byte length")
    b2 = buf[ptr + 2]
    if b2 < 128:
        size = 128 * (b0 - 128) + (b1 - 128) + 16384 * b2
        return size, 3, [b0, b1, b2]

    raise ValueError(
        f"length at {ptr} requires >=4 limbs ({b0:#x} {b1:#x} {b2:#x}); "
        "unsupported for this known 11-block sample"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("handoff", type=Path, help="luraph_j9_handoff.json")
    ap.add_argument("buffer", type=Path, help="luraph_j9_z_7.bin / A-layer source buffer")
    ap.add_argument("-o", "--out", type=Path, default=Path("luraph_A_lcg_manifest.json"))
    args = ap.parse_args()

    handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
    z4_raw = handoff.get("z_summary", {}).get("4")
    if not isinstance(z4_raw, dict):
        raise ValueError("handoff missing z_summary['4'] mapping")
    z4 = {int(k): int(v) for k, v in z4_raw.items()}
    buf = args.buffer.read_bytes()

    rows = []
    for index, (seed_in, expected_size) in enumerate(EXPECTED, 1):
        if seed_in not in z4:
            raise ValueError(f"z4 missing seed/index {seed_in}")
        record = z4[seed_in]
        length_ptr = record + 1
        size, header_len, header_bytes = parse_length(buf, length_ptr)
        if size != expected_size:
            raise ValueError(
                f"block {index} seed={seed_in}: parsed size {size} != trace {expected_size}; "
                f"z4={record}, header={header_bytes}"
            )
        src = length_ptr + header_len
        if src + size > len(buf):
            raise ValueError(
                f"block {index} seed={seed_in}: range [{src},{src+size}) outside buffer len={len(buf)}"
            )
        rows.append({
            "index": index,
            "seed_in": seed_in,
            "seed0": (seed_in + 240) % 256,
            "z4_record": record,
            "length_ptr": length_ptr,
            "length_header_bytes": header_bytes,
            "length_header_size": header_len,
            "size": size,
            "src": src,
        })

    result = {
        "schema": "luraph-deobf.a-lcg-manifest.v1",
        "source_handoff": str(args.handoff),
        "source_buffer": str(args.buffer),
        "block_count": len(rows),
        "total_decoded_bytes": sum(r["size"] for r in rows),
        "blocks": rows,
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
