#!/usr/bin/env python3
"""Recover the outer J9 z4 proto-index map and z7 boundary from stage1.bin.

For this verified Luraph v15 sample, the J9 epilogue material is laid out as:

  stage1[0:6]        outer prefix
  stage1[6:1270]     399 serialized integers -> z4[1..399]
  stage1[1270]       z6 boolean byte (0)
  stage1[1271:1274]  serialized z7 length (79999)
  stage1[1274:81273] z7 bytes

The integer codec is the same 1/2/3/4-byte codec independently recovered from
A321 plaintexts. This tool fails closed on sample SHA, map anchors, z6, z7 size,
and z7 SHA.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

STAGE1_SHA = "108da67ce0920931a4896896927fa127816bb9980d9fec2518bcad8ed472b2ec"
Z7_SHA = "158c17bfdd79cb23c036639223a730d9c8d2c4940cb07cbfb31aa97551b64891"
MAP_START = 6
MAP_COUNT = 399
EXPECTED_MAP_END = 1270
EXPECTED_Z6 = 0
EXPECTED_Z7_SIZE = 79999
EXPECTED_Z7_START = 1274
ANCHORS = {
    14: 57229,
    44: 263942668,
    46: 263891360,
    48: 263891762,
    159: 63037,
    164: 35911,
    211: 263852361,
    218: 64308,
    268: 263857930,
    318: 57245,
    399: 79954,
}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def decode_one(data: bytes, pos: int) -> tuple[int, int, int]:
    b0 = data[pos]
    if b0 < 128:
        return b0, pos + 1, 1
    b1 = data[pos + 1]
    if b1 < 128:
        return (b0 - 128) * 128 + b1, pos + 2, 2
    b2 = data[pos + 2]
    if b2 < 128:
        return (b0 - 128) * 128 + (b1 - 128) + 16384 * b2, pos + 3, 3
    b3 = data[pos + 3]
    value = (
        (b0 - 128) * 16384
        + (b1 - 128) * 2097152
        + (b2 - 128) * 128
        + (b3 % 128)
        + (b3 - b3 % 128) * 2097152
    )
    return value, pos + 4, 4


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage1", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    data = args.stage1.read_bytes()
    digest = sha256(data)
    if digest != STAGE1_SHA:
        raise SystemExit(f"FAIL: stage1 SHA mismatch: {digest}")

    pos = MAP_START
    z4 = {}
    widths = {}
    for idx in range(1, MAP_COUNT + 1):
        value, pos, width = decode_one(data, pos)
        z4[idx] = value
        widths[str(width)] = widths.get(str(width), 0) + 1

    if pos != EXPECTED_MAP_END:
        raise SystemExit(f"FAIL: z4 end {pos} != {EXPECTED_MAP_END}")

    for idx, expected in ANCHORS.items():
        if z4[idx] != expected:
            raise SystemExit(
                f"FAIL: z4[{idx}]={z4[idx]} != expected {expected}"
            )

    z6 = data[pos]
    if z6 != EXPECTED_Z6:
        raise SystemExit(f"FAIL: z6 byte {z6} != 0")
    pos += 1

    z7_size, z7_start, z7_width = decode_one(data, pos)
    if z7_size != EXPECTED_Z7_SIZE:
        raise SystemExit(f"FAIL: z7 size {z7_size} != {EXPECTED_Z7_SIZE}")
    if z7_start != EXPECTED_Z7_START:
        raise SystemExit(f"FAIL: z7 start {z7_start} != {EXPECTED_Z7_START}")

    z7 = data[z7_start:z7_start + z7_size]
    if len(z7) != EXPECTED_Z7_SIZE:
        raise SystemExit("FAIL: truncated z7 slice")
    z7_digest = sha256(z7)
    if z7_digest != Z7_SHA:
        raise SystemExit(f"FAIL: z7 SHA mismatch: {z7_digest}")

    packed = b"".join(z4[i].to_bytes(4, "little") for i in range(1, 400))

    result = {
        "schema": "luraph-deobf.j9-z4-index-map.v1",
        "stage1_sha256": digest,
        "map_start": MAP_START,
        "map_end": EXPECTED_MAP_END,
        "map_count": MAP_COUNT,
        "width_histogram": widths,
        "values_u32le_sha256": sha256(packed),
        "anchors": {str(k): z4[k] for k in sorted(ANCHORS)},
        "z6": {"offset": EXPECTED_MAP_END, "value": z6},
        "z7": {
            "length_field_offset": EXPECTED_MAP_END + 1,
            "length_width": z7_width,
            "start": z7_start,
            "size": z7_size,
            "sha256": z7_digest,
        },
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
