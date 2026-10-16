#!/usr/bin/env python3
"""Decode the first verified integer table inside Luraph A-layer block #1.

The count (4474), start offset (16), and integer decoder are derived from the
reachable B:A source path. This tool operates only on the already-decrypted
block-1 plaintext and does not execute the protected target.
"""
from __future__ import annotations
import argparse, collections, hashlib, json
from pathlib import Path

BLOCK1_SHA = "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"
START = 16
COUNT = 4474
EXPECT_END = 4500
EXPECT_RAW_SHA = "710e664df1c6a340316b6fe86696351f55a1fa6bfeb686b6e7770bc79ffe3f44"
EXPECT_VALUES_SHA = "4c79f884d866a14860621efb1b41869b3bace4e45906dedaeb7e9840cab05699"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def decode_one(buf: bytes, pos: int) -> tuple[int, int, int]:
    b0 = buf[pos]
    if b0 < 128:
        return b0, pos + 1, 1
    b1 = buf[pos + 1]
    if b1 < 128:
        return (b0 - 128) * 128 + b1, pos + 2, 2
    b2 = buf[pos + 2]
    if b2 < 128:
        return (b0 - 128) * 128 + (b1 - 128) + 16384 * b2, pos + 3, 3
    b3 = buf[pos + 3]
    # Exact state-24 `b` formula for the four-byte branch in this build.
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
    ap.add_argument("block1", type=Path)
    ap.add_argument("--receipt", type=Path)
    ap.add_argument("--values", type=Path, help="optional u32le value dump")
    args = ap.parse_args()

    data = args.block1.read_bytes()
    got = sha256(data)
    if got != BLOCK1_SHA:
        raise SystemExit(f"FAIL: block1 SHA mismatch: {got}")

    pos = START
    values: list[int] = []
    widths: list[int] = []
    for _ in range(COUNT):
        value, pos, width = decode_one(data, pos)
        values.append(value)
        widths.append(width)

    raw = data[START:pos]
    packed = b"".join(v.to_bytes(4, "little") for v in values)
    raw_sha = sha256(raw)
    values_sha = sha256(packed)
    if pos != EXPECT_END:
        raise SystemExit(f"FAIL: decoded end {pos} != {EXPECT_END}")
    if raw_sha != EXPECT_RAW_SHA:
        raise SystemExit(f"FAIL: raw-span SHA mismatch: {raw_sha}")
    if values_sha != EXPECT_VALUES_SHA:
        raise SystemExit(f"FAIL: values SHA mismatch: {values_sha}")

    hist = dict(sorted(collections.Counter(widths).items()))
    result = {
        "schema": "luraph-deobf.a-block1-int-table.v1",
        "block1_sha256": got,
        "start_offset": START,
        "end_offset": pos,
        "encoded_size": len(raw),
        "count": COUNT,
        "width_histogram": {str(k): v for k, v in hist.items()},
        "minimum": min(values),
        "maximum": max(values),
        "zero_count": values.count(0),
        "lt_128_count": sum(v < 128 for v in values),
        "raw_span_sha256": raw_sha,
        "values_u32le_sha256": values_sha,
        "first32": values[:32],
        "last32": values[-32:],
    }
    if args.values:
        args.values.write_bytes(packed)
    if args.receipt:
        args.receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
