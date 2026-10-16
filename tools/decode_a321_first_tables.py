#!/usr/bin/env python3
"""Parse the first integer table from all 11 verified A321 plaintext objects.

This generalises the block-1 checkpoint without assuming that all objects have
the same table size or end offset.

Known common prefix grammar for this sample:
  * byte 0 == 1
  * bytes 8..10 take the verified 3-byte integer branch
  * raw = 128*(b8-128) + (b9-128) + 16384*b10
  * table_count = raw - 38764
  * the first integer table begins at offset 16

The input files are verified against receipts/luraph_A321_plaintexts.runtime.json
before parsing. The tool then decodes exactly table_count serialized integers
using the source-derived 1/2/3/4-byte integer grammar and reports where the table
actually ends for each object.

No source-buffer provenance or stage1 offset assumption is used here.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

TABLE_START = 16
COUNT_BIAS = 38764


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_one(buf: bytes, pos: int) -> tuple[int, int, int]:
    if pos >= len(buf):
        raise ValueError(f"truncated integer at offset {pos}")
    b0 = buf[pos]
    if b0 < 128:
        return b0, pos + 1, 1

    if pos + 1 >= len(buf):
        raise ValueError(f"truncated 2-byte integer at offset {pos}")
    b1 = buf[pos + 1]
    if b1 < 128:
        return (b0 - 128) * 128 + b1, pos + 2, 2

    if pos + 2 >= len(buf):
        raise ValueError(f"truncated 3-byte integer at offset {pos}")
    b2 = buf[pos + 2]
    if b2 < 128:
        return (b0 - 128) * 128 + (b1 - 128) + 16384 * b2, pos + 3, 3

    if pos + 3 >= len(buf):
        raise ValueError(f"truncated 4-byte integer at offset {pos}")
    b3 = buf[pos + 3]
    value = (
        (b0 - 128) * 16384
        + (b1 - 128) * 2097152
        + (b2 - 128) * 128
        + (b3 % 128)
        + (b3 - b3 % 128) * 2097152
    )
    return value, pos + 4, 4


def derive_count(data: bytes) -> tuple[int, int]:
    if len(data) < TABLE_START:
        raise ValueError(f"object too short for common prefix: {len(data)}")
    if data[0] != 1:
        raise ValueError(f"unexpected byte0={data[0]}, expected 1")
    b8, b9, b10 = data[8], data[9], data[10]
    if not (b8 >= 128 and b9 >= 128 and b10 < 128):
        raise ValueError(
            "bytes 8..10 do not take the verified 3-byte integer branch: "
            f"{b8:02x} {b9:02x} {b10:02x}"
        )
    raw = 128 * (b8 - 128) + (b9 - 128) + 16384 * b10
    count = raw - COUNT_BIAS
    if count <= 0:
        raise ValueError(f"derived non-positive table count {count} from raw={raw}")
    return raw, count


def resolve_file(root: Path, row: dict) -> Path:
    # Prefer the canonical runtime-dump filename over the Windows path recorded
    # by the capture machine.
    name = f"block{int(row['index']):02d}_seed{int(row['seed_in'])}.bin"
    p = root / name
    if not p.is_file():
        raise FileNotFoundError(f"missing plaintext block: {p}")
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("plaintext_dir", type=Path)
    ap.add_argument(
        "--runtime-receipt",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "receipts" / "luraph_A321_plaintexts.runtime.json",
    )
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    runtime = json.loads(args.runtime_receipt.read_text(encoding="utf-8"))
    blocks = runtime.get("blocks")
    if not isinstance(blocks, list) or len(blocks) != 11:
        raise SystemExit("FAIL: runtime receipt must contain exactly 11 blocks")

    rows = []
    for meta in blocks:
        index = int(meta["index"])
        seed = int(meta["seed_in"])
        path = resolve_file(args.plaintext_dir, meta)
        data = path.read_bytes()

        if len(data) != int(meta["size"]):
            raise SystemExit(
                f"FAIL: block {index} size {len(data)} != receipt {meta['size']}"
            )
        digest = sha256(data)
        if digest != meta["sha256"]:
            raise SystemExit(
                f"FAIL: block {index} SHA mismatch: {digest} != {meta['sha256']}"
            )
        if data[:16].hex() != meta["head16_hex"]:
            raise SystemExit(f"FAIL: block {index} head16 mismatch")

        raw_count, count = derive_count(data)

        pos = TABLE_START
        values: list[int] = []
        widths: list[int] = []
        try:
            for _ in range(count):
                value, pos, width = decode_one(data, pos)
                values.append(value)
                widths.append(width)
        except ValueError as e:
            raise SystemExit(f"FAIL: block {index}: {e}") from e

        table_bytes = data[TABLE_START:pos]
        packed = b"".join(v.to_bytes(8, "little", signed=False) for v in values)
        hist = collections.Counter(widths)

        next_value = None
        next_width = None
        next_end = None
        if pos < len(data):
            try:
                next_value, next_end, next_width = decode_one(data, pos)
            except ValueError:
                pass

        rows.append({
            "index": index,
            "seed_in": seed,
            "object_size": len(data),
            "object_sha256": digest,
            "header_raw_count_value": raw_count,
            "table_count": count,
            "table_start": TABLE_START,
            "table_end": pos,
            "table_encoded_size": pos - TABLE_START,
            "bytes_remaining_after_table": len(data) - pos,
            "width_histogram": {str(k): hist[k] for k in sorted(hist)},
            "minimum": min(values),
            "maximum": max(values),
            "zero_count": values.count(0),
            "lt_128_count": sum(v < 128 for v in values),
            "table_raw_sha256": sha256(table_bytes),
            "values_u64le_sha256": sha256(packed),
            "first16_values": values[:16],
            "last16_values": values[-16:],
            "next_serialized_integer": {
                "value": next_value,
                "width": next_width,
                "end_offset": next_end,
            } if next_value is not None else None,
        })

    result = {
        "schema": "luraph-deobf.a321-first-int-tables.v1",
        "runtime_plaintext_receipt": str(args.runtime_receipt),
        "table_start": TABLE_START,
        "count_bias": COUNT_BIAS,
        "block_count": len(rows),
        "total_object_bytes": sum(r["object_size"] for r in rows),
        "total_table_entries": sum(r["table_count"] for r in rows),
        "blocks": rows,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
