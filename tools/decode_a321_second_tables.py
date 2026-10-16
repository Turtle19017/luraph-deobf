#!/usr/bin/env python3
"""Decode the second count-sized integer table from all 11 A321 plaintexts.

Source-derived layout established for the known sample:

  header
  first_int_table[count]
  tag215 = 81 57
  meta16
  meta5
  secondary_integer
  second_int_table[count]

The transition through state237 allocates the second table and builds a loop
descriptor with the still-live first-table count. State495 iterates exactly that
count; state162 starts one serialized integer; all 1/2/3/4-byte branches
converge at state469, which stores the decoded value and returns to state495.

Inputs are verified against the runtime plaintext receipt. No runtime execution,
source-buffer provenance, or stage1 offset is needed.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from decode_a321_first_tables import decode_one, derive_count, resolve_file, TABLE_START
from decode_a321_post_table_branch import secondary_integer_path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def first_table_end(data: bytes, count: int) -> int:
    pos = TABLE_START
    for _ in range(count):
        _, pos, _ = decode_one(data, pos)
    return pos


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
            raise SystemExit(f"FAIL: block {index} size mismatch")
        digest = sha256(data)
        if digest != meta["sha256"]:
            raise SystemExit(f"FAIL: block {index} SHA mismatch: {digest}")
        if data[:16].hex() != meta["head16_hex"]:
            raise SystemExit(f"FAIL: block {index} head16 mismatch")

        _, count = derive_count(data)
        end1 = first_table_end(data, count)

        tag, tag_end, tag_width = decode_one(data, end1)
        if (tag, tag_width, data[end1:tag_end].hex()) != (215, 2, "8157"):
            raise SystemExit(
                f"FAIL: block {index} post-table tag is "
                f"{tag}/width{tag_width}/{data[end1:tag_end].hex()}, expected 215/2/8157"
            )

        if tag_end + 3 > len(data):
            raise SystemExit(f"FAIL: block {index} truncated after tag215")

        meta16 = data[tag_end]
        meta5 = data[tag_end + 1]
        if meta16 >= 128:
            raise SystemExit(
                f"FAIL: block {index} state147 diverges: meta16={meta16} >= 128"
            )
        if meta5 >= 128:
            raise SystemExit(
                f"FAIL: block {index} state46 diverges: meta5={meta5} >= 128"
            )

        secondary_start = tag_end + 2
        try:
            secondary_value, second_start, secondary_width, secondary_path = (
                secondary_integer_path(data, secondary_start)
            )
        except ValueError as e:
            raise SystemExit(f"FAIL: block {index} secondary integer: {e}") from e

        if secondary_path[-1] != 237:
            raise SystemExit(
                f"FAIL: block {index} secondary integer does not reach state237: "
                f"{secondary_path}"
            )

        pos = second_start
        values: list[int] = []
        widths: list[int] = []
        try:
            for _ in range(count):
                value, pos, width = decode_one(data, pos)
                values.append(value)
                widths.append(width)
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} second table: {e}") from e

        raw = data[second_start:pos]
        packed = b"".join(v.to_bytes(8, "little", signed=False) for v in values)
        hist = collections.Counter(widths)

        next_integer = None
        if pos < len(data):
            try:
                nxt, nxt_end, nxt_width = decode_one(data, pos)
                next_integer = {
                    "value": nxt,
                    "width": nxt_width,
                    "end_offset": nxt_end,
                    "encoding_hex": data[pos:nxt_end].hex(),
                }
            except (ValueError, IndexError):
                pass

        rows.append({
            "index": index,
            "seed_in": seed,
            "object_size": len(data),
            "object_sha256": digest,
            "table_count": count,
            "first_table_end": end1,
            "tag215_end": tag_end,
            "meta16": meta16,
            "meta5": meta5,
            "secondary_integer": {
                "offset": secondary_start,
                "end_offset": second_start,
                "value": secondary_value,
                "width": secondary_width,
                "encoding_hex": data[secondary_start:second_start].hex(),
                "state_path": secondary_path,
            },
            "second_table_start": second_start,
            "second_table_end": pos,
            "second_table_encoded_size": pos - second_start,
            "bytes_remaining_after_second_table": len(data) - pos,
            "width_histogram": {str(k): hist[k] for k in sorted(hist)},
            "minimum": min(values),
            "maximum": max(values),
            "zero_count": values.count(0),
            "lt_128_count": sum(v < 128 for v in values),
            "table_raw_sha256": sha256(raw),
            "values_u64le_sha256": sha256(packed),
            "first16_values": values[:16],
            "last16_values": values[-16:],
            "next_serialized_integer": next_integer,
        })

    result = {
        "schema": "luraph-deobf.a321-second-int-tables.v1",
        "block_count": len(rows),
        "total_object_bytes": sum(r["object_size"] for r in rows),
        "total_second_table_entries": sum(r["table_count"] for r in rows),
        "source_path": {
            "allocation": "237(Ty)",
            "loop": "495(QW)",
            "read_first_limb": "162(g)",
            "store_and_repeat": "469(YW) -> 495(QW)",
        },
        "blocks": rows,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
