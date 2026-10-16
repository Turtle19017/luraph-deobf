#!/usr/bin/env python3
"""Decode the post-second scalar and third count-sized integer table.

Source-derived layout for the known A321 corpus:

  header
  first_int_table[count]
  tag215
  meta16
  meta5
  secondary_integer
  second_int_table[count]
  post_second_scalar
  third_int_table[count]
  phase4_count_u32
  ...

For the current eleven runtime-verified objects, post_second_scalar is encoded
in one byte. The source path is:

  second table finishes
    495 -> 404 -> 50

  state50 reads the scalar first limb
    <128 -> 325 -> 503 -> 4 -> 412

  state412 stores the scalar in the object, allocates two tables of size count,
  and creates a count-bound loop descriptor.

  third table loop:
    36  -> loop controller
    401 -> read first serialized-integer limb
    ... -> 1/2/3/4-byte decoder
    343 -> store value[index]
    36  -> repeat

  when the loop ends:
    36 -> 51 -> 55

  state55 then reads one little-endian u32 from the current cursor. That value
  is reported as phase4_count_u32 but this tool does not parse phase 4 further.

Inputs are verified against receipts/luraph_A321_plaintexts.runtime.json.
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


def parse_n_ints(data: bytes, pos: int, count: int) -> tuple[list[int], list[int], int]:
    values: list[int] = []
    widths: list[int] = []
    for _ in range(count):
        value, pos, width = decode_one(data, pos)
        values.append(value)
        widths.append(width)
    return values, widths, pos


def verified_prefix_to_second_end(data: bytes) -> tuple[int, int]:
    _, count = derive_count(data)

    _, _, first_end = parse_n_ints(data, TABLE_START, count)

    tag, tag_end, tag_width = decode_one(data, first_end)
    if (tag, tag_width, data[first_end:tag_end].hex()) != (215, 2, "8157"):
        raise ValueError(
            f"post-first-table tag {tag}/width{tag_width}/"
            f"{data[first_end:tag_end].hex()} != 215/2/8157"
        )

    if tag_end + 3 > len(data):
        raise ValueError("truncated after tag215")

    meta16 = data[tag_end]
    meta5 = data[tag_end + 1]
    if meta16 >= 128:
        raise ValueError(f"state147 diverges: meta16={meta16} >= 128")
    if meta5 >= 128:
        raise ValueError(f"state46 diverges: meta5={meta5} >= 128")

    secondary_start = tag_end + 2
    _, second_start, _, secondary_path = secondary_integer_path(data, secondary_start)
    if secondary_path[-1] != 237:
        raise ValueError(f"secondary integer does not reach state237: {secondary_path}")

    _, _, second_end = parse_n_ints(data, second_start, count)
    return count, second_end


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

        try:
            count, second_end = verified_prefix_to_second_end(data)
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} prefix/second-table: {e}") from e

        # Current corpus takes state50 -> 325 -> 503 -> 4 -> 412.
        try:
            scalar, scalar_end, scalar_width = decode_one(data, second_end)
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} post-second scalar: {e}") from e

        if scalar_width != 1:
            raise SystemExit(
                f"FAIL: block {index} post-second scalar width {scalar_width} != 1; "
                "current source proof for phase-3 entry is scoped to the observed width-1 path"
            )

        third_start = scalar_end
        try:
            values, widths, third_end = parse_n_ints(data, third_start, count)
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} third table: {e}") from e

        if third_end + 4 > len(data):
            raise SystemExit(
                f"FAIL: block {index} lacks 4-byte phase4 count after third table"
            )

        phase4_count = int.from_bytes(data[third_end:third_end + 4], "little")
        phase4_start = third_end + 4

        raw = data[third_start:third_end]
        packed = b"".join(v.to_bytes(8, "little", signed=False) for v in values)
        hist = collections.Counter(widths)

        rows.append({
            "index": index,
            "seed_in": seed,
            "object_size": len(data),
            "object_sha256": digest,
            "table_count": count,
            "second_table_end": second_end,
            "post_second_scalar": {
                "offset": second_end,
                "end_offset": scalar_end,
                "value": scalar,
                "width": scalar_width,
                "encoding_hex": data[second_end:scalar_end].hex(),
                "observed_state_path": [50, 325, 503, 4, 412],
            },
            "third_table_start": third_start,
            "third_table_end": third_end,
            "third_table_encoded_size": third_end - third_start,
            "bytes_remaining_after_third_table": len(data) - third_end,
            "width_histogram": {str(k): hist[k] for k in sorted(hist)},
            "minimum": min(values),
            "maximum": max(values),
            "zero_count": values.count(0),
            "lt_128_count": sum(v < 128 for v in values),
            "table_raw_sha256": sha256(raw),
            "values_u64le_sha256": sha256(packed),
            "first16_values": values[:16],
            "last16_values": values[-16:],
            "phase4_count_u32": {
                "offset": third_end,
                "end_offset": phase4_start,
                "value": phase4_count,
                "encoding_hex": data[third_end:phase4_start].hex(),
                "source_read": "state55 uses buffer.readu32",
            },
            "phase4_start": phase4_start,
            "bytes_remaining_after_phase4_count": len(data) - phase4_start,
        })

    result = {
        "schema": "luraph-deobf.a321-third-int-tables.v1",
        "block_count": len(rows),
        "total_object_bytes": sum(r["object_size"] for r in rows),
        "total_third_table_entries": sum(r["table_count"] for r in rows),
        "source_path": {
            "post_second_scalar": "50(U)->325(Ey)->503(lW)->4(s)->412(nW)",
            "allocation": "412(nW): two table.create(count)",
            "loop": "36(T)",
            "read_first_limb": "401(vW)",
            "store_and_repeat": "343(Py)->36(T)",
            "exit_to_phase4": "36(T)->51(U)->55(t)",
            "phase4_count_read": "state55 buffer.readu32",
        },
        "blocks": rows,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
