#!/usr/bin/env python3
"""Parse the common post-table B:A fields across all 11 A321 plaintexts.

The first-table parser establishes table_end for each object. All eleven then
contain the serialized integer 215 encoded as 81 57.

Source-derived path after that tag:

  state147 reads meta16
    <128  -> 167
    >=128 -> 267

  state46 (after 167) reads meta5
    <128  -> 229
    >=128 -> 490

  state10 (after 229) begins ANOTHER serialized integer at E+4.

That integer uses the same verified 1/2/3/4-byte grammar:
  width 1: 10 -> 328 -> 237
  width 2: 10 -> 425 -> 88  -> 237
  width 3: 10 -> 425 -> 473 -> 482 -> 237
  width 4: 10 -> 425 -> 473 -> 101 -> 237

Important correction: the old classifier inverted the state10 branch. The
actual source is:

    not(128 > first_byte) and 425 or 328

so first_byte < 128 goes directly to 328, while first_byte >= 128 goes to 425
to read more integer limbs.

Inputs are verified against the runtime plaintext receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from decode_a321_first_tables import decode_one, derive_count, resolve_file, TABLE_START


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recompute_table_end(data: bytes) -> tuple[int, int]:
    _, count = derive_count(data)
    pos = TABLE_START
    for _ in range(count):
        _, pos, _ = decode_one(data, pos)
    return count, pos


def secondary_integer_path(data: bytes, pos: int) -> tuple[int, int, int, list[int]]:
    """Decode the integer beginning at state10 and return its exact state path."""
    value, end, width = decode_one(data, pos)
    b0 = data[pos]

    if width == 1:
        if b0 >= 128:
            raise ValueError("width1 integer has high first byte")
        path = [10, 328, 237]
    elif width == 2:
        if not (b0 >= 128 and data[pos + 1] < 128):
            raise ValueError("width2 threshold pattern mismatch")
        path = [10, 425, 88, 237]
    elif width == 3:
        if not (b0 >= 128 and data[pos + 1] >= 128 and data[pos + 2] < 128):
            raise ValueError("width3 threshold pattern mismatch")
        path = [10, 425, 473, 482, 237]
    elif width == 4:
        if not (b0 >= 128 and data[pos + 1] >= 128 and data[pos + 2] >= 128):
            raise ValueError("width4 threshold pattern mismatch")
        path = [10, 425, 473, 101, 237]
    else:
        raise ValueError(f"unexpected serialized integer width {width}")

    return value, end, width, path


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
        path = resolve_file(args.plaintext_dir, meta)
        data = path.read_bytes()

        if len(data) != int(meta["size"]):
            raise SystemExit(f"FAIL: block {index} size mismatch")
        digest = sha256(data)
        if digest != meta["sha256"]:
            raise SystemExit(f"FAIL: block {index} SHA mismatch: {digest}")
        if data[:16].hex() != meta["head16_hex"]:
            raise SystemExit(f"FAIL: block {index} head16 mismatch")

        count, table_end = recompute_table_end(data)

        tag, tag_end, tag_width = decode_one(data, table_end)
        if tag != 215 or tag_width != 2:
            raise SystemExit(
                f"FAIL: block {index} post-table integer {tag}/width{tag_width} != 215/2"
            )
        if data[table_end:tag_end] != bytes.fromhex("8157"):
            raise SystemExit(
                f"FAIL: block {index} post-table encoding "
                f"{data[table_end:tag_end].hex()} != 8157"
            )

        if tag_end + 3 > len(data):
            raise SystemExit(f"FAIL: block {index} truncated after post-table tag")

        meta16 = data[tag_end]
        branch147 = 167 if meta16 < 128 else 267

        meta5 = None
        branch46 = None
        secondary = None
        reaches237 = False
        full_path = [82, 272, 275, 147, branch147]

        if branch147 == 167:
            meta5 = data[tag_end + 1]
            branch46 = 229 if meta5 < 128 else 490
            full_path += [46, branch46]

            if branch46 == 229:
                secondary_start = tag_end + 2
                try:
                    value2, end2, width2, path2 = secondary_integer_path(
                        data, secondary_start
                    )
                except ValueError as e:
                    raise SystemExit(f"FAIL: block {index}: {e}") from e

                secondary = {
                    "offset": secondary_start,
                    "end_offset": end2,
                    "value": value2,
                    "width": width2,
                    "encoding_hex": data[secondary_start:end2].hex(),
                    "state_path": path2,
                }
                full_path += path2
                reaches237 = path2[-1] == 237

        rows.append({
            "index": index,
            "seed_in": int(meta["seed_in"]),
            "table_count": count,
            "table_end": table_end,
            "tag215": {
                "offset": table_end,
                "end_offset": tag_end,
                "encoding_hex": data[table_end:tag_end].hex(),
                "value": tag,
                "width": tag_width,
            },
            "meta16": {
                "offset": tag_end,
                "byte": meta16,
                "state147_next": branch147,
            },
            "meta5": {
                "offset": tag_end + 1,
                "byte": meta5,
                "state46_next": branch46,
            } if meta5 is not None else None,
            "secondary_integer": secondary,
            "reaches_state237": reaches237,
            "path_from_state82": full_path,
            "cursor_at_state237": secondary["end_offset"]
                if reaches237 and secondary is not None else None,
            "raw_post_table_hex": (
                data[table_end:secondary["end_offset"]].hex()
                if secondary is not None
                else data[table_end:tag_end + 1].hex()
            ),
        })

    width_groups: dict[str, list[int]] = {}
    path_groups: dict[str, list[int]] = {}
    for row in rows:
        sec = row["secondary_integer"]
        width_key = str(sec["width"]) if sec is not None else "unreached"
        width_groups.setdefault(width_key, []).append(row["index"])
        path_key = "->".join(str(x) for x in row["path_from_state82"])
        path_groups.setdefault(path_key, []).append(row["index"])

    reaches237 = [row["index"] for row in rows if row["reaches_state237"]]

    result = {
        "schema": "luraph-deobf.a321-post-table-fields.v2",
        "block_count": len(rows),
        "invariant_tag": {"value": 215, "width": 2, "encoding_hex": "8157"},
        "state10_branch_rule": {
            "first_byte_lt_128": 328,
            "first_byte_ge_128": 425,
        },
        "secondary_integer_width_groups": width_groups,
        "path_groups": path_groups,
        "reaches_state237_blocks": reaches237,
        "blocks": rows,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
