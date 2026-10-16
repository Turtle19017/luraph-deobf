#!/usr/bin/env python3
"""Parse the u32-counted phase-4 record stream after the third A321 table.

Corrected layout before this phase:

  ... second_int_table[count]
  scalar_a
  scalar_b
  third_int_table[count]
  phase4_record_count_u32
  phase4_records[record_count]
  ...

Source record grammar:

  state55:
    record_count = buffer.readu32(...)
    create result table
    create outer loop descriptor

  state407:
    iterate exactly record_count records

  state72:
    tag = buffer.readu32(...)
    half = tag / 2

    tag even:
      state477 stores floor(half) in the phase-4 result table at the current
      sequential record slot; then state95 advances to the next record.

    tag odd:
      state411 reads two more u32 values:
        range_end
        value
      state221/297 performs an inner interval fill using:
        range_start = floor(tag / 2)
        range_end   = first extra u32
        value       = second extra u32
      then state456/95 returns to the outer record loop.

This tool does NOT materialize odd-record intervals. It records the logical span
and source offsets only, so a large range cannot cause memory/time blow-ups.

After the phase-4 records, the tool previews the next serialized integer but
does not assign phase-5 semantics yet.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from decode_a321_first_tables import decode_one, resolve_file
from decode_a321_third_tables import (
    parse_n_ints,
    scalar_b_state_path,
    verified_prefix_to_second_end,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def corrected_third_boundary(data: bytes) -> tuple[int, int, int, int, int]:
    """Return count, scalar_a, scalar_b, third_end, phase4_start."""
    count, second_end = verified_prefix_to_second_end(data)

    scalar_a, scalar_a_end, scalar_a_width = decode_one(data, second_end)
    if scalar_a_width != 1:
        raise ValueError(
            f"scalar_a width {scalar_a_width} != 1; current corpus proof is width1"
        )

    scalar_b, third_start, _, scalar_b_path = scalar_b_state_path(data, scalar_a_end)
    if scalar_b_path[-1] != 412:
        raise ValueError(f"scalar_b path does not reach state412: {scalar_b_path}")

    _, _, third_end = parse_n_ints(data, third_start, count)
    if third_end + 4 > len(data):
        raise ValueError("truncated phase4 record count")

    phase4_start = third_end + 4
    return count, scalar_a, scalar_b, third_end, phase4_start


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
            count, scalar_a, scalar_b, third_end, phase4_start = (
                corrected_third_boundary(data)
            )
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} corrected phase3 boundary: {e}") from e

        record_count = int.from_bytes(data[third_end:phase4_start], "little")
        remaining = len(data) - phase4_start
        if record_count > remaining // 4:
            raise SystemExit(
                f"FAIL: block {index} phase4 record_count={record_count} cannot fit "
                f"in remaining {remaining} bytes at minimum 4 bytes/record"
            )

        pos = phase4_start
        records = []
        literal_count = 0
        range_count = 0
        logical_range_iterations = 0

        for record_index in range(1, record_count + 1):
            if pos + 4 > len(data):
                raise SystemExit(
                    f"FAIL: block {index} phase4 record {record_index}: truncated tag"
                )
            tag_offset = pos
            tag = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4

            if tag % 2 == 0:
                literal_count += 1
                value = tag // 2
                records.append({
                    "record_index": record_index,
                    "kind": "literal",
                    "offset": tag_offset,
                    "end_offset": pos,
                    "tag_u32": tag,
                    "encoding_hex": data[tag_offset:pos].hex(),
                    "sequential_slot": record_index,
                    "value": value,
                    "source_path": [407, 72, 477, 95],
                })
                continue

            if pos + 8 > len(data):
                raise SystemExit(
                    f"FAIL: block {index} phase4 record {record_index}: "
                    "truncated odd/range payload"
                )

            range_count += 1
            range_start = tag // 2
            range_end = int.from_bytes(data[pos:pos + 4], "little")
            value = int.from_bytes(data[pos + 4:pos + 8], "little")
            pos += 8

            inner_iterations = (
                range_end - range_start + 1 if range_end >= range_start else 0
            )
            logical_range_iterations += inner_iterations

            records.append({
                "record_index": record_index,
                "kind": "range_fill",
                "offset": tag_offset,
                "end_offset": pos,
                "tag_u32": tag,
                "encoding_hex": data[tag_offset:pos].hex(),
                "range_start": range_start,
                "range_end": range_end,
                "value": value,
                "inner_iterations": inner_iterations,
                "source_path": [407, 72, 411, 221, 297, 456, 95],
                "note": (
                    "state297 repeats once per logical interval position when "
                    "range_end >= range_start; interval is not materialized here"
                ),
            })

        phase4_end = pos

        next_integer = None
        if phase4_end < len(data):
            try:
                nxt, nxt_end, nxt_width = decode_one(data, phase4_end)
                next_integer = {
                    "offset": phase4_end,
                    "end_offset": nxt_end,
                    "value": nxt,
                    "width": nxt_width,
                    "encoding_hex": data[phase4_end:nxt_end].hex(),
                }
            except (ValueError, IndexError):
                pass

        rows.append({
            "index": index,
            "seed_in": seed,
            "object_size": len(data),
            "object_sha256": digest,
            "table_count": count,
            "post_second_scalar_a": scalar_a,
            "post_second_scalar_b": scalar_b,
            "third_table_end": third_end,
            "phase4_record_count_u32": {
                "offset": third_end,
                "end_offset": phase4_start,
                "value": record_count,
                "encoding_hex": data[third_end:phase4_start].hex(),
            },
            "phase4_start": phase4_start,
            "phase4_end": phase4_end,
            "phase4_encoded_size": phase4_end - phase4_start,
            "literal_record_count": literal_count,
            "range_record_count": range_count,
            "logical_range_iterations": logical_range_iterations,
            "records": records,
            "bytes_remaining_after_phase4": len(data) - phase4_end,
            "next_serialized_integer_preview": next_integer,
        })

    result = {
        "schema": "luraph-deobf.a321-phase4-records.v1",
        "block_count": len(rows),
        "source_path": {
            "count_read": "55(t): buffer.readu32",
            "outer_loop": "407(sW)",
            "record_tag_read": "72(Y): buffer.readu32",
            "even_record": "477(MW) -> 95(I) -> 407(sW)",
            "odd_record": "411(nW) -> 221(fy) -> 297(Ry)* -> 456(qW) -> 95(I) -> 407(sW)",
            "outer_exit": "407(sW) -> 1(v)",
        },
        "blocks": rows,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
