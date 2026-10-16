#!/usr/bin/env python3
"""Parse the complete source-derived phase-5 tail of A321 plaintext objects.

Known layout entering this phase:

  ... third_int_table[count]
  u32 phase4_record_count
  phase4_records[record_count]

Phase 5 then follows the B:A source as:

  serialized integer A
    state388 begins the integer
    all integer-width paths converge at state485
    state485 stores it in q[scalar_A]

  serialized integer B
    state485 immediately begins another integer
    all width paths converge at state340
    state340 stores it in q[q[1]]

  serialized integer C
    state340 immediately begins another integer
    all width paths converge at state129
    state129 stores it in q[8], allocates two table.create(count) arrays,
    and creates a count-bound loop descriptor

  fourth_int_table[count]
    state169 loop controller
    state43 begins one serialized integer
    all width paths converge at state475
    state475 stores value[index] and returns to state169

  fill_offset_delta
    state393 begins a serialized integer
    its width paths converge at state357

  fill_length
    state357 begins another serialized integer
    its width paths converge at state214

  fill_byte
    state214 reads one raw u8 and performs:
      buffer.fill(target_buffer, base_offset + fill_offset_delta,
                  fill_byte, fill_length)

The final branch after state214 depends on object metadata/runtime structure, not
on additional bytes consumed by this serialized tail.

The parser deliberately reports bytes_remaining_after_phase5 instead of
requiring EOF for every object. Block #1 is independently known to end exactly
at this boundary; the 11-object run determines whether that is corpus-wide.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from decode_a321_first_tables import decode_one, resolve_file
from decode_a321_phase4_records import corrected_third_boundary


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_phase4_end(data: bytes) -> tuple[int, int, int, int, int, int]:
    """Return count, scalar_a, scalar_b, third_end, record_count, phase4_end."""
    count, scalar_a, scalar_b, third_end, phase4_start = corrected_third_boundary(data)

    record_count = int.from_bytes(data[third_end:phase4_start], "little")
    remaining = len(data) - phase4_start
    if record_count > remaining // 4:
        raise ValueError(
            f"phase4 record_count={record_count} cannot fit in remaining={remaining}"
        )

    pos = phase4_start
    for record_index in range(1, record_count + 1):
        if pos + 4 > len(data):
            raise ValueError(f"phase4 record {record_index}: truncated tag")
        tag = int.from_bytes(data[pos:pos + 4], "little")
        pos += 4
        if tag % 2 == 0:
            continue
        if pos + 8 > len(data):
            raise ValueError(
                f"phase4 record {record_index}: truncated odd/range payload"
            )
        pos += 8

    return count, scalar_a, scalar_b, third_end, record_count, pos


def integer_field(data: bytes, pos: int) -> tuple[dict, int]:
    value, end, width = decode_one(data, pos)
    return {
        "offset": pos,
        "end_offset": end,
        "value": value,
        "width": width,
        "encoding_hex": data[pos:end].hex(),
    }, end


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
            count, scalar_a, scalar_b, third_end, phase4_count, phase4_end = (
                parse_phase4_end(data)
            )
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} phase4 boundary: {e}") from e

        try:
            field_a, pos = integer_field(data, phase4_end)
            field_b, pos = integer_field(data, pos)
            field_c, table4_start = integer_field(data, pos)
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} phase5 metadata integers: {e}") from e

        pos = table4_start
        values: list[int] = []
        widths: list[int] = []
        try:
            for _ in range(count):
                value, pos, width = decode_one(data, pos)
                values.append(value)
                widths.append(width)
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} fourth table: {e}") from e

        table4_end = pos
        try:
            fill_offset, pos = integer_field(data, pos)
            fill_length, pos = integer_field(data, pos)
        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index} phase5 fill integers: {e}") from e

        if pos >= len(data):
            raise SystemExit(f"FAIL: block {index} missing phase5 fill byte")

        fill_byte_offset = pos
        fill_byte = data[pos]
        phase5_end = pos + 1

        raw = data[table4_start:table4_end]
        packed = b"".join(v.to_bytes(8, "little", signed=False) for v in values)
        hist = collections.Counter(widths)

        rows.append({
            "index": index,
            "seed_in": seed,
            "object_size": len(data),
            "object_sha256": digest,
            "table_count": count,
            "phase4_record_count": phase4_count,
            "phase4_end": phase4_end,
            "phase5_integer_a": field_a,
            "phase5_integer_b": field_b,
            "phase5_integer_c": field_c,
            "fourth_table_start": table4_start,
            "fourth_table_end": table4_end,
            "fourth_table_encoded_size": table4_end - table4_start,
            "width_histogram": {str(k): hist[k] for k in sorted(hist)},
            "minimum": min(values),
            "maximum": max(values),
            "zero_count": values.count(0),
            "lt_128_count": sum(v < 128 for v in values),
            "table_raw_sha256": sha256(raw),
            "values_u64le_sha256": sha256(packed),
            "first16_values": values[:16],
            "last16_values": values[-16:],
            "fill_offset_delta": fill_offset,
            "fill_length": fill_length,
            "fill_byte": {
                "offset": fill_byte_offset,
                "end_offset": phase5_end,
                "value": fill_byte,
                "encoding_hex": f"{fill_byte:02x}",
            },
            "phase5_end": phase5_end,
            "bytes_remaining_after_phase5": len(data) - phase5_end,
            "consumes_object_exactly": phase5_end == len(data),
        })

    exact = [r["index"] for r in rows if r["consumes_object_exactly"]]
    result = {
        "schema": "luraph-deobf.a321-phase5-tail.v1",
        "block_count": len(rows),
        "canonical_slot_map": {
            "table1": {"placement": "q[q[12]]", "companion": "q[q[15]]"},
            "table2": {"placement": "q[q[13]]", "companion": "q[q[11]]"},
            "phase4_range_table": {"placement": "q[q[5]]"},
            "table3": {"placement": "q[q[10]]", "companion": "q[q[16]]"},
            "metadata_a": {"placement": "q[q[9]]"},
            "metadata_b": {"placement": "q[q[1]]"},
            "metadata_c_and_table4_key": {"placement": "q[8]"},
            "table4": {
                "placement": "q[q[8]] after q[8]=metadata_c",
                "companion": "q[q[14]]",
            },
        },
        "source_layout": [
            "serialized_integer_A -> state485 metadata store",
            "serialized_integer_B -> state340 metadata store",
            "serialized_integer_C -> state129 metadata store + allocate two count-sized tables",
            "fourth_int_table[count] -> state169/43/.../475 loop",
            "fill_offset_delta serialized integer",
            "fill_length serialized integer",
            "fill_byte raw u8 -> state214 buffer.fill",
        ],
        "exact_eof_blocks": exact,
        "all_blocks_end_exactly": len(exact) == len(rows),
        "blocks": rows,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
