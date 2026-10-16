#!/usr/bin/env python3
"""Parse the complete known A321 plaintext layout in one fail-closed pass.

This consolidates the source-derived phases already established for the sample:

  16-byte prefix / count derivation
  table1[count]
  tag215
  meta16
  meta5
  secondary_integer
  table2[count]
  scalar_a
  scalar_b
  table3[count]
  u32 phase4_record_count
  phase4 records (literal / range-fill)
  metadata_a
  metadata_b
  metadata_c
  table4[count]
  fill_offset_delta
  fill_length
  fill_byte

The tool verifies every plaintext against the immutable runtime receipt before
parsing. It reports, but does not require, exact EOF at the fill-tail boundary.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from decode_a321_first_tables import decode_one, derive_count, resolve_file, TABLE_START
from decode_a321_post_table_branch import secondary_integer_path
from decode_a321_third_tables import scalar_b_state_path


SLOT_MAP = {
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
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_table(data: bytes, start: int, count: int) -> tuple[dict, int]:
    values: list[int] = []
    widths: list[int] = []
    pos = start
    for _ in range(count):
        value, pos, width = decode_one(data, pos)
        values.append(value)
        widths.append(width)

    raw = data[start:pos]
    packed = b"".join(v.to_bytes(8, "little", signed=False) for v in values)
    hist = collections.Counter(widths)
    return {
        "start": start,
        "end": pos,
        "count": count,
        "encoded_size": pos - start,
        "width_histogram": {str(k): hist[k] for k in sorted(hist)},
        "minimum": min(values),
        "maximum": max(values),
        "zero_count": values.count(0),
        "lt_128_count": sum(v < 128 for v in values),
        "raw_sha256": sha256(raw),
        "values_u64le_sha256": sha256(packed),
        "first16_values": values[:16],
        "last16_values": values[-16:],
    }, pos


def parse_integer_field(data: bytes, pos: int) -> tuple[dict, int]:
    value, end, width = decode_one(data, pos)
    return {
        "offset": pos,
        "end_offset": end,
        "value": value,
        "width": width,
        "encoding_hex": data[pos:end].hex(),
    }, end


def parse_phase4_records(data: bytes, pos: int, record_count: int) -> tuple[dict, int]:
    records = []
    literal_count = 0
    range_count = 0
    logical_range_iterations = 0
    start = pos

    for record_index in range(1, record_count + 1):
        if pos + 4 > len(data):
            raise ValueError(f"phase4 record {record_index}: truncated tag")
        rec_start = pos
        tag = int.from_bytes(data[pos:pos + 4], "little")
        pos += 4

        if tag % 2 == 0:
            literal_count += 1
            records.append({
                "record_index": record_index,
                "kind": "literal",
                "offset": rec_start,
                "end_offset": pos,
                "tag_u32": tag,
                "value": tag // 2,
            })
            continue

        if pos + 8 > len(data):
            raise ValueError(f"phase4 record {record_index}: truncated range payload")

        range_count += 1
        range_start = tag // 2
        range_end = int.from_bytes(data[pos:pos + 4], "little")
        value = int.from_bytes(data[pos + 4:pos + 8], "little")
        pos += 8
        iterations = range_end - range_start + 1 if range_end >= range_start else 0
        logical_range_iterations += iterations

        records.append({
            "record_index": record_index,
            "kind": "range_fill",
            "offset": rec_start,
            "end_offset": pos,
            "tag_u32": tag,
            "range_start": range_start,
            "range_end": range_end,
            "value": value,
            "inner_iterations": iterations,
        })

    return {
        "start": start,
        "end": pos,
        "record_count": record_count,
        "encoded_size": pos - start,
        "literal_record_count": literal_count,
        "range_record_count": range_count,
        "logical_range_iterations": logical_range_iterations,
        "records": records,
    }, pos


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
    metas = runtime.get("blocks")
    if not isinstance(metas, list) or len(metas) != 11:
        raise SystemExit("FAIL: runtime receipt must contain exactly 11 blocks")

    rows = []
    for meta in metas:
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
            raw_count, count = derive_count(data)

            table1, pos = parse_table(data, TABLE_START, count)

            tag215, pos2, tag_width = decode_one(data, pos)
            if (tag215, tag_width, data[pos:pos2].hex()) != (215, 2, "8157"):
                raise ValueError(
                    f"tag215 mismatch: {tag215}/width{tag_width}/{data[pos:pos2].hex()}"
                )
            tag = {
                "offset": pos, "end_offset": pos2, "value": tag215,
                "width": tag_width, "encoding_hex": data[pos:pos2].hex(),
            }
            pos = pos2

            if pos + 2 > len(data):
                raise ValueError("truncated meta16/meta5")
            meta16 = data[pos]
            meta5 = data[pos + 1]
            if meta16 >= 128:
                raise ValueError(f"meta16={meta16} diverges from state147->167")
            if meta5 >= 128:
                raise ValueError(f"meta5={meta5} diverges from state46->229")
            pos += 2

            secondary_start = pos
            secondary_value, pos, secondary_width, secondary_path = (
                secondary_integer_path(data, secondary_start)
            )
            secondary = {
                "offset": secondary_start,
                "end_offset": pos,
                "value": secondary_value,
                "width": secondary_width,
                "encoding_hex": data[secondary_start:pos].hex(),
                "state_path": secondary_path,
            }

            table2, pos = parse_table(data, pos, count)

            scalar_a, pos = parse_integer_field(data, pos)
            if scalar_a["width"] != 1:
                raise ValueError(
                    f"scalar_a width={scalar_a['width']} diverges from observed corpus"
                )

            scalar_b_start = pos
            scalar_b_value, pos, scalar_b_width, scalar_b_path = (
                scalar_b_state_path(data, scalar_b_start)
            )
            scalar_b = {
                "offset": scalar_b_start,
                "end_offset": pos,
                "value": scalar_b_value,
                "width": scalar_b_width,
                "encoding_hex": data[scalar_b_start:pos].hex(),
                "state_path": scalar_b_path,
            }

            table3, pos = parse_table(data, pos, count)

            if pos + 4 > len(data):
                raise ValueError("truncated phase4 record count")
            phase4_count_offset = pos
            phase4_count = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
            if phase4_count > (len(data) - pos) // 4:
                raise ValueError(
                    f"phase4_count={phase4_count} cannot fit in remaining bytes"
                )
            phase4, pos = parse_phase4_records(data, pos, phase4_count)
            phase4["count_offset"] = phase4_count_offset
            phase4["count_end_offset"] = phase4_count_offset + 4
            phase4["count_encoding_hex"] = data[
                phase4_count_offset:phase4_count_offset + 4
            ].hex()

            metadata_a, pos = parse_integer_field(data, pos)
            metadata_b, pos = parse_integer_field(data, pos)
            metadata_c, pos = parse_integer_field(data, pos)

            table4, pos = parse_table(data, pos, count)

            fill_offset, pos = parse_integer_field(data, pos)
            fill_length, pos = parse_integer_field(data, pos)
            if pos >= len(data):
                raise ValueError("missing fill_byte")
            fill_byte_offset = pos
            fill_byte = data[pos]
            pos += 1

        except (ValueError, IndexError) as e:
            raise SystemExit(f"FAIL: block {index}: {e}") from e

        rows.append({
            "index": index,
            "seed_in": seed,
            "object_size": len(data),
            "object_sha256": digest,
            "header16_hex": data[:16].hex(),
            "header_raw_count_value": raw_count,
            "count": count,
            "canonical": {
                "table1": table1,
                "tag215": tag,
                "meta16": meta16,
                "meta5": meta5,
                "secondary_integer": secondary,
                "table2": table2,
                "scalar_a": scalar_a,
                "scalar_b": scalar_b,
                "table3": table3,
                "phase4_range_table": phase4,
                "metadata_a": metadata_a,
                "metadata_b": metadata_b,
                "metadata_c_and_table4_key": metadata_c,
                "table4": table4,
                "fill": {
                    "offset_delta": fill_offset,
                    "length": fill_length,
                    "byte": {
                        "offset": fill_byte_offset,
                        "end_offset": fill_byte_offset + 1,
                        "value": fill_byte,
                        "encoding_hex": f"{fill_byte:02x}",
                    },
                    "source_operation": (
                        "buffer.fill(target_buffer, "
                        "base_offset + offset_delta, byte, length)"
                    ),
                },
            },
            "end_offset": pos,
            "bytes_remaining": len(data) - pos,
            "consumes_object_exactly": pos == len(data),
        })

    exact = [row["index"] for row in rows if row["consumes_object_exactly"]]
    result = {
        "schema": "luraph-deobf.a321-full-layout.v1",
        "block_count": len(rows),
        "total_object_bytes": sum(row["object_size"] for row in rows),
        "canonical_slot_map": SLOT_MAP,
        "source_finalization": {
            "last_byte_consumer": "214(ny): raw fill byte + buffer.fill",
            "post_fill_branch": "214 -> 451 when object flag [6] is false; otherwise 35",
            "closure_attach": (
                "451 reuses object slot [5] and goes 48 when present; "
                "otherwise goes 39, whose J>38 branch builds c[B.ep], stores P[2][5], "
                "then returns 48"
            ),
            "return_path": "35 -> 513; 513/WW returns control code 2; B:A returns q",
        },
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
