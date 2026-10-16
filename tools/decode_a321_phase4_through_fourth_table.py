#!/usr/bin/env python3
"""Parse A321 phase4 records, scalars C/D/E, and the fourth count-sized table.

This is a longer semantic-phase parser. It starts from the already verified
runtime plaintexts and recomputes the corrected two-scalar/third-table boundary.

Known layout:

  first_int_table[count]
  ...
  second_int_table[count]
  scalar A
  scalar B
  third_int_table[count]
  u32 phase4_record_count
  phase4_records[record_count]
  scalar C
  scalar D
  scalar E
  fourth_int_table[count]
  ...

Phase4 records use the source-derived u32 grammar already documented by
decode_a321_phase4_records.py. Odd interval records are never materialized.

The three scalars C/D/E use the same serialized 1/2/3/4-byte integer format,
but traverse different flattened state chains before converging:

  scalar C starts at state 388 and converges at 485.
  scalar D starts at state 485 and converges at 340.
  scalar E starts at state 340 and converges at 129.

State129 allocates two tables of the original object count and starts a
count-bound loop. State43 reads each fourth-table integer, state475 stores it,
and state169 repeats exactly count times.

No runtime execution or source-buffer provenance is required.
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


def integer_path(data: bytes, pos: int, family: str) -> tuple[int, int, int, list[int]]:
    value, end, width = decode_one(data, pos)
    b0 = data[pos]

    patterns = {
        "C": {
            1: [388, 395, 485],
            2: [388, 148, 498, 485],
            3: [388, 148, 274, 105, 485],
            4: [388, 148, 274, 65, 485],
        },
        "D": {
            1: [485, 199, 340],
            2: [485, 510, 511, 340],
            3: [485, 510, 208, 326, 340],
            4: [485, 510, 208, 122, 340],
        },
        "E": {
            1: [340, 26, 129],
            2: [340, 230, 206, 129],
            3: [340, 230, 441, 424, 129],
            4: [340, 230, 441, 125, 129],
        },
        "FOURTH": {
            1: [43, 80, 475, 169],
            2: [43, 200, 371, 475, 169],
            3: [43, 200, 18, 120, 475, 169],
            4: [43, 200, 18, 487, 475, 169],
        },
    }
    if family not in patterns:
        raise ValueError(f"unknown integer path family {family!r}")

    if width == 1:
        ok = b0 < 128
    elif width == 2:
        ok = b0 >= 128 and data[pos + 1] < 128
    elif width == 3:
        ok = (
            b0 >= 128
            and data[pos + 1] >= 128
            and data[pos + 2] < 128
        )
    elif width == 4:
        ok = (
            b0 >= 128
            and data[pos + 1] >= 128
            and data[pos + 2] >= 128
        )
    else:
        ok = False

    if not ok:
        raise ValueError(
            f"{family} width/threshold mismatch at {pos}: width={width}"
        )

    return value, end, width, patterns[family][width]


def skip_phase4_records(data: bytes, third_end: int) -> tuple[int, int, int, int, list[dict]]:
    if third_end + 4 > len(data):
        raise ValueError("truncated phase4 record count")

    phase4_start = third_end + 4
    record_count = int.from_bytes(data[third_end:phase4_start], "little")
    remaining = len(data) - phase4_start
    if record_count > remaining // 4:
        raise ValueError(
            f"phase4 record_count={record_count} cannot fit in remaining "
            f"{remaining} bytes at minimum 4 bytes/record"
        )

    pos = phase4_start
    literal_count = 0
    range_count = 0
    records: list[dict] = []

    for record_index in range(1, record_count + 1):
        if pos + 4 > len(data):
            raise ValueError(f"phase4 record {record_index}: truncated tag")
        start = pos
        tag = int.from_bytes(data[pos:pos + 4], "little")
        pos += 4

        if tag % 2 == 0:
            literal_count += 1
            records.append({
                "record_index": record_index,
                "kind": "literal",
                "offset": start,
                "end_offset": pos,
                "tag_u32": tag,
                "value": tag // 2,
            })
            continue

        if pos + 8 > len(data):
            raise ValueError(
                f"phase4 record {record_index}: truncated odd/range payload"
            )
        range_count += 1
        range_start = tag // 2
        range_end = int.from_bytes(data[pos:pos + 4], "little")
        range_value = int.from_bytes(data[pos + 4:pos + 8], "little")
        pos += 8
        records.append({
            "record_index": record_index,
            "kind": "range_fill",
            "offset": start,
            "end_offset": pos,
            "tag_u32": tag,
            "range_start": range_start,
            "range_end": range_end,
            "value": range_value,
            "inner_iterations": (
                range_end - range_start + 1
                if range_end >= range_start else 0
            ),
        })

    return record_count, phase4_start, pos, literal_count, range_count, records


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
            count, scalar_a, scalar_b, third_end, _ = corrected_third_boundary(data)
            (
                phase4_record_count,
                phase4_start,
                phase4_end,
                phase4_literal_count,
                phase4_range_count,
                phase4_records,
            ) = skip_phase4_records(data, third_end)

            c_val, c_end, c_width, c_path = integer_path(data, phase4_end, "C")
            d_val, d_end, d_width, d_path = integer_path(data, c_end, "D")
            e_val, fourth_start, e_width, e_path = integer_path(data, d_end, "E")
        except (ValueError, IndexError) as exc:
            raise SystemExit(
                f"FAIL: block {index} phase4/scalars C-D-E boundary: {exc}"
            ) from exc

        pos = fourth_start
        values: list[int] = []
        widths: list[int] = []
        width_paths = collections.Counter()

        try:
            for _ in range(count):
                value, next_pos, width, path4 = integer_path(data, pos, "FOURTH")
                values.append(value)
                widths.append(width)
                width_paths["->".join(map(str, path4))] += 1
                pos = next_pos
        except (ValueError, IndexError) as exc:
            raise SystemExit(f"FAIL: block {index} fourth table: {exc}") from exc

        fourth_end = pos
        raw = data[fourth_start:fourth_end]
        packed = b"".join(v.to_bytes(8, "little", signed=False) for v in values)
        hist = collections.Counter(widths)

        next_integer = None
        if fourth_end < len(data):
            try:
                nxt, nxt_end, nxt_width = decode_one(data, fourth_end)
                next_integer = {
                    "offset": fourth_end,
                    "end_offset": nxt_end,
                    "value": nxt,
                    "width": nxt_width,
                    "encoding_hex": data[fourth_end:nxt_end].hex(),
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
            "phase4": {
                "record_count": phase4_record_count,
                "start": phase4_start,
                "end": phase4_end,
                "encoded_size": phase4_end - phase4_start,
                "literal_record_count": phase4_literal_count,
                "range_record_count": phase4_range_count,
                "records": phase4_records,
            },
            "scalar_c": {
                "offset": phase4_end,
                "end_offset": c_end,
                "value": c_val,
                "width": c_width,
                "encoding_hex": data[phase4_end:c_end].hex(),
                "state_path": c_path,
            },
            "scalar_d": {
                "offset": c_end,
                "end_offset": d_end,
                "value": d_val,
                "width": d_width,
                "encoding_hex": data[c_end:d_end].hex(),
                "state_path": d_path,
            },
            "scalar_e": {
                "offset": d_end,
                "end_offset": fourth_start,
                "value": e_val,
                "width": e_width,
                "encoding_hex": data[d_end:fourth_start].hex(),
                "state_path": e_path,
            },
            "fourth_table_start": fourth_start,
            "fourth_table_end": fourth_end,
            "fourth_table_encoded_size": fourth_end - fourth_start,
            "bytes_remaining_after_fourth_table": len(data) - fourth_end,
            "width_histogram": {str(k): hist[k] for k in sorted(hist)},
            "state_path_histogram": dict(sorted(width_paths.items())),
            "minimum": min(values),
            "maximum": max(values),
            "zero_count": values.count(0),
            "lt_128_count": sum(v < 128 for v in values),
            "table_raw_sha256": sha256(raw),
            "values_u64le_sha256": sha256(packed),
            "first16_values": values[:16],
            "last16_values": values[-16:],
            "next_serialized_integer_preview": next_integer,
        })

    result = {
        "schema": "luraph-deobf.a321-phase4-through-fourth-table.v1",
        "block_count": len(rows),
        "total_object_bytes": sum(r["object_size"] for r in rows),
        "total_fourth_table_entries": sum(r["table_count"] for r in rows),
        "source_path": {
            "phase4_exit": "407(sW)->1(v)->388(eW)",
            "scalar_c": {
                "width1": "388->395->485",
                "width2": "388->148->498->485",
                "width3": "388->148->274->105->485",
                "width4": "388->148->274->65->485",
            },
            "scalar_d": {
                "width1": "485->199->340",
                "width2": "485->510->511->340",
                "width3": "485->510->208->326->340",
                "width4": "485->510->208->122->340",
            },
            "scalar_e": {
                "width1": "340->26->129",
                "width2": "340->230->206->129",
                "width3": "340->230->441->424->129",
                "width4": "340->230->441->125->129",
            },
            "fourth_table": {
                "allocation_and_loop": "129(E)->169(cy)",
                "read_first_limb": "43(m)",
                "width1": "43->80->475->169",
                "width2": "43->200->371->475->169",
                "width3": "43->200->18->120->475->169",
                "width4": "43->200->18->487->475->169",
                "store": "475(jW)",
                "loop_exit": "169(cy)->361(gy)",
            },
        },
        "blocks": rows,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
