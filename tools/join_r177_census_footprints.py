#!/usr/bin/env python3
"""Join the offline R177 writer census with mode233 handler footprints.

No target execution. No reachability inference.

For each non-opcode7 tracked operand hit from the census:
  * if its opcode is absent from the extracted mode233 dispatch, keep MODE_UNRESOLVED;
  * if present, compare the site's concrete w/s/H values against the handler's
    direct destination lane fields;
  * mark a site as a direct tracked-register write candidate only when a
    destination field resolves to R117/R155/R177 at that exact site;
  * preserve helper/call/self-rewrite side-effect gaps independently.

pc3784 is marked as the analysis boundary, not as a pre-boundary last-writer
candidate.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

TRACKED = {117, 155, 177}
BOUNDARY_PC = 3784


def classify_hit(hit: dict, footprints: dict, present: set[int], absent: set[int]) -> dict:
    pc = int(hit["pc"])
    op = int(hit["opcode"])
    tup = {k: int(v) for k, v in hit["tuple"].items()}

    row = {
        "pc": pc,
        "opcode": op,
        "tuple": tup,
        "tracked_operand_fields": hit.get("tracked_operand_fields", {}),
        "classification": None,
        "direct_tracked_destinations": [],
        "side_effect_gap": False,
        "boundary": pc == BOUNDARY_PC,
    }

    if op in absent:
        row["classification"] = "MODE_UNRESOLVED_ABSENT_FROM_MODE233"
        return row

    if op not in present:
        row["classification"] = "MODE_UNRESOLVED_NO_FOOTPRINT"
        return row

    fp = footprints[str(op)]
    dest_fields = fp.get("direct_dest_lane_fields", [])
    direct = []
    for field in dest_fields:
        if field not in tup:
            continue
        reg = int(tup[field])
        if reg in TRACKED:
            direct.append({"field": field, "register": reg})

    row["direct_tracked_destinations"] = direct
    row["side_effect_gap"] = bool(
        fp.get("helper_calls_with_BR")
        or fp.get("calls_through_BR_values")
        or fp.get("all_named_calls")
        or fp.get("lane_self_rewrites")
        or fp.get("unknown_direct_dest_expressions")
    )

    if pc == BOUNDARY_PC and direct:
        row["classification"] = "BOUNDARY_DIRECT_TRACKED_WRITE"
    elif direct and row["side_effect_gap"]:
        row["classification"] = "DIRECT_TRACKED_WRITE_PLUS_SIDE_EFFECT_GAP"
    elif direct:
        row["classification"] = "DIRECT_TRACKED_WRITE"
    elif row["side_effect_gap"]:
        row["classification"] = "NO_DIRECT_TRACKED_DEST_BUT_SIDE_EFFECT_GAP"
    else:
        row["classification"] = "NO_DIRECT_TRACKED_DEST"

    return row


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("writer_census", type=Path)
    ap.add_argument("mode233_footprints", type=Path)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    census = json.loads(args.writer_census.read_text(encoding="utf-8"))
    fps_doc = json.loads(args.mode233_footprints.read_text(encoding="utf-8"))

    if census.get("schema") != "luraph-deobf.r177-offline-writer-census.v1":
        raise SystemExit("FAIL: unexpected writer census schema")
    if fps_doc.get("schema") != "luraph-deobf.mode233-handler-write-footprints.v1":
        raise SystemExit("FAIL: unexpected handler footprint schema")

    present = {int(x) for x in fps_doc.get("present_in_mode233_dispatch", [])}
    absent = {int(x) for x in fps_doc.get("absent_from_mode233_dispatch", [])}
    if present & absent:
        raise SystemExit("FAIL: present/absent opcode sets overlap")

    footprints = fps_doc.get("footprints", {})
    if {int(k) for k in footprints} != present:
        raise SystemExit("FAIL: footprint keys do not exactly match present opcode set")

    hits = census.get("non_opcode7_operand_hits")
    if not isinstance(hits, list):
        raise SystemExit("FAIL: census missing non_opcode7_operand_hits")

    rows = [classify_hit(hit, footprints, present, absent) for hit in hits]

    pre_boundary_direct = [
        r for r in rows
        if r["pc"] < BOUNDARY_PC and r["direct_tracked_destinations"]
    ]
    pre_boundary_r177 = [
        r for r in pre_boundary_direct
        if any(x["register"] == 177 for x in r["direct_tracked_destinations"])
    ]
    boundary = [r for r in rows if r["pc"] == BOUNDARY_PC]

    counts = {}
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1

    result = {
        "schema": "luraph-deobf.r177-census-footprint-join.v1",
        "scope": "static site/handler intersection only; no runtime mode or reachability proof",
        "row_count": len(rows),
        "classification_counts": dict(sorted(counts.items())),
        "pre_boundary_direct_tracked_write_candidates": pre_boundary_direct,
        "pre_boundary_direct_r177_write_candidates": pre_boundary_r177,
        "boundary_rows": boundary,
        "rows": rows,
        "proof_status": "INCOMPLETE_NO_CONTROL_ORDER",
        "complete_for_registers": [],
        "no_target_execution": True,
    }

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8")

    print(f"joined rows: {len(rows)}")
    for key in sorted(counts):
        print(f"{key}: {counts[key]}")
    print(f"pre-boundary direct tracked-write candidates: {len(pre_boundary_direct)}")
    print(f"pre-boundary direct R177 candidates: {len(pre_boundary_r177)}")
    print("proof: INCOMPLETE_NO_CONTROL_ORDER")
    print("complete_for_registers: []")
    print("No target execution performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
