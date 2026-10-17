#!/usr/bin/env python3
"""Refine the R177 census/footprint join with the pc1229 opcode34 audit.

Offline only. No target execution and no reachability inference beyond the
scope of the input receipts/audits.

If the pc1229 audit proves that w=177 is the selector121 lazy-repair XOR key
rather than a BR[177] destination on that concrete opcode34 path, remove pc1229
from the generic path-insensitive direct-writer candidate set.

All other mode/control/alias gaps remain open.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

EXPECTED_JOIN_SCHEMA = "luraph-deobf.r177-census-footprint-join.v1"
EXPECTED_AUDIT_SCHEMA = "luraph-deobf.r177-pc1229-op34-audit.v1"
EXPECTED_CLASS = "RECEIPT_SUPPORTED_SELECTOR121_LAZY_REPAIR_NOT_DIRECT_R177_WRITE"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("join_json", type=Path)
    ap.add_argument("pc1229_audit_json", type=Path)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    joined = json.loads(args.join_json.read_text(encoding="utf-8"))
    audit = json.loads(args.pc1229_audit_json.read_text(encoding="utf-8"))

    if joined.get("schema") != EXPECTED_JOIN_SCHEMA:
        raise SystemExit("FAIL: unexpected join schema")
    if audit.get("schema") != EXPECTED_AUDIT_SCHEMA:
        raise SystemExit("FAIL: unexpected pc1229 audit schema")
    if int(audit.get("pc", -1)) != 1229:
        raise SystemExit("FAIL: pc1229 audit has wrong pc")
    if int(audit.get("fail", -1)) != 0:
        raise SystemExit("FAIL: pc1229 audit did not pass")
    if audit.get("classification") != EXPECTED_CLASS:
        raise SystemExit("FAIL: pc1229 audit classification mismatch")
    if audit.get("r177_direct_write") is not False:
        raise SystemExit("FAIL: pc1229 audit did not rule out direct R177 write")

    direct = joined.get("pre_boundary_direct_tracked_write_candidates", [])
    r177 = joined.get("pre_boundary_direct_r177_write_candidates", [])

    d1229 = [x for x in direct if int(x.get("pc", -1)) == 1229]
    r1229 = [x for x in r177 if int(x.get("pc", -1)) == 1229]
    if len(d1229) != 1 or len(r1229) != 1:
        raise SystemExit(
            f"FAIL: expected exactly one generic pc1229 candidate in both sets; "
            f"got direct={len(d1229)} r177={len(r1229)}"
        )

    refined_direct = [x for x in direct if int(x.get("pc", -1)) != 1229]
    refined_r177 = [x for x in r177 if int(x.get("pc", -1)) != 1229]

    result = {
        "schema": "luraph-deobf.r177-census-footprint-refined.v1",
        "removed_false_positive": {
            "pc": 1229,
            "reason": (
                "path-insensitive opcode34 footprint treated w as a possible BR "
                "destination, but the concrete selector121 lazy-repair path uses "
                "w=177 as the string payload XOR key for proto254"
            ),
            "source_join_row": d1229[0],
            "pc1229_audit_classification": audit["classification"],
        },
        "pre_boundary_direct_tracked_write_candidates": refined_direct,
        "pre_boundary_direct_r177_write_candidates": refined_r177,
        "remaining_mode_unresolved_count": int(
            joined.get("classification_counts", {}).get(
                "MODE_UNRESOLVED_ABSENT_FROM_MODE233", 0
            )
        ),
        "boundary_rows": joined.get("boundary_rows", []),
        "proof_status": "INCOMPLETE_NO_CONTROL_ORDER_OR_MODE_COMPLETENESS",
        "last_writer": "UNKNOWN",
        "complete_for_registers": [],
        "no_target_execution": True,
    }

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    print("removed pc1229 generic direct-writer false positive: 1")
    print(
        "remaining pre-boundary direct tracked-write candidates:",
        len(refined_direct),
    )
    print(
        "remaining pre-boundary direct R177 candidates:",
        len(refined_r177),
    )
    print("last writer: UNKNOWN")
    print("proof: INCOMPLETE_NO_CONTROL_ORDER_OR_MODE_COMPLETENESS")
    print("complete_for_registers: []")
    print("No target execution performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
