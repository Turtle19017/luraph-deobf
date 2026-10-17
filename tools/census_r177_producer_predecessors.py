#!/usr/bin/env python3
"""Offline predecessor census around the three R177 producer PCs.

This tool never executes Luau and never infers reachability.

It reconstructs the verified block1 lanes using the same promoted XOR set as
the R177 writer census, then emits conservative clues for producer targets
pc2150, pc3504 and pc3363:

* a small raw lane window around each producer;
* every slot whose w/s/H operand equals target or target-1;
* every slot where one operand is literal 37 and another is target/target-1,
  a useful clue for possible R37 jump-target setters.

No opcode semantics are assigned. Numeric PC order is not treated as execution
order. The output is a candidate census only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from extract_r177_writer_census import (
    BLOCK1_SHA256,
    RECEIPTS,
    ROOT,
    bulk_ops,
    digest,
    lane_xor,
    parse_lanes,
)

TARGETS = (2150, 3504, 3363)
WINDOW_RADIUS = 5


def tuple_at(S, w, s, H, pc: int) -> dict:
    return {
        "pc": pc,
        "S": int(S[pc]),
        "w": int(w[pc]),
        "s": int(s[pc]),
        "H": int(H[pc]),
    }


def scan_target(S, w, s, H, target: int) -> dict:
    literal_values = {target - 1, target}
    operand_hits = []
    r37_cohits = []

    for pc in range(85, 4442):
        fields = {
            "w": int(w[pc]),
            "s": int(s[pc]),
            "H": int(H[pc]),
        }
        matches = {
            name: value for name, value in fields.items()
            if value in literal_values
        }
        if matches:
            row = tuple_at(S, w, s, H, pc)
            row["matched_fields"] = matches
            operand_hits.append(row)

        fields_with_37 = [name for name, value in fields.items() if value == 37]
        fields_with_target = [
            name for name, value in fields.items()
            if value in literal_values
        ]
        if fields_with_37 and fields_with_target:
            row = tuple_at(S, w, s, H, pc)
            row["fields_equal_37"] = fields_with_37
            row["fields_equal_target_or_minus1"] = fields_with_target
            r37_cohits.append(row)

    lo = max(1, target - WINDOW_RADIUS)
    hi = min(len(S) - 1, target + WINDOW_RADIUS)
    window = [tuple_at(S, w, s, H, pc) for pc in range(lo, hi + 1)]

    return {
        "target_pc": target,
        "target_minus_one": target - 1,
        "window_radius": WINDOW_RADIUS,
        "producer_window": window,
        "operand_literal_hits": operand_hits,
        "r37_literal_cohits": r37_cohits,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("block1", type=Path)
    ap.add_argument("--repo-root", type=Path, default=ROOT)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    raw = args.block1.read_bytes()
    got = digest(raw)
    if got != BLOCK1_SHA256:
        raise SystemExit(f"FAIL: block1 SHA mismatch: {got}")

    try:
        count, S, w, s, H = parse_lanes(raw)
        if count != 4474:
            raise ValueError(f"lane count {count} != 4474")

        # Same deterministic pre-mode233 body decrypts as writer census.
        lane_xor(S, w, s, H, 44, 85, 4357)
        lane_xor(S, w, s, H, 11, 93, 4349)

        promoted = {}
        for rel in RECEIPTS:
            obj = json.loads((args.repo_root / rel).read_text(encoding="utf-8"))
            for op in bulk_ops(obj, rel):
                key = (op["seed"], op["start"], op["length"])
                promoted.setdefault(key, op)

        required_1582 = (113, 639, 26)
        if required_1582 not in promoted:
            raise ValueError("missing promoted pc1582 bulk XOR")

        for seed, start, length in sorted(promoted):
            lane_xor(S, w, s, H, seed, start, length)

        producers = {
            2150: (7, 61, 224),
            3504: (7, 117, 90),
            3363: (7, 155, 48),
        }
        producer_checks = []
        for pc, (opcode, start_reg, count_ret) in producers.items():
            producer_checks.append({
                "pc": pc,
                "tuple": tuple_at(S, w, s, H, pc),
                "expected_opcode": opcode,
                "expected_w_start": start_reg,
                "expected_H_count": count_ret,
                "pass": (
                    int(S[pc]) == opcode
                    and int(w[pc]) == start_reg
                    and int(H[pc]) == count_ret
                ),
            })
        if not all(x["pass"] for x in producer_checks):
            raise ValueError(f"producer tuple mismatch: {producer_checks}")

        targets = [scan_target(S, w, s, H, target) for target in TARGETS]

        result = {
            "schema": "luraph-deobf.r177-producer-predecessor-census.v1",
            "block1_sha256": BLOCK1_SHA256,
            "promoted_mode233_bulk_xor_count": len(promoted),
            "producer_checks": producer_checks,
            "targets": targets,
            "scope": (
                "raw lane/literal predecessor clues only; no opcode semantics, "
                "no runtime mode proof, no execution-order inference"
            ),
            "proof_status": "CANDIDATE_CENSUS_ONLY",
            "no_target_execution": True,
        }

        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(
                json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

        print(f"promoted mode233 bulk XORs: {len(promoted)}")
        for row in targets:
            print(
                f"pc{row['target_pc']}: "
                f"literal_hits={len(row['operand_literal_hits'])} "
                f"r37_cohits={len(row['r37_literal_cohits'])}"
            )
        print("proof: CANDIDATE_CENSUS_ONLY")
        print("No target execution performed")
        return 0

    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
