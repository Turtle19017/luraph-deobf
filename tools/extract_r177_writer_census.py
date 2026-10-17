#!/usr/bin/env python3
"""Conservative offline writer census for R117/R155/R177.

This tool does not execute Luau. It SHA-guards the protected source and verified
block1 plaintext, reconstructs VM lanes, applies the two deterministic mode54
bulk XORs plus committed/promoted mode233 bulk XORs, validates promoted opcode
checkpoints, then enumerates:

* every opcode7 return bank whose range intersects R117/R155/R177;
* every non-opcode7 instruction whose concrete w/s/H operand equals one of the
  tracked registers.

The second category is intentionally unresolved until that opcode handler is
modeled. The output never claims a complete ledger.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from lift_vm68_block1_bootstrap import parse_lanes

ROOT = Path(__file__).resolve().parent.parent
TARGET_SHA256 = "02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"
BLOCK1_SHA256 = "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"
TRACKED = (117, 155, 177)

RECEIPTS = [
    "receipts/luraph_VM68_mode233_api_bootstrap.json",
    "receipts/luraph_VM68_mode233_selector135.json",
    "receipts/luraph_VM68_mode233_selector101_93.json",
    "receipts/luraph_VM68_native_builtin_registration.json",
    "receipts/luraph_VM68_mode233_selector107_buffer_continuation.json",
    "receipts/luraph_VM68_mode233_selector56_137.json",
    "receipts/luraph_VM68_mode233_selector141.json",
    "receipts/luraph_VM68_mode233_selector50.json",
    "receipts/luraph_VM68_mode233_selector29.json",
]

CHECKPOINTS = {
    2129: 82,
    4080: 39,
    4183: 52,
    4184: 52,
    652: 77,
    4302: 77,
    2651: 77,
    839: 77,
    3784: 21,
}
PC3784 = (21, 156, 177, 50)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lane_xor(S, w, s, H, seed: int, start: int, length: int) -> None:
    end = start + length - 1
    if start < 1 or end >= len(S):
        raise ValueError(f"XOR range {start}..{end} outside lanes")
    for i in range(1, length + 1):
        mask = (seed ^ i) & 0x7F
        pc = start + i - 1
        S[pc] ^= mask
        w[pc] ^= mask
        s[pc] ^= mask
        H[pc] ^= mask


def bulk_ops(obj, path=""):
    out = []
    if isinstance(obj, dict):
        has_range = all(k in obj for k in ("seed", "start", "length", "end"))
        semantic = str(obj.get("semantic", "")).lower()
        labelled_bulk = (
            "bulk" in path.lower()
            or "bulk xor" in semantic
            or "bulk-xor" in semantic
        )
        if has_range and labelled_bulk:
            seed = int(obj["seed"])
            start = int(obj["start"])
            length = int(obj["length"])
            end = int(obj["end"])
            if end != start + length - 1:
                raise ValueError(f"bad bulk receipt {path}")
            out.append({
                "path": path,
                "seed": seed,
                "start": start,
                "length": length,
                "end": end,
                "semantic": obj.get("semantic"),
            })
        for key, value in obj.items():
            out.extend(bulk_ops(value, path + "/" + str(key)))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            out.extend(bulk_ops(value, path + "/" + str(i)))
    return out


def infer_field_model(arrays, producers, expected_key):
    candidates = []
    for name in ("w", "s", "H"):
        arr = arrays[name]
        for delta in (-1, 0, 1):
            ok = True
            for row in producers:
                pc = int(row["pc"])
                expected = int(row["function_register"] if expected_key == "start"
                               else row["return_count"])
                if int(arr[pc]) + delta != expected:
                    ok = False
                    break
            if ok:
                candidates.append({"field": name, "delta": delta})
    if len(candidates) != 1:
        raise ValueError(f"opcode7 {expected_key} model not unique: {candidates}")
    return candidates[0]


def model_value(model, arrays, pc):
    return int(arrays[model["field"]][pc]) + int(model["delta"])


def opcode7_site_status(pc: int, promoted_producer_pcs: set[int]) -> str:
    return (
        "PROMOTED_MODE233_OPCODE7_PRODUCER"
        if pc in promoted_producer_pcs
        else "MODE_UNRESOLVED_OPCODE7_LIKE_SITE"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("script", type=Path)
    ap.add_argument("block1", type=Path)
    ap.add_argument("--repo-root", type=Path, default=ROOT)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    script_raw = args.script.read_bytes()
    block_raw = args.block1.read_bytes()
    if digest(script_raw) != TARGET_SHA256:
        raise SystemExit(f"FAIL: target SHA mismatch: {digest(script_raw)}")
    if digest(block_raw) != BLOCK1_SHA256:
        raise SystemExit(f"FAIL: block1 SHA mismatch: {digest(block_raw)}")

    try:
        count, S, w, s, H = parse_lanes(block_raw)
        if count != 4474:
            raise ValueError(f"lane count {count} != 4474")

        # Deterministic mode54 body decrypts established before mode233.
        lane_xor(S, w, s, H, 44, 85, 4357)
        lane_xor(S, w, s, H, 11, 93, 4349)

        promoted = {}
        for rel in RECEIPTS:
            obj = json.loads((args.repo_root / rel).read_text(encoding="utf-8"))
            for op in bulk_ops(obj, rel):
                key = (op["seed"], op["start"], op["length"])
                promoted.setdefault(key, op)

        # Regression guard: selector107 pc1582 stores its bulk-XOR record under
        # deterministic_path/5, with the label in the semantic field rather
        # than in the JSON key path. Missing it leaves pc652 at pre-XOR opcode
        # 50 instead of promoted opcode77.
        required_1582 = (113, 639, 26)
        if required_1582 not in promoted:
            raise ValueError(
                "missing promoted pc1582 bulk XOR (seed=113,start=639,length=26)"
            )

        # All these transforms are lane XORs, so exact promoted transforms may
        # be applied once each; overlap/order does not alter the final XOR sum.
        for seed, start, length in sorted(promoted):
            lane_xor(S, w, s, H, seed, start, length)

        checks = []
        for pc, expected in CHECKPOINTS.items():
            checks.append({
                "pc": pc,
                "expected_opcode": expected,
                "actual_opcode": int(S[pc]),
                "pass": int(S[pc]) == expected,
            })
        bad = [x for x in checks if not x["pass"]]
        if bad:
            raise ValueError(f"promoted opcode checkpoint mismatch: {bad}")

        got3784 = (int(S[3784]), int(w[3784]), int(s[3784]), int(H[3784]))
        if got3784 != PC3784:
            raise ValueError(f"pc3784 mismatch: {got3784} != {PC3784}")

        source = script_raw.decode("utf-8")
        op21_anchor = "elseif t==21 then N,a,p=s[l],w[l],H[l];g=N+a;n=BR[g];i=n[J];"
        if source.count(op21_anchor) != 1:
            raise ValueError(f"opcode21 anchor count {source.count(op21_anchor)} != 1")

        # Source-level sanity: opcode7 must exist in the same protected source.
        op7_markers = list(re.finditer(r"(?:if|elseif)\s+t\s*==\s*7\s+then", source))
        if len(op7_markers) != 1:
            raise ValueError(f"opcode7 marker count {len(op7_markers)} != 1")

        prod = json.loads(
            (args.repo_root / "receipts/luraph_VM68_r177_producer_bank_overwrite.json")
            .read_text(encoding="utf-8")
        )
        producers = prod["producers"]
        arrays = {"w": w, "s": s, "H": H}
        start_model = infer_field_model(arrays, producers, "start")
        count_model = infer_field_model(arrays, producers, "count")

        promoted_producer_pcs = {int(row["pc"]) for row in producers}
        opcode7_candidates = []
        mode_unresolved_opcode7_sites = []
        operand_hits = []
        for pc in range(85, 4442):
            opcode = int(S[pc])
            if opcode == 7:
                raw_tuple = {
                    "S": int(S[pc]),
                    "w": int(w[pc]),
                    "s": int(s[pc]),
                    "H": int(H[pc]),
                }
                site_status = opcode7_site_status(pc, promoted_producer_pcs)
                if site_status == "PROMOTED_MODE233_OPCODE7_PRODUCER":
                    # Only these three sites have receipt-backed mode233 opcode7
                    # semantics. Other S==7 slots may belong to another VM mode
                    # or an unproven route and must not inherit this handler.
                    start = model_value(start_model, arrays, pc)
                    nret = model_value(count_model, arrays, pc)
                    if nret < 0 or nret > 10000:
                        raise ValueError(
                            f"promoted opcode7 producer has implausible count at pc{pc}: {nret}"
                        )
                    end = start + nret - 1
                    hits = [reg for reg in TRACKED if start <= reg <= end]
                    opcode7_candidates.append({
                        "pc": pc,
                        "opcode": 7,
                        "register_start": start,
                        "register_end": end,
                        "return_count": nret,
                        "hits": hits,
                        "status": site_status,
                    })
                else:
                    mode_unresolved_opcode7_sites.append({
                        "pc": pc,
                        "opcode": 7,
                        "tuple": raw_tuple,
                        "status": site_status,
                        "note": (
                            "S==7 alone does not establish mode233 opcode7 semantics; "
                            "range/count interpretation is intentionally not applied."
                        ),
                    })
            else:
                fields = {"w": int(w[pc]), "s": int(s[pc]), "H": int(H[pc])}
                hit_fields = {name: value for name, value in fields.items()
                              if value in TRACKED}
                if hit_fields:
                    operand_hits.append({
                        "pc": pc,
                        "opcode": opcode,
                        "tracked_operand_fields": hit_fields,
                        "tuple": {
                            "S": int(S[pc]),
                            "w": int(w[pc]),
                            "s": int(s[pc]),
                            "H": int(H[pc]),
                        },
                        "status": "UNRESOLVED_MODE_AND_HANDLER_WRITE_SEMANTICS",
                    })

        expected = {
            int(row["pc"]): (
                int(row["function_register"]),
                int(row["function_register"]) + int(row["return_count"]) - 1,
            )
            for row in producers
        }
        bypc = {row["pc"]: row for row in opcode7_candidates}
        known_bank_checks = []
        for pc, interval in expected.items():
            row = bypc.get(pc)
            ok = bool(row and
                      (row["register_start"], row["register_end"]) == interval)
            known_bank_checks.append({
                "pc": pc,
                "expected": list(interval),
                "actual": None if row is None else
                          [row["register_start"], row["register_end"]],
                "pass": ok,
            })
        if not all(x["pass"] for x in known_bank_checks):
            raise ValueError(f"known producer banks not reproduced: {known_bank_checks}")

        result = {
            "schema": "luraph-deobf.r177-offline-writer-census.v1",
            "target_sha256": TARGET_SHA256,
            "block1_sha256": BLOCK1_SHA256,
            "scope": "static writer candidates after promoted lane decrypts; no reachability/order proof",
            "lane_count": count,
            "mode54_bulk_xor": [
                {"seed": 44, "start": 85, "length": 4357, "end": 4441},
                {"seed": 11, "start": 93, "length": 4349, "end": 4441},
            ],
            "promoted_mode233_bulk_xor_count": len(promoted),
            "promoted_mode233_bulk_xor": [promoted[k] for k in sorted(promoted)],
            "checkpoint_validation": checks,
            "pc3784_tuple": {
                "S": int(S[3784]), "w": int(w[3784]),
                "s": int(s[3784]), "H": int(H[3784]),
            },
            "opcode7_tuple_model": {
                "start": start_model,
                "count": count_model,
            },
            "known_bank_checks": known_bank_checks,
            "opcode7_candidates_touching_tracked": opcode7_candidates,
            "mode_unresolved_opcode7_like_sites": mode_unresolved_opcode7_sites,
            "non_opcode7_operand_hits": operand_hits,
            "gaps": [
                {
                    "kind": "NON_OPCODE7_HANDLER_WRITE_SEMANTICS",
                    "count": len(operand_hits),
                    "meaning": (
                        "Concrete operands equal tracked registers, but handler "
                        "write footprints are not yet modeled."
                    ),
                },
                {
                    "kind": "MODE_UNRESOLVED_OPCODE7_LIKE_SITES",
                    "count": len(mode_unresolved_opcode7_sites),
                    "meaning": (
                        "S==7 outside the three promoted producer PCs does not "
                        "establish mode233 opcode7 semantics."
                    ),
                },
                {
                    "kind": "HIDDEN_RANGE_ALIAS_CAPTURE_WRITES_NOT_YET_CENSUSED",
                    "meaning": (
                        "Handlers can mutate BR through ranges, aliases, captures "
                        "or lane self-rewrites without a tracked register appearing "
                        "directly in w/s/H. Source-handler footprint analysis is "
                        "required before completeness."
                    ),
                },
                {
                    "kind": "CONTROL_ORDER_NOT_MODELED",
                    "meaning": (
                        "Static writer candidates are not an execution order and "
                        "do not prove that a site reaches pc3784."
                    ),
                },
            ],
            "complete_for_registers": [],
            "proof_status": "INCOMPLETE_WRITER_CENSUS",
            "no_target_execution": True,
        }

        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(
                json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

        print(f"promoted mode233 bulk XORs: {len(promoted)}")
        print(f"opcode7 promoted tracked-writer candidates: {len(opcode7_candidates)}")
        print(f"mode-unresolved S==7 sites: {len(mode_unresolved_opcode7_sites)}")
        print(f"non-opcode7 tracked operand hits: {len(operand_hits)}")
        print("proof: INCOMPLETE_WRITER_CENSUS")
        print("complete_for_registers: []")
        print("No target execution performed")
        return 0

    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc


if __name__ == "__main__":
    sys.exit(main())
