#!/usr/bin/env python3
"""Fail-closed offline write-order checker for the R177 producer chain.

This tool never executes the protected target. With committed receipts only it
validates overwrite arithmetic and emits proof obligations. If an optional
complete offline event ledger is supplied, it can prove or reject the candidate
chain pc2150 -> pc3504 -> pc3363 -> pc3784.

Ledger schema:
{
  "schema": "luraph-deobf.r177-write-ledger.v1",
  "boundary_pc": 3784,
  "complete_for_registers": [117,155,177],
  "events": [
    {"seq": 1, "pc": 2150, "kind": "opcode7-return-bank",
     "register_start": 61, "register_end": 284},
    {"seq": 2, "pc": 3504, "kind": "opcode7-return-bank",
     "register_start": 117, "register_end": 206},
    {"seq": 3, "pc": 3363, "kind": "opcode7-return-bank",
     "register_start": 155, "register_end": 202},
    {"seq": 4, "pc": 3784, "kind": "boundary"}
  ]
}

Any other event that writes one of the tracked registers must also be present.
Completeness is an explicit assertion by the offline extractor that produced
the ledger; this checker does not infer completeness from absence.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRODUCER_RECEIPT = ROOT / "receipts" / "luraph_VM68_r177_producer_bank_overwrite.json"
SELECTOR29_RECEIPT = ROOT / "receipts" / "luraph_VM68_mode233_selector29.json"

TRACKED = (117, 155, 177)
EXPECTED_PCS = (2150, 3504, 3363)
BOUNDARY_PC = 3784


def covers(event: dict, reg: int) -> bool:
    if "register" in event:
        return int(event["register"]) == reg
    if "register_start" in event and "register_end" in event:
        return int(event["register_start"]) <= reg <= int(event["register_end"])
    regs = event.get("registers")
    if isinstance(regs, list):
        return reg in [int(x) for x in regs]
    return False


def fail(msg: str) -> None:
    raise ValueError(msg)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--producer-receipt", type=Path, default=PRODUCER_RECEIPT)
    ap.add_argument("--selector29-receipt", type=Path, default=SELECTOR29_RECEIPT)
    ap.add_argument("--ledger", type=Path, help="Optional complete offline write ledger")
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    checks: list[dict] = []
    def check(name: str, ok: bool, detail=None) -> None:
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    result: dict = {
        "schema": "luraph-deobf.r177-write-order-audit.v1",
        "scope": "offline receipt/ledger consistency; no target execution",
        "tracked_registers": list(TRACKED),
        "candidate_chain": list(EXPECTED_PCS) + [BOUNDARY_PC],
        "last_writer": "UNKNOWN",
        "callee_provenance": {"R117_at_pc3504": "UNKNOWN", "R155_at_pc3363": "UNKNOWN"},
        "proof_status": "UNKNOWN",
    }

    try:
        prod = json.loads(args.producer_receipt.read_text(encoding="utf-8"))
        s29 = json.loads(args.selector29_receipt.read_text(encoding="utf-8"))
        producers = prod["producers"]
        check("three producer banks present", len(producers) == 3)
        check("producer PCs exact",
              tuple(int(x["pc"]) for x in producers) == EXPECTED_PCS,
              [x["pc"] for x in producers])

        for row in producers:
            start = int(row["function_register"])
            count = int(row["return_count"])
            end = start + count - 1
            ordinal = 177 - start + 1
            check(f"pc{row['pc']} destination interval",
                  row["return_destination"] == f"R{start}..R{end}",
                  row["return_destination"])
            check(f"pc{row['pc']} R177 ordinal",
                  start <= 177 <= end and int(row["r177_return_ordinal"]) == ordinal,
                  f"computed return #{ordinal}")
            check(f"pc{row['pc']} return #1 overwrites callee",
                  row["callee_register_after_call"] == f"R{start} = return #1")

        intervals = [(int(x["function_register"]),
                      int(x["function_register"]) + int(x["return_count"]) - 1)
                     for x in producers]
        nested = (intervals[0][0] < intervals[1][0] < intervals[2][0] <= 177
                  and 177 <= intervals[2][1] <= intervals[1][1] <= intervals[0][1])
        check("producer intervals are nested around R177", nested, intervals)

        sites = s29["register_factory_structure"]["static_multi_return_expand_sites"]
        check("selector29 receipt agrees with producer PCs",
              [int(x["pc"]) for x in sites] == list(EXPECTED_PCS))
        check("pc3784 remains R177 opcode21 boundary",
              int(s29["post_xor_block"]["pc3784"]["opcode"]) == 21
              and int(s29["post_xor_block"]["pc3784"]["tuple"]["s"]) == 177)

        if args.ledger:
            ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
            if ledger.get("schema") != "luraph-deobf.r177-write-ledger.v1":
                fail(f"unexpected ledger schema: {ledger.get('schema')!r}")
            if int(ledger.get("boundary_pc", -1)) != BOUNDARY_PC:
                fail("ledger boundary_pc must be 3784")
            complete = sorted(int(x) for x in ledger.get("complete_for_registers", []))
            check("ledger explicitly complete for R117/R155/R177",
                  complete == list(TRACKED), complete)

            events = ledger.get("events")
            if not isinstance(events, list) or not events:
                fail("ledger events must be a non-empty list")
            seqs = [int(x["seq"]) for x in events]
            check("ledger sequence strictly increasing and unique",
                  seqs == sorted(seqs) and len(seqs) == len(set(seqs)), seqs)

            by_pc = {}
            for e in events:
                by_pc.setdefault(int(e["pc"]), []).append(e)
            for pc in EXPECTED_PCS:
                check(f"ledger contains pc{pc}", pc in by_pc)
            check("ledger contains boundary pc3784", BOUNDARY_PC in by_pc)

            boundary_seq = min(int(e["seq"]) for e in by_pc[BOUNDARY_PC])
            before_boundary = [e for e in events if int(e["seq"]) < boundary_seq]

            def last_writer(reg: int, before_seq: int) -> dict | None:
                hits = [e for e in events if int(e["seq"]) < before_seq and covers(e, reg)]
                return max(hits, key=lambda e: int(e["seq"])) if hits else None

            pc3504_seq = min(int(e["seq"]) for e in by_pc[3504])
            pc3363_seq = min(int(e["seq"]) for e in by_pc[3363])

            w117 = last_writer(117, pc3504_seq)
            w155 = last_writer(155, pc3363_seq)
            w177 = last_writer(177, boundary_seq)

            result["callee_provenance"]["R117_at_pc3504"] = (
                f"pc{w117['pc']}" if w117 else "NO_PRIOR_WRITE")
            result["callee_provenance"]["R155_at_pc3363"] = (
                f"pc{w155['pc']}" if w155 else "NO_PRIOR_WRITE")
            result["last_writer"] = f"pc{w177['pc']}" if w177 else "NO_PRIOR_WRITE"

            check("R117 last writer before pc3504 is pc2150",
                  w117 is not None and int(w117["pc"]) == 2150,
                  w117)
            check("R155 last writer before pc3363 is pc3504",
                  w155 is not None and int(w155["pc"]) == 3504,
                  w155)
            check("R177 last writer before pc3784 is pc3363",
                  w177 is not None and int(w177["pc"]) == 3363,
                  w177)

            # Make intervening writes visible even when the three key checks pass/fail.
            result["writes_before_boundary"] = {
                f"R{reg}": [
                    {"seq": int(e["seq"]), "pc": int(e["pc"]), "kind": e.get("kind")}
                    for e in before_boundary if covers(e, reg)
                ]
                for reg in TRACKED
            }

            if complete == list(TRACKED) and all(
                x["status"] == "PASS" for x in checks[-3:]):
                result["proof_status"] = "PROVEN_FROM_COMPLETE_LEDGER"
            else:
                result["proof_status"] = "NOT_PROVEN"
        else:
            result["proof_obligations"] = [
                "produce a complete offline write ledger for R117, R155, R177 through pc3784",
                "prove last write to R117 before pc3504",
                "prove last write to R155 before pc3363",
                "prove last write to R177 before pc3784",
                "include direct writes and non-opcode7 multi-register writes, not just the three known banks",
            ]

    except (OSError, KeyError, TypeError, ValueError, IndexError) as exc:
        check("required evidence is available and well-formed", False, str(exc))
        result["proof_status"] = "ERROR"

    result["checks"] = checks
    result["pass"] = sum(x["status"] == "PASS" for x in checks)
    result["fail"] = sum(x["status"] == "FAIL" for x in checks)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8")

    print(f"R177 write-order audit: {result['pass']} PASS, {result['fail']} FAIL")
    print("proof:", result["proof_status"])
    print("last writer:", result["last_writer"])
    print("callee provenance:", result["callee_provenance"])
    print("No target execution performed")
    return 1 if result["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
