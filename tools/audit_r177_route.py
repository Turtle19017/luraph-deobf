#!/usr/bin/env python3
"""Offline-only R177 route audit against committed, source-derived receipts.

Checks *consistency of receipts*, not reachability in a fresh execution.
Does not load, build, modify, or run the protected Lua/Luau target.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    "sentinels": "receipts/luraph_VM68_sentinel_provenance.json",
    "child297": "receipts/luraph_A321_child297_coroutine_sentinels.json",
    "selector137": "receipts/luraph_VM68_mode233_selector56_137.json",
    "selector141": "receipts/luraph_VM68_mode233_selector141.json",
    "selector50": "receipts/luraph_VM68_mode233_selector50.json",
    "selector29": "receipts/luraph_VM68_mode233_selector29.json",
}
COMPARE = re.compile(r"(\d+)\s*<=\s*(\d+)\s*\)?\s*->\s*(true|false)")

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--capture", type=Path, help="Optional previous capture; read only")
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    checks: list[dict] = []
    def check(name: str, predicate: bool, detail: str = "") -> None:
        checks.append({"check": name, "status": "PASS" if predicate else "FAIL", "detail": detail})

    try:
        r = {key: json.loads((args.root / path).read_text(encoding="utf-8"))
             for key, path in FILES.items()}
        s, c = r["sentinels"], r["child297"]
        r137, r141, r50, r29 = (r["selector137"]["selector137"],
                                r["selector141"], r["selector50"], r["selector29"])
        a, b = (s["level3_constants"]["proto150"], s["level3_constants"]["proto208"])
        va, vb = a["value_i32"], b["value_i32"]

        check("proto150 little-endian i32",
              int.from_bytes(bytes.fromhex(a["decoded_hex"]), "little", signed=True) == va)
        check("proto208 little-endian i32",
              int.from_bytes(bytes.fromhex(b["decoded_hex"]), "little", signed=True) == vb)
        check("distinct sentinels", va == 1464316551 and vb == 1791364062 and va != vb)
        check("child297 captures R121/R86 by reference",
              [(x["kind"], x["parent_register"]) for x in c["construction"]["captures"]]
              == [(1, 121), (1, 86)])
        seq = c["callable_sequence"]
        check("child297 resume sequence",
              seq["resume_1"] == "R121" and seq["resume_2"] == "R86"
              and seq["resume_3"].startswith("no values"))
        check("selector137 sets R88=141",
              "R88 = 141" in r137["transition"]["effect"])
        check("selector141 two-iteration exit",
              r141["entry"]["value"] == 141
              and r141["frontier"]["iteration_count_before_exit"] == 2
              and r141["frontier"]["deterministic_exit_selector"] == 50)
        check("selector141 gate values",
              not (va != va) and (vb != va)
              and s["selector141_actual_path"]["post_not1"] is False
              and s["selector141_actual_path"]["post_not2"] is True)
        check("selector50 transitions to 29",
              r50["entry"]["value"] == 50
              and r50["transition"]["next_selector"] == 29
              and "R88 = 29" in r50["transition"]["effect"])
        check("selector50 child339 call is present",
              r50["child_call"]["bound_child_seed"] == 339
              and "call R1()" in r50["child_call"]["pc838"])
        check("selector29 child325 call precedes gate",
              r29["entry"]["value"] == 29
              and any("call R59(R47)" in x for x in r29["pre_call_gate"]))
        check("selector29 produces boolean R88",
              r29["pre_call_gate_resolution"]["R86"] == vb
              and r29["pre_call_gate_resolution"]["pc3240"] == "R88 = not false = true"
              and r29["frontier"]["selector_register_before_call"] is True)
        p = r29["post_xor_block"]["pc3784"]
        check("pc3784 opcode21 tuple",
              p["opcode"] == 21 and p["tuple"] == {"S": 21, "w": 156, "s": 177, "H": 50})
        check("pc3784 argument bank span",
              p["argument_bank"]["register_span"] == "R178..R332"
              and p["argument_bank"]["packed_tail_register"] == 333
              and p["argument_bank"]["appended_register_count"] == 155)
        banks = r29["register_factory_structure"]["static_multi_return_expand_sites"]
        check("R177 in all three return-bank ranges",
              len(banks) == 3 and {x["pc"] for x in banks} == {2150, 3504, 3363}
              and all(x["function_register"] <= 177
                      < x["function_register"] + x["return_count"] for x in banks))
        for name, lines, selector, minimum in (
            ("selector141 threshold comparisons", r141["decision_prefix"], 141, 7),
            ("selector50 threshold comparisons", r50["decision_path"], 50, 4),
            ("selector29 threshold comparisons", r29["decision_path"], 29, 7),
        ):
            matches = [COMPARE.search(line) for line in lines]
            matches = [m for m in matches if m]
            ok = len(matches) >= minimum and all(
                int(m.group(1)) == selector
                and (int(m.group(1)) <= int(m.group(2))) == (m.group(3) == "true")
                for m in matches)
            check(name, ok, f"verified={len(matches)}, minimum={minimum}")
    except (OSError, KeyError, ValueError, TypeError, IndexError) as exc:
        check("required evidence available and well-formed", False, str(exc))

    observations: dict = {
        "runner": "UNKNOWN", "r177_pre": "UNKNOWN",
        "r177_post": "UNKNOWN", "r177_done": "UNKNOWN",
    }
    if args.capture:
        try:
            payload = args.capture.read_text(encoding="utf-8", errors="replace")
            starts = [line for line in payload.splitlines() if line.strip()]
            observations = {
                "runner": any(line.startswith("[runner] === probe start ===") for line in starts),
                "r177_pre": any(line.startswith("[R177PRE]") for line in starts),
                "r177_post": any(line.startswith("[R177POST]") for line in starts),
                "r177_done": "__R177_DONE__" in payload,
            }
            check("capture marker order",
                  not observations["r177_post"] or observations["r177_pre"],
                  "POST requires PRE")
        except OSError as exc:
            check("capture can be read", False, str(exc))

    result = {
        "schema": "luraph-deobf.r177-offline-route-audit.v1",
        "scope": "receipt consistency, not runtime-path proof",
        "inputs": list(FILES.values()),
        "checks": checks,
        "pass": sum(x["status"] == "PASS" for x in checks),
        "fail": sum(x["status"] == "FAIL" for x in checks),
        "derived_conditional_route": "141 -> 50 -> 29 -> pc3784",
        "conditions": [
            "child331 resume/setup must complete on selector141",
            "selector50 pc838 child339 call must return normally",
            "selector29 pc3235 child325 call must return normally",
            "opcode21 argument preparation must complete before R177 call",
        ],
        "unresolved": [
            "actual VM selector reached during v2 run",
            "dynamic identity of R177 callable",
            "R88 after mega-call",
            "normal return/control transfer from R177",
        ],
        "observed_capture_markers": observations,
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8")
    print(f"R177 offline audit: {result['pass']} PASS, {result['fail']} FAIL")
    print("route (conditional):", result["derived_conditional_route"])
    print("capture markers:", observations)
    print("No target execution performed")
    return 1 if result["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
