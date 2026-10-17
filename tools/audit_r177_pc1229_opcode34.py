#!/usr/bin/env python3
"""Audit the apparent pc1229 R177 write against selector121 opcode34 semantics.

Offline receipt/census consistency only. No target execution.

The generic opcode34 footprint is path-insensitive and contains BR writes from
multiple internal branches. At pc1229 the concrete tuple is (34,177,0,254).
Selector121 independently records its first registration pair as proto254 with
string_repair_xor=177 ("getmetatable"). The established opcode34 lazy-repair
semantics use w as the payload XOR key and the proto/index field to choose the
lazy constant.

If all independent anchors agree, pc1229 is classified as a reachable lazy
string-repair site, NOT a direct BR[177] write merely because w==177.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PC = 1229
EXPECTED_TUPLE = {"S": 34, "w": 177, "s": 0, "H": 254}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("writer_census", type=Path)
    ap.add_argument(
        "--registration-receipt",
        type=Path,
        default=ROOT / "receipts" / "luraph_VM68_native_builtin_registration.json",
    )
    ap.add_argument(
        "--api-receipt",
        type=Path,
        default=ROOT / "receipts" / "luraph_VM68_mode233_api_bootstrap.json",
    )
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    census = json.loads(args.writer_census.read_text(encoding="utf-8"))
    reg = json.loads(args.registration_receipt.read_text(encoding="utf-8"))
    api = json.loads(args.api_receipt.read_text(encoding="utf-8"))

    checks = []
    def check(name, ok, detail=None):
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    hits = census.get("non_opcode7_operand_hits", [])
    rows = [x for x in hits if int(x.get("pc", -1)) == EXPECTED_PC]
    check("census has exactly one pc1229 hit", len(rows) == 1, len(rows))

    row = rows[0] if len(rows) == 1 else {}
    tup = {k: int(v) for k, v in row.get("tuple", {}).items()} if row else {}
    check("pc1229 tuple exact", tup == EXPECTED_TUPLE, tup)
    check("pc1229 census opcode is 34", int(row.get("opcode", -1)) == 34 if row else False)

    selector121 = reg.get("selector121", {})
    pairs = selector121.get("pairs", [])
    first = pairs[0] if pairs else {}
    check("selector121 first pair builtin is getmetatable",
          first.get("builtin") == "getmetatable", first.get("builtin"))
    check("selector121 first pair proto is 254",
          int(first.get("string_proto", -1)) == 254, first.get("string_proto"))
    check("selector121 first pair repair xor is 177",
          int(first.get("string_repair_xor", -1)) == 177,
          first.get("string_repair_xor"))

    helper = reg.get("helper", {}).get("constructed_at", {})
    check("selector121 helper construction precedes pc1229",
          int(helper.get("repair_pc", -1)) == 1226
          and int(helper.get("dispatch_pc", -1)) == 1227,
          helper)

    lazy = api.get("mode233_lazy_repair_hub", {})
    semantic = str(lazy.get("semantics", ""))
    check("opcode34 established semantics uses instruction w as XOR key",
          "XOR the payload bytes with w[pc]" in semantic, semantic)
    check("opcode34 established semantics rewrites VM slot",
          "rewrite the current VM slot" in semantic, semantic)

    fail = sum(x["status"] == "FAIL" for x in checks)
    classification = (
        "REACHABLE_SELECTOR121_LAZY_REPAIR_NOT_DIRECT_R177_WRITE"
        if fail == 0
        else "UNKNOWN"
    )

    result = {
        "schema": "luraph-deobf.r177-pc1229-op34-audit.v1",
        "pc": EXPECTED_PC,
        "tuple": tup,
        "classification": classification,
        "reason": (
            "w=177 matches selector121 first-pair string repair XOR key, while "
            "H=254 matches its string proto. Generic path-insensitive opcode34 "
            "BR[w] footprint must not be applied to this lazy-repair path."
        ) if fail == 0 else "one or more independent anchors failed",
        "r177_direct_write": False if fail == 0 else "UNKNOWN",
        "checks": checks,
        "pass": sum(x["status"] == "PASS" for x in checks),
        "fail": fail,
        "no_target_execution": True,
    }

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8")

    print(f"pc1229 opcode34 audit: {result['pass']} PASS, {result['fail']} FAIL")
    print("classification:", classification)
    print("R177 direct write:", result["r177_direct_write"])
    print("No target execution performed")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
