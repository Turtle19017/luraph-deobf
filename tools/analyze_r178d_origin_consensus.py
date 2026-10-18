#!/usr/bin/env python3
"""R178D: group path-conditioned R178C write fates by stable R178B origin ID."""
from __future__ import annotations
import argparse, json
from collections import Counter, defaultdict
from pathlib import Path

IN_SCHEMA = "luraph-deobf.r178c-write-fates.v1"
OUT_SCHEMA = "luraph-deobf.r178d-origin-consensus.v1"
NEGATIVE = {"MUST_SHADOWED", "MUST_DEAD"}


def classify(rows):
    classes = {r.get("classification") for r in rows}
    if rows and classes <= NEGATIVE and all(r.get("safe_negative_claim") for r in rows):
        return "PROVEN_UNCONSUMED", True
    if classes == {"MUST_LIVE"}:
        return "PROVEN_LIVE", False
    if "UNKNOWN" in classes or any(not r.get("origin_id") for r in rows):
        return "UNKNOWN", False
    return "PATH_DEPENDENT", False


def analyze(doc):
    if doc.get("schema") != IN_SCHEMA:
        raise ValueError(f"unexpected input schema: {doc.get('schema')!r}")
    groups, missing = defaultdict(list), []
    for i, row in enumerate(doc.get("write_instances", [])):
        origin = row.get("origin_id")
        reg = row.get("register")
        if not isinstance(origin, str) or not origin:
            missing.append(i); continue
        groups[(origin, int(reg))].append(row)
    out = []
    for (origin, reg), rows in sorted(groups.items()):
        consensus, prunable = classify(rows)
        out.append({
            "origin_id": origin,
            "statement_origin": rows[0].get("statement_origin"),
            "register": reg,
            "instance_count": len(rows),
            "classifications": sorted({r.get("classification") for r in rows}),
            "possible_fates": sorted({f for r in rows for f in r.get("possible_fates", [])}),
            "consensus": consensus,
            "prunable_origin": prunable,
            "instances": [{
                "node": r.get("node"), "path_index": r.get("path_index"),
                "branch_trace": r.get("branch_trace"), "event_index": r.get("event_index"),
                "classification": r.get("classification"), "possible_fates": r.get("possible_fates"),
            } for r in rows],
        })
    c = Counter(x["consensus"] for x in out)
    return {
        "schema": OUT_SCHEMA,
        "source_schema": IN_SCHEMA,
        "source_commit": doc.get("source_commit"),
        "proto_key": doc.get("proto_key"),
        "summary": {
            "origin_groups": len(out),
            "proven_unconsumed": c.get("PROVEN_UNCONSUMED", 0),
            "proven_live": c.get("PROVEN_LIVE", 0),
            "path_dependent": c.get("PATH_DEPENDENT", 0),
            "unknown": c.get("UNKNOWN", 0) + len(missing),
            "missing_origin_instances": len(missing),
        },
        "origins": out,
        "prunable_origins": [x["origin_id"] for x in out if x["prunable_origin"]],
        "missing_origin_instance_indices": missing,
        "pruning_applied": False,
        "proof_status": "ORIGIN_CONSENSUS_ONLY",
        "no_protected_target_execution": True,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("fates", type=Path); ap.add_argument("--json-out", type=Path, required=True)
    a = ap.parse_args()
    try:
        doc = json.loads(a.fates.read_text(encoding="utf-8")); out = analyze(doc)
        a.json_out.parent.mkdir(parents=True, exist_ok=True)
        a.json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
        s = out["summary"]
        print(f"R178D origin consensus: groups={s['origin_groups']} unconsumed={s['proven_unconsumed']} live={s['proven_live']} path_dependent={s['path_dependent']} unknown={s['unknown']}")
        print("pruning_applied=false"); print("proof: ORIGIN_CONSENSUS_ONLY"); return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc


if __name__ == "__main__": raise SystemExit(main())
