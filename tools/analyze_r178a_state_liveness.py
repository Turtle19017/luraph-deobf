#!/usr/bin/env python3
"""Fail-closed R178A write->read liveness census over an ordered offline ledger."""
from __future__ import annotations
import argparse, hashlib, json, sys
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path

SCHEMA = "luraph-deobf.r178a-state-event-ledger.v1"
OUT_SCHEMA = "luraph-deobf.r178a-state-liveness.v1"
WRITE_KINDS = {"write", "direct-write", "opcode7-return-bank"}
READ_KINDS = {"read", "host-effect-read"}
BOUNDARY_KINDS = {"boundary"}


def fail(msg): raise ValueError(msg)
def sha256(data): return hashlib.sha256(data).hexdigest()

def canonical_location(v):
    if isinstance(v, str):
        v = v.strip()
        if not v: fail("empty location string")
        return v
    if isinstance(v, int) and not isinstance(v, bool): return f"BR:{v}"
    if isinstance(v, dict):
        if "space" in v and "key" in v: return f"{v['space']}:{v['key']}"
        if "register" in v: return f"BR:{int(v['register'])}"
    fail(f"unsupported location: {v!r}")

def location_space(loc): return loc.split(":", 1)[0] if ":" in loc else loc

def exact_locations(e):
    out = []
    if e.get("location") is not None: out.append(canonical_location(e["location"]))
    if e.get("locations") is not None:
        if not isinstance(e["locations"], list): fail("event.locations must be a list")
        out += [canonical_location(x) for x in e["locations"]]
    if e.get("register") is not None: out.append(f"BR:{int(e['register'])}")
    if e.get("registers") is not None:
        if not isinstance(e["registers"], list): fail("event.registers must be a list")
        out += [f"BR:{int(x)}" for x in e["registers"]]
    if "register_start" in e or "register_end" in e:
        if "register_start" not in e or "register_end" not in e: fail("register_start/register_end must appear together")
        lo, hi = int(e["register_start"]), int(e["register_end"])
        if hi < lo or hi - lo > 100000: fail(f"invalid register range {lo}..{hi}")
        out += [f"BR:{r}" for r in range(lo, hi + 1)]
    return list(dict.fromkeys(out))

def is_may_alias(e):
    return bool(e.get("may_alias")) or str(e.get("alias", "")).upper() in {"MAY", "UNKNOWN", "DYNAMIC"}

def alias_spaces(e):
    out = set()
    if isinstance(e.get("alias_space"), str) and e["alias_space"]: out.add(e["alias_space"])
    if isinstance(e.get("alias_spaces"), list): out |= {str(x) for x in e["alias_spaces"] if str(x)}
    for loc in exact_locations(e):
        if loc.endswith(":*"): out.add(location_space(loc))
    return out

def alias_may_touch(e, loc):
    if not is_may_alias(e): return False
    spaces = alias_spaces(e)
    return not spaces or "*" in spaces or location_space(loc) in spaces

def complete_set(doc, key):
    v = doc.get(key, []) or []
    if not isinstance(v, list): fail(f"{key} must be a list")
    return {canonical_location(x) for x in v}

def loc_complete(loc, s): return loc in s or f"{location_space(loc)}:*" in s or "*" in s

def normalize_doc(doc):
    if doc.get("schema") != SCHEMA: fail(f"unexpected ledger schema: {doc.get('schema')!r}")
    events = doc.get("events")
    if not isinstance(events, list): fail("ledger.events must be a list")
    both = complete_set(doc, "complete_for_locations")
    rc = both | complete_set(doc, "read_complete_for_locations")
    wc = both | complete_set(doc, "write_complete_for_locations")
    out, last = [], {}
    for i, raw in enumerate(events):
        if not isinstance(raw, dict): fail(f"events[{i}] must be an object")
        e = deepcopy(raw); path = str(e.get("path", e.get("path_id", "default")))
        if "seq" not in e: fail(f"events[{i}] missing seq")
        seq = int(e["seq"])
        if path in last and seq <= last[path]: fail(f"non-increasing seq in path {path}: {seq} <= {last[path]}")
        last[path] = seq
        kind = str(e.get("kind", ""))
        if kind not in WRITE_KINDS | READ_KINDS | BOUNDARY_KINDS: fail(f"events[{i}] unsupported kind {kind!r}")
        locs, may = exact_locations(e), is_may_alias(e)
        if kind in WRITE_KINDS | READ_KINDS and not locs and not may: fail(f"events[{i}] {kind} has neither exact location nor MAY alias")
        out.append({"raw": e, "index": i, "path": path, "seq": seq, "kind": kind, "locations": locs, "may_alias": may})
    by = defaultdict(list)
    for e in out: by[e["path"]].append(e)
    return {"by_path": by, "read_complete": rc, "write_complete": wc, "control_order_complete": bool(doc.get("control_order_complete"))}

def source_point(e):
    r = {"seq": e["seq"], "path": e["path"]}
    for k in ("pc", "function", "walk", "opcode", "kind"):
        if k in e["raw"]: r[k] = e["raw"][k]
    return r

def complete_for(loc, n):
    return n["control_order_complete"] and loc_complete(loc, n["read_complete"]) and loc_complete(loc, n["write_complete"])

def classify(path_events, pos, loc, n):
    e, raw = path_events[pos], path_events[pos]["raw"]
    row = {"source_event_index": e["index"], "path": e["path"], "seq": e["seq"], "pc": raw.get("pc"),
           "function": raw.get("function"), "walk": raw.get("walk"), "location": loc, "source_kind": e["kind"],
           "classification": "UNKNOWN", "classification_reason": None, "consumer": None, "shadowing_write": None,
           "boundary": None, "host_effect_relevant": bool(raw.get("host_effect_relevant")),
           "packed_provenance": deepcopy(raw.get("packed_provenance")) if "packed_provenance" in raw else None,
           "packed_provenance_preserved": "packed_provenance" in raw, "complete_for_location": complete_for(loc, n),
           "classification_scope": "per_ordered_path"}
    if e["may_alias"]: row["classification_reason"] = "source write itself is MAY/dynamic alias"; return row
    if row["host_effect_relevant"]: row["classification_reason"] = "source write explicitly marked host-effect relevant"; return row
    for x in path_events[pos + 1:]:
        if x["kind"] in BOUNDARY_KINDS:
            row["boundary"] = source_point(x)
            if complete_for(loc, n): row["classification"], row["classification_reason"] = "DEAD", "complete ordered path reached explicit boundary without consumer or clobber"
            else: row["classification_reason"] = "boundary reached but read/write/control completeness is insufficient"
            return row
        if x["kind"] in READ_KINDS:
            if loc in x["locations"] and not x["may_alias"]:
                row["classification"], row["consumer"] = "LIVE", source_point(x)
                row["host_effect_relevant"] = x["kind"] == "host-effect-read" or bool(x["raw"].get("host_effect"))
                row["classification_reason"] = "definite consumer observed before clobber"; return row
            if alias_may_touch(x["raw"], loc): row["classification_reason"] = "MAY/dynamic read could consume this location"; return row
        elif x["kind"] in WRITE_KINDS:
            if alias_may_touch(x["raw"], loc): row["classification_reason"] = "MAY/dynamic write could alias this location"; return row
            if loc in x["locations"]:
                row["shadowing_write"] = source_point(x)
                if complete_for(loc, n): row["classification"], row["classification_reason"] = "SHADOWED", "complete ordered path has definite overwrite before any consumer"
                else: row["classification_reason"] = "definite overwrite observed but read/write/control completeness is insufficient"
                return row
    row["classification_reason"] = "path ended without explicit boundary or proof-complete consumer/clobber result"
    return row

def analyze(doc, ledger_sha256=None):
    n, writes, src = normalize_doc(doc), [], 0
    for path, evs in n["by_path"].items():
        for pos, e in enumerate(evs):
            if e["kind"] not in WRITE_KINDS: continue
            src += 1
            if e["may_alias"] and not e["locations"]:
                raw = e["raw"]
                writes.append({"source_event_index": e["index"], "path": path, "seq": e["seq"], "pc": raw.get("pc"),
                    "function": raw.get("function"), "walk": raw.get("walk"), "location": None, "source_kind": e["kind"],
                    "classification": "UNKNOWN", "classification_reason": "dynamic write has no exact location", "consumer": None,
                    "shadowing_write": None, "boundary": None, "host_effect_relevant": bool(raw.get("host_effect_relevant")),
                    "packed_provenance": deepcopy(raw.get("packed_provenance")) if "packed_provenance" in raw else None,
                    "packed_provenance_preserved": "packed_provenance" in raw, "complete_for_location": False,
                    "classification_scope": "per_ordered_path"})
                continue
            writes += [classify(evs, pos, loc, n) for loc in e["locations"]]
    counts = Counter(r["classification"] for r in writes)
    return {"schema": OUT_SCHEMA, "source_schema": doc.get("schema"), "source_commit": doc.get("source_commit"),
        "ledger_sha256": ledger_sha256, "scope": "ordered offline event-ledger census only; classifications are per path; no evaluator mutation and no protected-target execution",
        "control_order_complete": n["control_order_complete"], "read_complete_for_locations": sorted(n["read_complete"]),
        "write_complete_for_locations": sorted(n["write_complete"]), "summary": {"source_write_events": src,
        "write_instances": len(writes), "live": counts.get("LIVE", 0), "shadowed": counts.get("SHADOWED", 0),
        "dead": counts.get("DEAD", 0), "unknown": counts.get("UNKNOWN", 0),
        "with_packed_provenance": sum(r["packed_provenance_preserved"] for r in writes),
        "host_effect_relevant": sum(r["host_effect_relevant"] for r in writes)}, "writes": writes,
        "global_dead_store_claims": False, "proof_status": "PER_PATH_CENSUS_ONLY", "no_target_execution": True}

def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("ledger", type=Path); ap.add_argument("--json-out", type=Path); ap.add_argument("--expect-source-commit"); a = ap.parse_args()
    try:
        raw = a.ledger.read_bytes(); doc = json.loads(raw.decode("utf-8"))
        if a.expect_source_commit is not None and not str(doc.get("source_commit", "")).startswith(a.expect_source_commit): fail("source commit mismatch")
        out = analyze(doc, sha256(raw))
        if a.json_out: a.json_out.parent.mkdir(parents=True, exist_ok=True); a.json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
        s = out["summary"]; print(f"R178A state liveness: writes={s['write_instances']} LIVE={s['live']} SHADOWED={s['shadowed']} DEAD={s['dead']} UNKNOWN={s['unknown']}")
        print(f"packed provenance preserved on {s['with_packed_provenance']} write instances"); print("proof: PER_PATH_CENSUS_ONLY"); print("No target execution performed"); return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, KeyError) as e: raise SystemExit(f"FAIL: {e}") from e

if __name__ == "__main__": sys.exit(main())
