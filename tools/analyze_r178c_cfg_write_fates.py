#!/usr/bin/env python3
"""R178C: fail-closed write-fate dataflow over R178B CFG footprints."""
from __future__ import annotations
import argparse, json
from collections import Counter, defaultdict
from pathlib import Path

IN_SCHEMA = "luraph-deobf.r178b-cfg-footprints.v1"
OUT_SCHEMA = "luraph-deobf.r178c-write-fates.v1"
DECISIVE = {"READ", "CLOBBER", "DEAD"}


def nid(summary):
    value = summary.get("repr") if isinstance(summary, dict) else None
    if not isinstance(value, str) or not value:
        raise ValueError("node key summary missing repr")
    return value


def first_effect(events, register, start=0):
    """Return the first event that decides or blocks the current value."""
    for i in range(start, len(events)):
        e, kind = events[i], events[i].get("kind")
        if kind == "read" and int(e.get("register")) == register:
            return "READ", i, e
        if kind == "may-read-all":
            return "BARRIER", i, e
        if kind == "call-barrier":
            if e.get("may_read_all_registers") or e.get("may_write_all_registers"):
                return "BARRIER", i, e
            if register in [int(x) for x in e.get("may_write_registers") or []]:
                return "BARRIER", i, e
        if kind == "write" and int(e.get("register")) == register:
            return "CLOBBER", i, e
        if kind in {"side-effect-gap", "unknown-ir-statement"}:
            return "BARRIER", i, e
    return None


def tarjan(nodes, edges):
    index, indices, low, stack, onstack, out = 0, {}, {}, [], set(), []
    def visit(v):
        nonlocal index
        indices[v] = low[v] = index; index += 1
        stack.append(v); onstack.add(v)
        for w in edges.get(v, ()):
            if w not in nodes: continue
            if w not in indices:
                visit(w); low[v] = min(low[v], low[w])
            elif w in onstack:
                low[v] = min(low[v], indices[w])
        if low[v] == indices[v]:
            comp = []
            while True:
                w = stack.pop(); onstack.remove(w); comp.append(w)
                if w == v: break
            out.append(comp)
    for v in sorted(nodes):
        if v not in indices: visit(v)
    return out


def classify(fates):
    if fates == {"READ"}: return "MUST_LIVE"
    if fates == {"CLOBBER"}: return "MUST_SHADOWED"
    if fates == {"DEAD"}: return "MUST_DEAD"
    if fates and fates <= DECISIVE: return "PATH_DEPENDENT"
    return "UNKNOWN"


def continuation_model(doc, register):
    nodes = {nid(n["key"]): n for n in doc.get("nodes", [])}
    mismatch = {nid(x["source"]) for x in doc.get("edge_mismatches", [])
                if isinstance(x, dict) and isinstance(x.get("source"), dict)}
    local, cont, witnesses = defaultdict(set), defaultdict(set), defaultdict(dict)
    for node_id, node in nodes.items():
        paths = node.get("micro_paths")
        if not isinstance(paths, list) or not paths:
            local[node_id].add("INCOMPLETE"); continue
        for path in paths:
            effect = first_effect(path.get("events") or [], register)
            if effect:
                fate, i, event = effect; local[node_id].add(fate)
                witnesses[node_id].setdefault(fate, {"path_index": path.get("path_index"), "event_index": i, "event": event})
                continue
            outcome, kind = path.get("outcome") or {}, (path.get("outcome") or {}).get("kind")
            if kind in {"return", "crash"}:
                local[node_id].add("DEAD"); witnesses[node_id].setdefault("DEAD", {"path_index": path.get("path_index"), "outcome": kind})
            elif kind == "next":
                if node_id in mismatch:
                    local[node_id].add("INCONSISTENT_CFG"); continue
                try: succ = nid(outcome.get("successor"))
                except ValueError:
                    local[node_id].add("INCOMPLETE"); continue
                if succ not in nodes:
                    local[node_id].add("INCOMPLETE"); witnesses[node_id].setdefault("INCOMPLETE", {"missing_successor": succ})
                else: cont[node_id].add(succ)
            else:
                local[node_id].add("INCOMPLETE"); witnesses[node_id].setdefault("INCOMPLETE", {"outcome": kind})
    for comp in tarjan(set(nodes), cont):
        cyclic = len(comp) > 1 or (comp and comp[0] in cont.get(comp[0], set()))
        if cyclic:
            for node_id in comp:
                local[node_id].add("LOOP"); witnesses[node_id].setdefault("LOOP", {"cycle_node": node_id})
    fates = {k: set(local[k]) for k in nodes}
    changed = True
    while changed:
        changed = False
        for node_id in nodes:
            new = set(fates[node_id])
            for succ in cont.get(node_id, ()): new |= fates[succ]
            if new != fates[node_id]: fates[node_id], changed = new, True
    return nodes, fates, witnesses, mismatch


def analyze_register(doc, register):
    nodes, node_fates, witnesses, mismatch = continuation_model(doc, register)
    out = []
    for node_id, node in nodes.items():
        for path in node.get("micro_paths", []):
            events = path.get("events") or []
            for i, event in enumerate(events):
                if event.get("kind") != "write" or int(event.get("register")) != register: continue
                effect = first_effect(events, register, i + 1)
                if effect:
                    fate, j, witness = effect; fates = {fate}
                    continuation = {"kind": "same-micro-path", "event_index": j, "event": witness}
                else:
                    outcome, kind = path.get("outcome") or {}, (path.get("outcome") or {}).get("kind")
                    if kind in {"return", "crash"}:
                        fates, continuation = {"DEAD"}, {"kind": "terminal", "outcome": kind}
                    elif kind == "next":
                        try: succ = nid(outcome.get("successor"))
                        except ValueError:
                            fates, continuation = {"INCOMPLETE"}, {"kind": "missing-successor-summary"}
                        else:
                            if node_id in mismatch:
                                fates, continuation = {"INCONSISTENT_CFG"}, {"kind": "edge-mismatch"}
                            elif succ not in node_fates:
                                fates, continuation = {"INCOMPLETE"}, {"kind": "missing-successor", "successor": succ}
                            else:
                                fates = set(node_fates[succ]); continuation = {"kind": "successor", "successor": succ,
                                    "successor_fates": sorted(fates), "successor_witnesses": witnesses.get(succ, {})}
                    else:
                        fates, continuation = {"INCOMPLETE"}, {"kind": "nonterminal-without-successor", "outcome": kind}
                cls = classify(fates)
                out.append({"node": node.get("key"), "opcode": node.get("opcode"), "path_index": path.get("path_index"),
                    "branch_trace": path.get("branch_trace"), "event_index": i, "register": register,
                    "origin_id": event.get("origin_id"), "statement_origin": event.get("statement_origin"),
                    "write_role": event.get("role"), "classification": cls, "possible_fates": sorted(fates),
                    "continuation": continuation, "safe_negative_claim": cls in {"MUST_SHADOWED", "MUST_DEAD"},
                    "path_conditioned": True})
    return out


def analyze(doc, tracked=None):
    if doc.get("schema") != IN_SCHEMA: raise ValueError(f"unexpected input schema: {doc.get('schema')!r}")
    regs = {int(x) for x in (tracked or [])}
    if not regs:
        regs = {int(e["register"]) for n in doc.get("nodes", []) for p in n.get("micro_paths", [])
                for e in p.get("events", []) if e.get("kind") == "write" and isinstance(e.get("register"), int)}
    rows = [row for reg in sorted(regs) for row in analyze_register(doc, reg)]
    c = Counter(r["classification"] for r in rows)
    return {"schema": OUT_SCHEMA, "source_schema": IN_SCHEMA, "source_commit": doc.get("source_commit"),
        "proto_key": doc.get("proto_key"), "graph_complete": bool(doc.get("graph_complete")), "tracked_registers": sorted(regs),
        "summary": {"write_instances": len(rows), "must_live": c.get("MUST_LIVE", 0), "must_shadowed": c.get("MUST_SHADOWED", 0),
            "must_dead": c.get("MUST_DEAD", 0), "path_dependent": c.get("PATH_DEPENDENT", 0), "unknown": c.get("UNKNOWN", 0),
            "safe_negative_claims": sum(r["safe_negative_claim"] for r in rows)},
        "write_instances": rows, "global_prune_ready": False,
        "global_prune_blocker": "write instances are path-conditioned; source-statement origin grouping is not yet proven across duplicated branch-prefix events",
        "proof_status": "PATH_CONDITIONED_WRITE_FATES", "no_protected_target_execution": True}


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("cfg", type=Path)
    ap.add_argument("--register", action="append", type=int, default=[]); ap.add_argument("--json-out", type=Path, required=True)
    a = ap.parse_args()
    try:
        doc = json.loads(a.cfg.read_text(encoding="utf-8")); out = analyze(doc, a.register or None)
        a.json_out.parent.mkdir(parents=True, exist_ok=True); a.json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
        s = out["summary"]; print(f"R178C write fates: writes={s['write_instances']} LIVE={s['must_live']} SHADOWED={s['must_shadowed']} DEAD={s['must_dead']} PATH_DEPENDENT={s['path_dependent']} UNKNOWN={s['unknown']}")
        print(f"safe_negative_claims={s['safe_negative_claims']}"); print("proof: PATH_CONDITIONED_WRITE_FATES"); print("No protected target execution performed"); return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc: raise SystemExit(f"FAIL: {exc}") from exc


if __name__ == "__main__": raise SystemExit(main())
