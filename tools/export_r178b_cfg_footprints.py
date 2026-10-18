#!/usr/bin/env python3
"""R178B: export per-node/micro-path register footprints plus the proved CFG.

The exporter does not alter devirt.py.  It walks an already captured offline
snapshot through Program.lift_raw(), then inspects the resulting IR and CFG.
Traversal order is never treated as execution order; only Node outcomes and
Program.edges define control-flow edges.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "core"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

import luasym as S
from luasym import Expr, Reg, RegFile, Multi, SymList
from ir import Assign, CallStmt, SetList, ForPrep, Close, Node, Next, Ret, Crash

SCHEMA = "luraph-deobf.r178b-cfg-footprints.v1"


def _stable(value: Any, depth: int = 0):
    """JSON-safe structural form for state keys without assuming their schema."""
    if depth > 8:
        return {"type": type(value).__name__, "cut": True}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, (tuple, list)):
        return [_stable(x, depth + 1) for x in value]
    if isinstance(value, dict):
        return {str(k): _stable(v, depth + 1) for k, v in sorted(value.items(), key=lambda kv: repr(kv[0]))}
    return {"type": type(value).__name__, "repr": repr(value)[:1000]}


def key_summary(key: Any) -> dict:
    out = {"repr": repr(key)[:4000], "stable": _stable(key)}
    if isinstance(key, tuple):
        if len(key) > 0: out["mode"] = key[0]
        if len(key) > 1: out["pc"] = key[1]
        if len(key) > 2: out["stack_depth"] = key[2]
    return out


def _walk_value(value: Any, seen: set[int] | None = None):
    """Yield symbolic values reachable from an IR value without descending LTable state."""
    if seen is None:
        seen = set()
    if value is None or isinstance(value, (bool, int, float, bytes, str)):
        return
    oid = id(value)
    if oid in seen:
        return
    seen.add(oid)
    yield value
    if isinstance(value, Expr):
        for child in value.__dict__.values():
            yield from _walk_value(child, seen)
    elif isinstance(value, Multi):
        yield from _walk_value(value.items, seen)
        yield from _walk_value(value.tail, seen)
    elif isinstance(value, SymList):
        yield from _walk_value(value.items, seen)
        yield from _walk_value(value.tail, seen)
        yield from _walk_value(value.extra, seen)
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            yield from _walk_value(child, seen)
    elif isinstance(value, dict):
        for k, child in value.items():
            yield from _walk_value(k, seen)
            yield from _walk_value(child, seen)


def value_access(value: Any) -> dict:
    regs = set()
    wild_read = False
    reasons = []
    for item in _walk_value(value):
        if isinstance(item, Reg):
            regs.add(int(item.n))
        elif type(item).__name__ == "FrameArg":
            if isinstance(getattr(item, "reg", None), int):
                regs.add(int(item.reg))
            wild_read = True
            reasons.append("FrameArg")
        elif isinstance(item, RegFile):
            wild_read = True
            reasons.append("RegFile")
    return {
        "register_reads": sorted(regs),
        "may_read_all_registers": wild_read,
        "wild_read_reasons": sorted(set(reasons)),
    }


def _append_reads(events: list[dict], value: Any, role: str):
    acc = value_access(value)
    for reg in acc["register_reads"]:
        events.append({"kind": "read", "register": reg, "role": role})
    if acc["may_read_all_registers"]:
        events.append({"kind": "may-read-all", "role": role,
                       "reasons": acc["wild_read_reasons"]})


def stmt_events(st: Any, captured_regs=()) -> list[dict]:
    events: list[dict] = []
    if isinstance(st, Assign):
        if not isinstance(st.target, Reg):
            _append_reads(events, st.target, "assign-target-address")
        _append_reads(events, st.value, "assign-rhs")
        if isinstance(st.target, Reg):
            events.append({"kind": "write", "register": int(st.target.n), "role": "assign-target"})
        else:
            events.append({"kind": "side-effect-gap", "effect": "indirect-assign",
                           "target_type": type(st.target).__name__})
        return events

    if isinstance(st, CallStmt):
        _append_reads(events, st.fn, "call-function")
        _append_reads(events, st.args, "call-arguments")
        frame_eval = getattr(st, "frame_eval", None)
        if isinstance(frame_eval, dict):
            for reg in sorted(int(r) for r in frame_eval):
                events.append({"kind": "write", "register": reg, "role": "proved-frame-call-write"})
        has_frame = value_access(st.args)["may_read_all_registers"]
        events.append({
            "kind": "call-barrier",
            "may_read_all_registers": bool(has_frame),
            "may_write_all_registers": bool(has_frame and not isinstance(frame_eval, dict)),
            "frame_eval_exact_writes": sorted(int(r) for r in frame_eval) if isinstance(frame_eval, dict) else None,
            "may_write_registers": sorted(int(r) for r in captured_regs),
        })
        return events

    if isinstance(st, SetList):
        _append_reads(events, st.tbl, "setlist-table")
        _append_reads(events, st.values, "setlist-values")
        events.append({"kind": "side-effect-gap", "effect": "setlist"})
        return events

    if isinstance(st, ForPrep):
        _append_reads(events, st.exprs, "forprep")
        return events

    if isinstance(st, Close):
        if isinstance(st.reg, int):
            events.append({"kind": "read", "register": int(st.reg), "role": "close-boundary"})
        else:
            _append_reads(events, st.reg, "close-boundary")
        events.append({"kind": "side-effect-gap", "effect": "close-upvalues"})
        return events

    events.append({"kind": "unknown-ir-statement", "statement_type": type(st).__name__})
    return events


def _outcome(node: Node, link: Any) -> dict:
    oc = node.outcome
    if isinstance(oc, Next):
        return {"kind": "next", "successor": key_summary(oc.state.key(link))}
    if isinstance(oc, Ret):
        return {"kind": "return"}
    if isinstance(oc, Crash):
        return {"kind": "crash"}
    if oc is None:
        return {"kind": "none"}
    return {"kind": "unknown", "type": type(oc).__name__}


def flatten_node(node: Node, link: Any, prefix_events=None, branch_trace=None, captured_regs=()) -> list[dict]:
    """One record per branch leaf, preserving intra-node event order."""
    events = list(prefix_events or [])
    trace = list(branch_trace or [])
    for st in node.stmts:
        events.extend(stmt_events(st, captured_regs))

    if node.cond is not None:
        _append_reads(events, node.cond, "branch-condition")
        out = []
        if node.then is not None:
            out.extend(flatten_node(node.then, link, events, trace + [True], captured_regs))
        else:
            out.append({"events": events, "branch_trace": trace + [True], "outcome": {"kind": "missing-then"}})
        if node.els is not None:
            out.extend(flatten_node(node.els, link, events, trace + [False], captured_regs))
        else:
            out.append({"events": events, "branch_trace": trace + [False], "outcome": {"kind": "missing-else"}})
        return out

    if isinstance(node.outcome, Ret):
        _append_reads(events, node.outcome.values, "return-values")
    elif isinstance(node.outcome, Next):
        _append_reads(events, node.outcome.state.mode, "next-mode")
        _append_reads(events, node.outcome.state.pc, "next-pc")

    return [{"events": events, "branch_trace": trace, "outcome": _outcome(node, link)}]


def _event_summary(events: list[dict]) -> dict:
    reads = sorted({e["register"] for e in events if e["kind"] == "read"})
    writes = sorted({e["register"] for e in events if e["kind"] == "write"})
    return {
        "reads": reads,
        "writes": writes,
        "may_read_all_registers": any(e["kind"] == "may-read-all" or
                                        (e["kind"] == "call-barrier" and e.get("may_read_all_registers"))
                                   for e in events),
        "may_write_all_registers": any(e["kind"] == "call-barrier" and e.get("may_write_all_registers")
                                     for e in events),
        "may_write_registers": sorted({
            int(r) for e in events if e["kind"] == "call-barrier"
            for r in (e.get("may_write_registers") or [])
        }),
        "side_effect_gaps": sum(e["kind"] in {"side-effect-gap", "unknown-ir-statement"} for e in events),
        "call_barriers": sum(e["kind"] == "call-barrier" for e in events),
    }


def build_export(order, edges, transport_edges, link, metrics=None, *, proto_key=None,
                 source_commit=None, entry_key=None, captured_regs=()) -> dict:
    nodes = []
    actual_keys = {k for k, _ in order}
    edge_mismatches = []
    counts = Counter()

    for key, node in order:
        paths = flatten_node(node, link, captured_regs=captured_regs)
        cfg_succ = set(edges.get(key, set()))
        leaf_succ = set()
        for idx, path in enumerate(paths):
            path["path_index"] = idx
            path["summary"] = _event_summary(path["events"])
            counts.update({"micro_paths": 1,
                           "reads": len(path["summary"]["reads"]),
                            "writes": len(path["summary"]["writes"])})
            if path["outcome"]["kind"] == "next":
                leaf_succ.add(path["outcome"]["successor"]["repr"])
        cfg_repr = {repr(x)[:4000] for x in cfg_succ}
        if leaf_succ != cfg_repr:
            edge_mismatches.append({"source": key_summary(key),
                                    "leaf_successors": sorted(leaf_succ),
                                    "cfg_successors": sorted(cfg_repr)})
        nodes.append({"key": key_summary(key), "opcode": getattr(node, "op", None),
                      "error": getattr(node, "error", None),
                      "cfg_successors": [key_summary(x) for x in sorted(cfg_succ, key=repr)],
                      "micro_paths": path})

    tedges = []
    for (src, dst), skipped in sorted(transport_edges.items(), key=lambda kv: repr(kv[0])):
        tedges.append({"source": key_summary(src), "target": key_summary(dst),
                        "skipped": [key_summary(x) for x in skipped],
                        "invariant": "transported nodes have no stmts/cond/error/transport_effects"})

    metrics = dict(metrics or {})
    graph_complete = bool(not metrics.get("restart", False) and metrics.get("reason") == "complete")
    missing_edge_targets = sorted({repr(dst) for succ in edges.values() for dst in succ if dst not in actual_keys})
    return {
        "schema": SCHEMA,
        "source_commit": source_commit,
        "proto_key": proto_key,
        "entry_key": key_summary(entry_key) if entry_key is not None else None,
        "walk_metrics": metrics,
        "graph_complete": graph_complete,
        "node_count": len(order),
        "edge_count": sum(len(v) for v in edges.values()),
        "transport_edge_count": len(transport_edges),
        "captured_registers": sorted(int(r) for r in captured_regs),
        "event_counts": dict(sorted(counts.items())),
        "edge_mismatches": edge_mismatches,
        "missing_edge_targets": missing_edge_targets,
        "nodes": nodes,
        "transport_edges": tedges,
        "r178a_ledger_ready": False,
        "r178a_ledger_blocker": "CFG paths/cycles are not yet summarized into proof-complete ordered paths",
        "proof_status": "CFG_FOOTPRINTS_ONLY",
        "traversal_order_is_execution_order": False,
        "no_core_evaluator_changes_required": True,
        "no_protected_target_execution": True,
    }


def export_proto(source: Path, protos: Path, proto_key: str, chunks, limit: int,
                 source_commit: str | None) -> dict:
    from obfuscators.luraph_v15 import devirt as d
    prog = d.Program(str(source), str(protos), [str(x) for x in chunks])
    s0, order, _lf = prog.lift_raw(proto_key, limit=limit)
    cap = prog.dump.protos[proto_key]
    vm = prog.vm_of(cap)
    return build_export(order, prog.edges, prog.transport_edges, vm.kstack_link,
                        getattr(prog, "walk_metrics", {}), proto_key=proto_key,
                        source_commit=source_commit, entry_key=s0.key(vm.kstack_link),
                        captured_regs=getattr(_lf, "captured_regs", set()))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=Path)
    ap.add_argument("protos", type=Path)
    ap.add_argument("proto")
    ap.add_argument("--chunk", action="append", type=Path, default=[])
    ap.add_argument("--limit", type=int, default=200000)
    ap.add_argument("--source-commit")
    ap.add_argument("--json-out", type=Path, required=True)
    args = ap.parse_args()
    try:
        out = export_proto(args.source, args.protos, args.proto, args.chunk, args.limit,
                           args.source_commit)
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"R178B CFG footprints: nodes={out['node_count']} edges={out['edge_count']} micro_paths={out['event_counts'].get('micro_paths', 0)}")
        print(f"graph_complete={out['graph_complete']} edge_mismatches={len(out['edge_mismatches'])} missing_targets={len(out['missing_edge_targets'])}")
        print("proof: CFG_FOOTPRINTS_ONLVHŠBˆš[
“›È›İXİY\™Ù]^Xİ][Ûˆ\™›Ü›YYŠBˆ™]\›ˆˆ^Ù\
ÔÑ\œ›Ü‹˜[YQ\œ›Ü‹Ù^Q\œ›Ü‹\Q\œ›Ü‹[\Ü\œ›ÜŠH\È^Î‚ˆ˜Z\ÙHŞ\İ[Q^]
ˆ‘RSˆÙ^ßHŠHœ›ÛH^Â‚‚šYˆ×Û˜[YW×ÈOH—×ÛXZ[—×È‚ˆ˜Z\ÙHŞ\İ[Q^]
XZ[Š
JB