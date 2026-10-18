#!/usr/bin/env python3
"""R181G: bind RHS AstExprLocal dependencies to frozen local snapshots from R181F."""
from __future__ import annotations
import argparse, json
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "luraph-deobf.r181g-rhs-local-dependency-census.v1"
ID_KEYS = ("id", "local_id", "identifier_id", "symbol_id", "decl_id")

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def atom(v):
    if v is None or isinstance(v, bool):
        return None
    return str(v) if isinstance(v, (str, int)) else None

def node_type(node):
    if not isinstance(node, dict):
        return type(node).__name__
    for key in ("type", "kind", "tag", "op"):
        value = node.get(key)
        if isinstance(value, str):
            return value
    return "dict"

def local_identity(node):
    """Return explicit identity fields from an AstExprLocal-shaped node."""
    if not isinstance(node, dict):
        return {"names": [], "ids": []}
    names, ids = [], []
    local = node.get("local")
    if isinstance(local, dict):
        name = local.get("name")
        if isinstance(name, str):
            names.append({"path": "$.local.name", "value": name})
        for key in ID_KEYS:
            value = local.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                ids.append({"path": f"$.local.{key}", "value": value})
    name = node.get("name")
    if isinstance(name, str):
        names.append({"path": "$.name", "value": name})
    for key in ID_KEYS:
        value = node.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            ids.append({"path": f"$.{key}", "value": value})
    return {"names": names, "ids": ids}

def walk_local_nodes(node, path="$"):
    if isinstance(node, dict):
        if node_type(node) == "AstExprLocal":
            yield path, node
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                yield from walk_local_nodes(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from walk_local_nodes(value, f"{path}[{i}]")

def entry_ids(entry):
    out = []
    for item in entry.get("ids", []):
        if isinstance(item, dict):
            value = item.get("value")
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                out.append(value)
    return out

def bind_local(node, snapshots):
    identity = local_identity(node)
    hits = []
    for entry in snapshots:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        ids = entry_ids(entry)
        name_match = any(x["value"] == name for x in identity["names"]) if isinstance(name, str) else False
        id_match = any(x["value"] in ids for x in identity["ids"])
        if name_match or id_match:
            hits.append(entry)

    uniq = {}
    for entry in hits:
        key = (entry.get("path"), entry.get("name"), repr(entry.get("value")), entry.get("encoding"))
        uniq[key] = entry
    matches = list(uniq.values())

    if not identity["names"] and not identity["ids"]:
        status = "NO_EXPLICIT_IDENTITY"
    elif not matches:
        status = "NO_SNAPSHOT_MATCH"
    elif len(matches) == 1:
        status = "UNIQUE_SNAPSHOT_MATCH"
    else:
        names = {x.get("name") for x in matches}
        values = {repr(x.get("value")) for x in matches}
        status = "MULTI_MATCH_CONSISTENT" if len(names) == 1 and len(values) == 1 else "AMBIGUOUS_MATCH"
    return {"status": status, "identity": identity, "matches": matches}

def require_r181f(obj):
    if not isinstance(obj, dict) or obj.get("schema") != "luraph-deobf.r181f-local-identity-rhs-census.v1":
        raise ValueError("expected R181F local-identity/RHS census")
    cp = obj.get("checkpoint", {}).get("expected", {})
    if (cp.get("functions"), cp.get("errors"), cp.get("fallbacks"), cp.get("requests")) != (78, 64, 0, 594):
        raise ValueError("checkpoint != 78/64/0/594")
    if obj.get("cohort_sites") != 7:
        raise ValueError(f"expected 7 cohort sites, found {obj.get('cohort_sites')}")
    summary = obj.get("summary", {})
    if summary.get("sub_instances") != 136:
        raise ValueError(f"expected 136 Sub instances, found {summary.get('sub_instances')}")
    if summary.get("left_type_counts", {}).get("AstExprLocal") != 136:
        raise ValueError("expected 136 AstExprLocal left operands")
    right = summary.get("right_type_counts", {})
    if right.get("AstExprIndexExpr") != 95 or right.get("AstExprCall") != 41:
        raise ValueError(f"expected RHS 95 IndexExpr / 41 Call, found {right}")
    if summary.get("left_structured_match_other") != 136:
        raise ValueError("expected all 136 left bindings to be structured_match_other")
    instances = obj.get("instances", [])
    if len(instances) != 136:
        raise ValueError(f"expected 136 instance records, found {len(instances)}")
    return instances

def analyze(path):
    obj = load(path)
    instances = require_r181f(obj)

    rhs_type_counts = Counter()
    local_path_counts = Counter()
    local_status_counts = Counter()
    local_name_counts = Counter()
    snapshot_value_counts = Counter()
    index_expr_types = Counter()
    index_index_types = Counter()
    call_func_types = Counter()
    call_argc = Counter()
    call_has_args = Counter()
    rows = []

    for i, inst in enumerate(instances):
        right = inst.get("right_node")
        rt = node_type(right)
        rhs_type_counts[rt] += 1
        snapshots = inst.get("local_snapshot_entries", [])
        deps = []

        for path0, local_node in walk_local_nodes(right):
            binding = bind_local(local_node, snapshots)
            local_path_counts[path0] += 1
            local_status_counts[binding["status"]] += 1
            for item in binding["identity"]["names"]:
                local_name_counts[item["value"]] += 1
            for entry in binding["matches"]:
                snapshot_value_counts[repr(entry.get("value"))] += 1
            deps.append({
                "path": path0,
                "node": local_node,
                "node_type": node_type(local_node),
                "binding": binding,
            })

        rhs_schema = {}
        if rt == "AstExprIndexExpr":
            expr = right.get("expr") if isinstance(right, dict) else None
            index = right.get("index") if isinstance(right, dict) else None
            index_expr_types[node_type(expr)] += 1
            index_index_types[node_type(index)] += 1
            rhs_schema = {
                "expr_type": node_type(expr),
                "index_type": node_type(index),
                "expr": expr,
                "index": index,
            }
        elif rt == "AstExprCall":
            func = right.get("func") if isinstance(right, dict) else None
            argc = right.get("argc") if isinstance(right, dict) else None
            call_func_types[node_type(func)] += 1
            call_argc[repr(argc)] += 1
            call_has_args["present" if isinstance(right, dict) and "args" in right else "absent"] += 1
            rhs_schema = {
                "func_type": node_type(func),
                "func": func,
                "argc": argc,
                "args_present": isinstance(right, dict) and "args" in right,
                "args": right.get("args") if isinstance(right, dict) and "args" in right else None,
            }

        rows.append({
            "instance_index": i,
            "function_id": inst.get("function_id"),
            "state_id": inst.get("state_id"),
            "source": inst.get("source"),
            "line": inst.get("line"),
            "right_type": rt,
            "rhs_schema": rhs_schema,
            "rhs_local_dependencies": deps,
        })

    return {
        "schema": SCHEMA,
        "source_r181f": str(path),
        "checkpoint": obj["checkpoint"],
        "cohort_sites": obj["cohort_sites"],
        "summary": {
            "instances": len(instances),
            "rhs_type_counts": dict(rhs_type_counts.most_common()),
            "rhs_local_dependency_instances": sum(local_status_counts.values()),
            "rhs_unique_snapshot_matches": local_status_counts["UNIQUE_SNAPSHOT_MATCH"],
            "rhs_multi_match_consistent": local_status_counts["MULTI_MATCH_CONSISTENT"],
            "rhs_ambiguous_matches": local_status_counts["AMBIGUOUS_MATCH"],
            "rhs_no_snapshot_match": local_status_counts["NO_SNAPSHOT_MATCH"],
            "rhs_no_explicit_identity": local_status_counts["NO_EXPLICIT_IDENTITY"],
        },
        "rhs_local_paths": dict(local_path_counts.most_common()),
        "rhs_local_names": dict(local_name_counts.most_common()),
        "rhs_bound_snapshot_values": dict(snapshot_value_counts.most_common()),
        "index_expr_types": dict(index_expr_types.most_common()),
        "index_index_types": dict(index_index_types.most_common()),
        "call_func_types": dict(call_func_types.most_common()),
        "call_argc": dict(call_argc.most_common()),
        "call_args_field": dict(call_has_args.most_common()),
        "instances": rows,
        "interpretation_gate": {
            "structured_rhs_local_match_is_dependency_evidence": True,
            "snapshot_value_is_live_at_rhs_evaluation": False,
            "indexexpr_value_evaluated": False,
            "call_value_evaluated": False,
            "subtraction_value_evaluated": False,
            "arithmetic_origin_proved": False,
            "frame_base_bug_proved": False,
            "semantic_change_authorized": False,
        },
        "no_lift_rerun": True,
    }

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181f", type=Path)
    ap.add_argument("--json-out", type=Path, required=True)
    a = ap.parse_args()
    try:
        out = analyze(a.r181f)
        a.json_out.parent.mkdir(parents=True, exist_ok=True)
        a.json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        s = out["summary"]
        print(f"R181G: instances={s['instances']} rhs_local_deps={s['rhs_local_dependency_instances']}")
        print("rhs types:", json.dumps(s["rhs_type_counts"], sort_keys=True))
        print("bindings:", json.dumps({
            "unique": s["rhs_unique_snapshot_matches"],
            "consistent_multi": s["rhs_multi_match_consistent"],
            "ambiguous": s["rhs_ambiguous_matches"],
            "no_match": s["rhs_no_snapshot_match"],
            "no_identity": s["rhs_no_explicit_identity"],
        }, sort_keys=True))
        print("index expr types:", json.dumps(out["index_expr_types"], sort_keys=True))
        print("index index types:", json.dumps(out["index_index_types"], sort_keys=True))
        print("call func types:", json.dumps(out["call_func_types"], sort_keys=True))
        print("call argc:", json.dumps(out["call_argc"], sort_keys=True))
        print("call args field:", json.dumps(out["call_args_field"], sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__ == "__main__":
    raise SystemExit(main())
