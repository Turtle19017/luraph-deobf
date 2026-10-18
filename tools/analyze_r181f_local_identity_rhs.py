#!/usr/bin/env python3
"""R181F: schema-aware local-identity and RHS-shape census for frozen read/Sub evidence."""
from __future__ import annotations
import argparse, json, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "luraph-deobf.r181f-local-identity-rhs-census.v1"
SUFFIX = {".json", ".jsonl", ".log", ".txt", ".md"}
UF = re.compile(r"(?:read|store) below the stack VM's frame \(register (?P<r>-?\d+)\)")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
META_KEYS = {"op","repr","text","span","loc","location","line","column","start","end","type","kind","tag"}
LOCAL_FIELDS = ("local_values", "carried_locals")
NAME_REF_KEYS = {"name","local","local_name","identifier","symbol","source_local","var","variable"}
ID_REF_KEYS = {"id","local_id","identifier_id","symbol_id","decl_id"}

def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

def atom(v):
    if v is None or isinstance(v, bool):
        return None
    return str(v) if isinstance(v, (str, int)) else None

def numeric(v):
    return None if isinstance(v, bool) else v if isinstance(v, (int, float)) else None

def ident(rec):
    f, s = atom(rec.get("function_id")), atom(rec.get("state_id"))
    return (f, s) if f is not None and s is not None else None

def files(inputs):
    out = []
    for p in inputs:
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in SUFFIX)
        else:
            raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(out))

def walk_dicts(v, path="$"):
    if isinstance(v, dict):
        yield path, v
        for k, x in v.items():
            yield from walk_dicts(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from walk_dicts(x, f"{path}[{i}]")

def scalar_leaves(v, path="$"):
    if isinstance(v, dict):
        for k, x in v.items():
            yield from scalar_leaves(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from scalar_leaves(x, f"{path}[{i}]")
    elif isinstance(v, (str, int, float, bool)) or v is None:
        yield path, v

def find_named_subtrees(rec, suffix):
    out = []
    for path, obj in walk_dicts(rec):
        if not isinstance(obj, dict):
            continue
        for key, value in obj.items():
            if str(key).lower() == suffix.lower():
                out.append((f"{path}.{key}", value))
    seen, uniq = set(), []
    for path, value in out:
        key = (path, repr(value))
        if key not in seen:
            seen.add(key)
            uniq.append((path, value))
    return uniq

def json_line(line):
    for i in sorted(x for x in {0, line.find("{"), line.find("[")} if x >= 0):
        try:
            return json.loads(line[i:].strip())
        except json.JSONDecodeError:
            pass
    return None

def underflow_match(rec, site):
    if ident(rec) != (site["function_id"], site["state_id"]):
        return False
    if rec.get("kind") in ("below_stack", "below_stack_store"):
        return numeric(rec.get("register")) == -1
    err = rec.get("error") or rec.get("exception")
    if isinstance(err, str):
        m = UF.search(err)
        return bool(m and int(m.group("r")) == -1)
    return False

def cohort(path, expect=7):
    obj = load(path)
    if not isinstance(obj, dict) or obj.get("schema") != "luraph-deobf.r181d-index-local-linkage.v2":
        raise ValueError("expected R181D-v2 linkage census")
    cp = obj.get("checkpoint", {}).get("expected", {})
    if (cp.get("functions"), cp.get("errors"), cp.get("fallbacks"), cp.get("requests")) != (78, 64, 0, 594):
        raise ValueError("checkpoint != 78/64/0/594")
    sites, seen = [], set()
    for rec in obj.get("sites", []):
        if not isinstance(rec, dict):
            continue
        if rec.get("operation") != "read" or rec.get("classification") != "NO_LINK":
            continue
        key = ident(rec)
        if key is None:
            raise ValueError("read/NO_LINK site missing composite identity")
        if key in seen:
            raise ValueError(f"duplicate read/NO_LINK composite identity: {key}")
        seen.add(key)
        sites.append(dict(rec, function_id=key[0], state_id=key[1]))
    if len(sites) != expect:
        raise ValueError(f"expected {expect} read/NO_LINK sites, found {len(sites)}")
    return obj, sites

def matching_records(inputs, sites):
    lookup = {(x["function_id"], x["state_id"]): x for x in sites}
    out = defaultdict(list)
    for p in files(inputs):
        if p.suffix.lower() == ".json":
            obj = load(p)
            if obj is not None:
                for jp, rec in walk_dicts(obj):
                    key = ident(rec)
                    if key in lookup and underflow_match(rec, lookup[key]):
                        out[key].append((str(p), None, jp, rec))
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            obj = json_line(line)
            if obj is None:
                continue
            for jp, rec in walk_dicts(obj):
                key = ident(rec)
                if key in lookup and underflow_match(rec, lookup[key]):
                    out[key].append((str(p), line_no, jp, rec))
    return out

def collect_ids(obj, path="$"):
    out = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            low = str(key).lower()
            if low in ID_REF_KEYS and isinstance(value, (str, int)) and not isinstance(value, bool):
                out.append({"path": f"{path}.{key}", "field": str(key), "value": value})
            if isinstance(value, (dict, list)):
                out.extend(collect_ids(value, f"{path}.{key}"))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            out.extend(collect_ids(value, f"{path}[{i}]"))
    return out

def walk_local_entries(obj, path="$"):
    """Read decl{name,value}, explicit name/value entries, lists, and legacy direct maps."""
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from walk_local_entries(item, f"{path}[{i}]")
        return
    if not isinstance(obj, dict):
        return

    decl = obj.get("decl")
    explicit = False
    if isinstance(decl, dict) and isinstance(decl.get("name"), str) and "value" in decl:
        explicit = True
        yield {
            "path": f"{path}.decl",
            "name": decl["name"],
            "value": decl.get("value"),
            "ids": collect_ids(decl, f"{path}.decl"),
            "encoding": "decl-name-value",
        }
    elif isinstance(obj.get("name"), str) and "value" in obj:
        explicit = True
        yield {
            "path": path,
            "name": obj["name"],
            "value": obj.get("value"),
            "ids": collect_ids(obj, path),
            "encoding": "name-value",
        }

    if not explicit:
        for key, value in obj.items():
            if (
                isinstance(key, str) and IDENT.match(key)
                and key not in {"decl", "name", "value", "ids"}
                and not isinstance(value, (dict, list))
            ):
                yield {
                    "path": f"{path}.{key}",
                    "name": key,
                    "value": value,
                    "ids": [],
                    "encoding": "direct-map",
                }

    for key, value in obj.items():
        if isinstance(value, (dict, list)):
            if key == "decl" and explicit:
                continue
            yield from walk_local_entries(value, f"{path}.{key}")

def local_snapshot_entries(rec):
    out, seen = [], set()
    for label in LOCAL_FIELDS:
        for path, obj in find_named_subtrees(rec, label):
            for entry in walk_local_entries(obj, path):
                sig = (entry["path"], entry["name"], repr(entry["value"]), entry["encoding"])
                if sig not in seen:
                    seen.add(sig)
                    out.append(entry)
    return out

def node_type(node):
    if not isinstance(node, dict):
        return type(node).__name__
    for key in ("type", "kind", "tag", "op"):
        value = node.get(key)
        if isinstance(value, str):
            return value
    return "dict"

def node_fields(node):
    if not isinstance(node, dict):
        return []
    return [
        {"field": str(key), "shape": node_type(value),
         "value": value if isinstance(value, (str, int, float, bool)) or value is None else None}
        for key, value in node.items()
        if str(key).lower() not in META_KEYS
    ]

def named_refs(node, path="$"):
    refs = []
    if isinstance(node, dict):
        for key, value in node.items():
            low = str(key).lower()
            p = f"{path}.{key}"
            if low in NAME_REF_KEYS and isinstance(value, str):
                refs.append({"path": p, "field": str(key), "kind": "name", "value": value})
            elif low in ID_REF_KEYS and isinstance(value, (str, int)) and not isinstance(value, bool):
                refs.append({"path": p, "field": str(key), "kind": "id", "value": value})
            if isinstance(value, (dict, list)):
                refs.extend(named_refs(value, p))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            refs.extend(named_refs(value, f"{path}[{i}]"))
    return refs

def textual_name_hits(node, local_names):
    hits = []
    for path, value in scalar_leaves(node):
        if not isinstance(value, str):
            continue
        for name in local_names:
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", value):
                hits.append({"path": path, "local_name": name, "text": value})
    return hits

def bind_left_local(left, entries):
    refs = named_refs(left)
    by_name = defaultdict(list)
    by_id = defaultdict(list)
    for entry in entries:
        by_name[entry["name"]].append(entry)
        for item in entry.get("ids", []):
            by_id[(type(item["value"]).__name__, repr(item["value"]))].append(entry)

    hits = []
    for ref in refs:
        if ref["kind"] == "name" and ref["value"] in by_name:
            hits.extend({"ref": ref, "entry": entry} for entry in by_name[ref["value"]])
        elif ref["kind"] == "id":
            key = (type(ref["value"]).__name__, repr(ref["value"]))
            hits.extend({"ref": ref, "entry": entry} for entry in by_id.get(key, []))

    unique = {}
    for hit in hits:
        entry = hit["entry"]
        unique[(entry["path"], entry["name"], repr(entry["value"]))] = entry
    matched = list(unique.values())
    names = {entry["name"] for entry in matched}
    values = {repr(entry["value"]) for entry in matched}

    if matched:
        if len(matched) > 1 and (len(names) > 1 or len(values) > 1):
            classification = "STRUCTURED_MATCH_AMBIGUOUS"
        elif all(entry["value"] == -1 and not isinstance(entry["value"], bool) for entry in matched):
            classification = "STRUCTURED_MATCH_VALUE_MINUS_ONE"
        else:
            classification = "STRUCTURED_MATCH_VALUE_OTHER"
    else:
        local_names = {entry["name"] for entry in entries}
        if textual_name_hits(left, local_names):
            classification = "TEXTUAL_ONLY"
        else:
            classification = "NO_STRUCTURED_MATCH"

    return {
        "classification": classification,
        "identity_refs": refs,
        "matched_local_entries": matched,
        "textual_hits": textual_name_hits(left, {entry["name"] for entry in entries}) if not matched else [],
    }

def analyze(r181d_path, evidence_inputs, expect_cohort=7,
            expect_sub_instances=136, expect_left_local=136,
            expect_right_index=95, expect_right_call=41):
    src, sites = cohort(r181d_path, expect_cohort)
    matches = matching_records(evidence_inputs, sites)
    rows, instances = [], []
    left_types, right_types = Counter(), Counter()
    left_field_paths, right_child_fields, right_child_shapes = Counter(), Counter(), Counter()
    bindings = Counter()
    per_site_counts = {}

    for site in sites:
        key = (site["function_id"], site["state_id"])
        site_instances = []
        for source, line, json_path, rec in matches.get(key, []):
            snapshots = local_snapshot_entries(rec)
            for ast_path, ast_obj in find_named_subtrees(rec, "index_ast"):
                if not isinstance(ast_obj, dict) or ast_obj.get("op") != "Sub":
                    continue
                if "left" not in ast_obj or "right" not in ast_obj:
                    raise ValueError(f"Sub AST missing left/right at {source}:{line}:{ast_path}")
                left, right = ast_obj["left"], ast_obj["right"]
                lt, rt = node_type(left), node_type(right)
                left_types[lt] += 1
                right_types[rt] += 1
                for p, _ in scalar_leaves(left):
                    left_field_paths[p] += 1
                for field in node_fields(right):
                    right_child_fields[field["field"]] += 1
                    right_child_shapes[f"{field['field']}::{field['shape']}"] += 1
                binding = bind_left_local(left, snapshots)
                bindings[binding["classification"]] += 1
                inst = {
                    "function_id": key[0], "state_id": key[1],
                    "source": source, "line": line, "json_path": json_path, "index_ast_path": ast_path,
                    "left_type": lt, "left_node": left,
                    "left_scalar_leaves": [{"path": p, "value": v} for p, v in scalar_leaves(left)],
                    "right_type": rt, "right_node": right,
                    "right_child_fields": node_fields(right),
                    "right_scalar_leaves": [{"path": p, "value": v} for p, v in scalar_leaves(right)],
                    "local_snapshot_entries": snapshots,
                    "left_binding": binding,
                }
                instances.append(inst)
                site_instances.append(inst)
        per_site_counts[f"{key[0]}::{key[1]}"] = len(site_instances)
        if not site_instances:
            raise ValueError(f"read site has no matched frozen Sub AST: {key}")
        rows.append({
            "function_id": key[0], "state_id": key[1],
            "mode": site.get("mode"), "pc": site.get("pc"),
            "operation": site.get("operation"), "classification_r181d": site.get("classification"),
            "sub_instances": len(site_instances),
            "left_binding_counts": dict(Counter(x["left_binding"]["classification"] for x in site_instances)),
        })

    right_index = right_types.get("AstExprIndexExpr", 0)
    right_call = right_types.get("AstExprCall", 0)
    left_local = left_types.get("AstExprLocal", 0)
    if len(instances) != expect_sub_instances:
        raise ValueError(f"expected {expect_sub_instances} Sub instances, found {len(instances)}")
    if left_local != expect_left_local:
        raise ValueError(f"expected {expect_left_local} AstExprLocal left operands, found {left_local}")
    if right_index != expect_right_index:
        raise ValueError(f"expected {expect_right_index} AstExprIndexExpr right operands, found {right_index}")
    if right_call != expect_right_call:
        raise ValueError(f"expected {expect_right_call} AstExprCall right operands, found {right_call}")

    return {
        "schema": SCHEMA,
        "source_r181d": str(r181d_path),
        "checkpoint": src["checkpoint"],
        "cohort_sites": len(sites),
        "summary": {
            "sub_instances": len(instances),
            "left_type_counts": dict(left_types.most_common()),
            "right_type_counts": dict(right_types.most_common()),
            "left_structured_match_minus_one": bindings.get("STRUCTURED_MATCH_VALUE_MINUS_ONE", 0),
            "left_structured_match_other": bindings.get("STRUCTURED_MATCH_VALUE_OTHER", 0),
            "left_structured_match_ambiguous": bindings.get("STRUCTURED_MATCH_AMBIGUOUS", 0),
            "left_textual_only": bindings.get("TEXTUAL_ONLY", 0),
            "left_no_structured_match": bindings.get("NO_STRUCTURED_MATCH", 0),
        },
        "left_scalar_paths": dict(left_field_paths.most_common()),
        "right_child_fields": dict(right_child_fields.most_common()),
        "right_child_shapes": dict(right_child_shapes.most_common()),
        "per_site_sub_instances": per_site_counts,
        "sites": sorted(rows, key=lambda x: (x["function_id"], x["state_id"])),
        "instances": instances,
        "interpretation_gate": {
            "structured_match_is_candidate_binding_not_temporal_value_proof": True,
            "snapshot_value_is_proven_current_at_ast_evaluation": False,
            "right_expression_was_evaluated": False,
            "arithmetic_origin_proved": False,
            "frame_base_bug_proved": False,
            "semantic_change_authorized": False,
            "requires_exact_composite_identity": True,
        },
        "no_lift_rerun": True,
    }

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181d", type=Path)
    ap.add_argument("evidence", nargs="+", type=Path)
    ap.add_argument("--expect-cohort", type=int, default=7)
    ap.add_argument("--expect-sub-instances", type=int, default=136)
    ap.add_argument("--expect-left-local", type=int, default=136)
    ap.add_argument("--expect-right-index", type=int, default=95)
    ap.add_argument("--expect-right-call", type=int, default=41)
    ap.add_argument("--json-out", type=Path, required=True)
    a = ap.parse_args()
    try:
        out = analyze(a.r181d, a.evidence, a.expect_cohort, a.expect_sub_instances,
                       a.expect_left_local, a.expect_right_index, a.expect_right_call)
        a.json_out.parent.mkdir(parents=True, exist_ok=True)
        a.json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"R181F: cohort={out['cohort_sites']} sub={out['summary']['sub_instances']}")
        print("left types:", json.dumps(out["summary"]["left_type_counts"], sort_keys=True))
        print("right types:", json.dumps(out["summary"]["right_type_counts"], sort_keys=True))
        print("left bindings:", json.dumps({k: v for k, v in out["summary"].items() if k.startswith("left_") and k not in ("left_type_counts",)}, sort_keys=True))
        print("right child fields:", json.dumps(out["right_child_fields"], sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__ == "__main__":
    raise SystemExit(main())
