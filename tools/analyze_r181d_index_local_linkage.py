#!/usr/bin/env python3
"""R181D: artifact-only linkage census between -1 locals and negative-slot index expressions."""
from __future__ import annotations
import argparse, ast, json, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "luraph-deobf.r181d-index-local-linkage.v1"
SUFFIX = {".json", ".jsonl", ".log", ".txt", ".md"}
UF = re.compile(r"(?:read|store) below the stack VM's frame \(register (?P<r>-?\d+)\)")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRUCTURED_NAME_KEYS = {
    "name", "local", "local_name", "identifier", "id", "var", "variable",
    "symbol", "source_local", "local_id",
}

def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

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

def atom(v):
    if v is None or isinstance(v, bool):
        return None
    return str(v) if isinstance(v, (str, int)) else None

def ident(rec):
    f, s = atom(rec.get("function_id")), atom(rec.get("state_id"))
    return (f, s) if f is not None and s is not None else None

def numeric(v):
    return None if isinstance(v, bool) else v if isinstance(v, (int, float)) else None

def parse_literal(v):
    if isinstance(v, str):
        try:
            return ast.literal_eval(v)
        except (ValueError, SyntaxError):
            return v
    return v

def is_minus_one(v):
    v = parse_literal(v)
    return not isinstance(v, bool) and (
        (isinstance(v, (int, float)) and v == -1)
        or (isinstance(v, str) and v.strip() in ("-1", "-1.0"))
    )

def walk_dicts(v, path="$"):
    if isinstance(v, dict):
        yield path, v
        for k, x in v.items():
            yield from walk_dicts(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from walk_dicts(x, f"{path}[{i}]")

def leaves(v, path="$"):
    if isinstance(v, dict):
        for k, x in v.items():
            yield from leaves(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from leaves(x, f"{path}[{i}]")
    else:
        yield path, v

def find_named_subtrees(rec, suffix):
    out = []
    def visit(v, path="$"):
        if isinstance(v, dict):
            for k, x in v.items():
                np = f"{path}.{k}"
                if str(k).lower() == suffix.lower():
                    out.append((np, x))
                visit(x, np)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                visit(x, f"{path}[{i}]")
    visit(rec)
    seen = set()
    uniq = []
    for p, v in out:
        key = (p, repr(v))
        if key not in seen:
            seen.add(key)
            uniq.append((p, v))
    return uniq

def local_minus_one_names(rec):
    names = set()
    for label in ("local_values", "carried_locals"):
        for _, obj in find_named_subtrees(rec, label):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(k, str) and IDENT.match(k) and is_minus_one(v):
                        names.add(k)
    return names

def structured_local_refs(ast_obj, local_names):
    hits = []
    def visit(v, path="$"):
        if isinstance(v, dict):
            for k, x in v.items():
                np = f"{path}.{k}"
                if str(k).lower() in STRUCTURED_NAME_KEYS and isinstance(x, (str, int)):
                    sx = str(x)
                    if sx in local_names:
                        hits.append((np, sx))
                visit(x, np)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                visit(x, f"{path}[{i}]")
    visit(ast_obj)
    return hits

def textual_local_refs(value, local_names):
    hits = []
    for path, leaf in leaves(value):
        if not isinstance(leaf, str):
            continue
        for name in local_names:
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", leaf):
                hits.append((path, name))
    return hits

def ast_op(ast_obj):
    if isinstance(ast_obj, dict):
        op = ast_obj.get("op")
        if isinstance(op, str):
            return op
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

def json_line(line):
    for i in sorted(x for x in {0, line.find("{"), line.find("[")} if x >= 0):
        try:
            return json.loads(line[i:].strip())
        except json.JSONDecodeError:
            pass
    return None

def cohort(path, expect=9):
    obj = load(path)
    if not isinstance(obj, dict) or obj.get("schema") != "luraph-deobf.r181b-negative-slot-provenance.v1":
        raise ValueError("expected R181B provenance census")
    cp = obj.get("checkpoint", {}).get("expected", {})
    if (cp.get("functions"), cp.get("errors"), cp.get("fallbacks"), cp.get("requests")) != (78, 64, 0, 594):
        raise ValueError("checkpoint != 78/64/0/594")
    sites = []
    seen = set()
    for rec in obj.get("sites", []):
        if not isinstance(rec, dict) or numeric(rec.get("register")) != -1 or numeric(rec.get("stack_base")) != 1:
            continue
        k = ident(rec)
        if k is None:
            raise ValueError("cohort site missing composite identity")
        if k in seen:
            raise ValueError(f"duplicate cohort identity: {k}")
        seen.add(k)
        sites.append(dict(rec, function_id=k[0], state_id=k[1]))
    if len(sites) != expect:
        raise ValueError(f"expected {expect} cohort sites, found {len(sites)}")
    return obj, sites

def matching_records(inputs, sites):
    lookup = {(x["function_id"], x["state_id"]): x for x in sites}
    out = defaultdict(list)
    for p in files(inputs):
        if p.suffix.lower() == ".json":
            obj = load(p)
            if obj is not None:
                for jp, rec in walk_dicts(obj):
                    k = ident(rec)
                    if k in lookup and underflow_match(rec, lookup[k]):
                        out[k].append((str(p), None, jp, rec))
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
                k = ident(rec)
                if k in lookup and underflow_match(rec, lookup[k]):
                    out[k].append((str(p), line_no, jp, rec))
    return out

def analyze(r181b_path, evidence_inputs, expect_cohort=9):
    src, sites = cohort(r181b_path, expect_cohort)
    matches = matching_records(evidence_inputs, sites)
    rows = []
    classes = Counter()
    ast_shapes = Counter()

    for site in sites:
        k = (site["function_id"], site["state_id"])
        site_records = matches.get(k, [])
        evidence = []
        site_classes = set()
        for source, line, json_path, rec in site_records:
            local_names = local_minus_one_names(rec)
            asts = find_named_subtrees(rec, "index_ast")
            trees = find_named_subtrees(rec, "key_tree")
            exact_hits = []
            ast_text_hits = []
            tree_text_hits = []
            ops = []
            for ap, av in asts:
                op = ast_op(av)
                if op:
                    ops.append(op)
                    ast_shapes[op] += 1
                exact_hits.extend((f"{ap}{p[1:]}", name) for p, name in structured_local_refs(av, local_names))
                ast_text_hits.extend((f"{ap}{p[1:]}", name) for p, name in textual_local_refs(av, local_names))
            for tp, tv in trees:
                tree_text_hits.extend((f"{tp}{p[1:]}", name) for p, name in textual_local_refs(tv, local_names))

            if exact_hits:
                cls = "AST_EXACT_LOCAL_LINK"
            elif tree_text_hits or ast_text_hits:
                cls = "TEXTUAL_LOCAL_LINK"
            elif local_names and asts:
                cls = "CO_OCCURRENCE_ONLY"
            else:
                cls = "NO_LINK"
            site_classes.add(cls)
            evidence.append({
                "source": source,
                "line": line,
                "json_path": json_path,
                "minus_one_locals": sorted(local_names),
                "index_ast_count": len(asts),
                "index_ast_ops": ops,
                "key_tree_count": len(trees),
                "exact_structured_local_refs": [{"path": p, "local": n} for p, n in exact_hits],
                "ast_textual_local_refs": [{"path": p, "local": n} for p, n in ast_text_hits],
                "key_tree_textual_local_refs": [{"path": p, "local": n} for p, n in tree_text_hits],
                "class": cls,
            })

        if "AST_EXACT_LOCAL_LINK" in site_classes:
            final = "AST_EXACT_LOCAL_LINK"
        elif "TEXTUAL_LOCAL_LINK" in site_classes:
            final = "TEXTUAL_LOCAL_LINK"
        elif "CO_OCCURRENCE_ONLY" in site_classes:
            final = "CO_OCCURRENCE_ONLY"
        else:
            final = "NO_LINK"
        classes[final] += 1
        rows.append({
            "function_id": k[0],
            "state_id": k[1],
            "mode": site.get("mode"),
            "pc": site.get("pc"),
            "operation": site.get("operation"),
            "classification": final,
            "matched_records": len(site_records),
            "evidence": evidence,
        })

    return {
        "schema": SCHEMA,
        "source_r181b": str(r181b_path),
        "checkpoint": src["checkpoint"],
        "cohort_sites": len(sites),
        "summary": {name: classes[name] for name in (
            "AST_EXACT_LOCAL_LINK", "TEXTUAL_LOCAL_LINK", "CO_OCCURRENCE_ONLY", "NO_LINK"
        )},
        "index_ast_ops": dict(ast_shapes.most_common()),
        "sites": sorted(rows, key=lambda x: (x["function_id"], x["state_id"])),
        "proof_gate": {
            "ast_exact_local_link_proves_value_reaches_index_operand": True,
            "ast_exact_local_link_proves_final_arithmetic_origin": False,
            "textual_link_proves_origin": False,
            "cooccurrence_proves_origin": False,
            "semantic_change_authorized": False,
            "requires_exact_composite_identity": True,
        },
        "no_lift_rerun": True,
    }

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181b", type=Path)
    ap.add_argument("evidence", nargs="+", type=Path)
    ap.add_argument("--expect-cohort", type=int, default=9)
    ap.add_argument("--json-out", type=Path, required=True)
    a = ap.parse_args()
    try:
        out = analyze(a.r181b, a.evidence, a.expect_cohort)
        a.json_out.parent.mkdir(parents=True, exist_ok=True)
        a.json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        s = out["summary"]
        print(f"R181D: cohort={out['cohort_sites']} exact={s['AST_EXACT_LOCAL_LINK']} textual={s['TEXTUAL_LOCAL_LINK']} cooccur={s['CO_OCCURRENCE_ONLY']} no_link={s['NO_LINK']}")
        print("index_ast_ops:", json.dumps(out["index_ast_ops"], sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__ == "__main__":
    raise SystemExit(main())
