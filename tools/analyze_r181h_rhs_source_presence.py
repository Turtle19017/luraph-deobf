#!/usr/bin/env python3
"""R181H: frozen-source presence census for LTable contents and bit32.bxor call arguments."""
from __future__ import annotations
import argparse, json, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "luraph-deobf.r181h-rhs-source-presence.v1"
SUFFIX = {".json", ".jsonl", ".log", ".txt", ".md"}
UF = re.compile(r"(?:read|store) below the stack VM's frame \(register (?P<r>-?\d+)\)")
TABLE_CONTENT_KEYS = {
    "h","entries","items","contents","content","values","map","mapping",
    "table_contents","table_entries","snapshot","members",
}
ARG_KEYS = {"args","arguments","argv","operands","call_args","arg_values","call_arguments"}
TABLE_ID_KEYS = {"tid","table_id","table_tid","object_id","object_tid"}

def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

def files(inputs):
    out=[]
    for p in inputs:
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in SUFFIX)
        else:
            raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(out))

def atom(v):
    if v is None or isinstance(v,bool): return None
    return str(v) if isinstance(v,(str,int)) else None

def ident(rec):
    f,s=atom(rec.get("function_id")),atom(rec.get("state_id"))
    return (f,s) if f is not None and s is not None else None

def numeric(v):
    return None if isinstance(v,bool) else v if isinstance(v,(int,float)) else None

def walk_dicts(v,path="$"):
    if isinstance(v,dict):
        yield path,v
        for k,x in v.items():
            yield from walk_dicts(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v):
            yield from walk_dicts(x,f"{path}[{i}]")

def leaves(v,path="$"):
    if isinstance(v,dict):
        for k,x in v.items():
            yield from leaves(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v):
            yield from leaves(x,f"{path}[{i}]")
    else:
        yield path,v

def normalize_path(path):
    return re.sub(r"\[\d+\]","[]",path)

def json_line(line):
    for i in sorted(x for x in {0,line.find("{"),line.find("[")} if x>=0):
        try: return json.loads(line[i:].strip())
        except json.JSONDecodeError: pass
    return None

def local_dep_name(dep):
    binding=dep.get("binding",{}) if isinstance(dep,dict) else {}
    names=binding.get("identity",{}).get("names",[])
    vals=[x.get("value") for x in names if isinstance(x,dict) and isinstance(x.get("value"),str)]
    return vals[0] if len(set(vals))==1 and vals else None

def local_dep_value(dep):
    binding=dep.get("binding",{}) if isinstance(dep,dict) else {}
    matches=binding.get("matches",[])
    vals=[x.get("value") for x in matches if isinstance(x,dict)]
    uniq={repr(v):v for v in vals}
    return next(iter(uniq.values())) if len(uniq)==1 else None

def require_r181g(obj, table_ref, builtin_ref):
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r181g-rhs-local-dependency-census.v1":
        raise ValueError("expected R181G RHS local-dependency census")
    cp=obj.get("checkpoint",{}).get("expected",{})
    if (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))!=(78,64,0,594):
        raise ValueError("checkpoint != 78/64/0/594")
    rows=obj.get("instances",[])
    if len(rows)!=136:
        raise ValueError(f"expected 136 R181G instances, found {len(rows)}")

    table_rows=[]; call_rows=[]; required_keys=Counter()
    for row in rows:
        if not isinstance(row,dict): continue
        rt=row.get("right_type")
        deps=row.get("rhs_local_dependencies",[])
        depmap={}
        for dep in deps:
            name=local_dep_name(dep)
            if name is not None:
                depmap[name]=local_dep_value(dep)
        if rt=="AstExprIndexExpr":
            if depmap.get("K")!=table_ref:
                raise ValueError(f"index instance K is not {table_ref!r}: {depmap.get('K')!r}")
            w=depmap.get("W")
            if numeric(w) is None:
                raise ValueError(f"index instance W is not numeric: {w!r}")
            required_keys[str(int(w) if isinstance(w,float) and w.is_integer() else w)] += 1
            table_rows.append(row)
        elif rt=="AstExprCall":
            if depmap.get("v")!=builtin_ref:
                raise ValueError(f"call instance v is not {builtin_ref!r}: {depmap.get('v')!r}")
            argc=row.get("rhs_schema",{}).get("argc")
            if argc!=2:
                raise ValueError(f"call argc is not 2: {argc!r}")
            call_rows.append(row)
    if len(table_rows)!=95 or len(call_rows)!=41:
        raise ValueError(f"expected 95 table / 41 call instances, found {len(table_rows)}/{len(call_rows)}")
    return table_rows,call_rows,required_keys

def record_contains_value(rec,target):
    return any(v==target for _,v in leaves(rec))

def record_contains_table_id(rec,tid):
    for path,v in leaves(rec):
        field=path.rsplit(".",1)[-1].split("[",1)[0].lower()
        if field in TABLE_ID_KEYS and numeric(v)==tid:
            return True
    return False

def candidate_paths(rec,keys):
    out=[]
    for path,obj in walk_dicts(rec):
        if not isinstance(obj,dict): continue
        for k,v in obj.items():
            if str(k).lower() in keys:
                out.append({"path":normalize_path(f"{path}.{k}"),"shape":shape(v),"sample":sample(v)})
    return out

def shape(v):
    if isinstance(v,dict): return "dict"
    if isinstance(v,list): return f"list[{len(v)}]"
    if v is None:return "null"
    if isinstance(v,bool):return "bool"
    if isinstance(v,int):return "int"
    if isinstance(v,float):return "float"
    if isinstance(v,str):return "str"
    return type(v).__name__

def sample(v):
    s=repr(v)
    return s if len(s)<=240 else s[:237]+"..."

def underflow_site_match(rec,key):
    if ident(rec)!=key:return False
    if rec.get("kind") in ("below_stack","below_stack_store"):
        return numeric(rec.get("register"))==-1
    err=rec.get("error") or rec.get("exception")
    if isinstance(err,str):
        m=UF.search(err); return bool(m and int(m.group("r"))==-1)
    return False

def scan(inputs, table_ref, table_tid, call_site_ids):
    table_records=[]
    call_records=defaultdict(list)
    global_builtin_records=0
    scanned=0

    def consume(source,line,obj):
        nonlocal global_builtin_records,scanned
        scanned += 1
        for jp,rec in walk_dicts(obj):
            if record_contains_value(rec,table_ref) or record_contains_table_id(rec,table_tid):
                paths=candidate_paths(rec,TABLE_CONTENT_KEYS)
                table_records.append({
                    "source":source,"line":line,"json_path":jp,
                    "table_ref_match":record_contains_value(rec,table_ref),
                    "table_tid_match":record_contains_table_id(rec,table_tid),
                    "candidate_content_paths":paths,
                })
            if record_contains_value(rec,"Builtin(bit32.bxor)"):
                global_builtin_records += 1
            key=ident(rec)
            if key in call_site_ids and underflow_site_match(rec,key):
                call_records[key].append({
                    "source":source,"line":line,"json_path":jp,
                    "arg_like_paths":candidate_paths(rec,ARG_KEYS),
                })

    for p in files(inputs):
        if p.suffix.lower()==".json":
            obj=load(p)
            if obj is not None: consume(str(p),None,obj)
            continue
        try: lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError: continue
        for n,line in enumerate(lines,1):
            obj=json_line(line)
            if obj is not None: consume(str(p),n,obj)
    return scanned,table_records,call_records,global_builtin_records

def analyze(r181g_path,evidence_inputs,table_ref="LTable#369",builtin_ref="Builtin(bit32.bxor)"):
    obj=load(r181g_path)
    table_rows,call_rows,required_keys=require_r181g(obj,table_ref,builtin_ref)
    m=re.fullmatch(r"LTable#(\d+)",table_ref)
    if not m: raise ValueError(f"table ref does not expose numeric tid: {table_ref!r}")
    tid=int(m.group(1))
    call_ids={(str(x.get("function_id")),str(x.get("state_id"))) for x in call_rows}
    if len(call_ids)==0: raise ValueError("no call composite identities")
    scanned,table_records,call_records,builtin_records=scan(evidence_inputs,table_ref,tid,call_ids)

    content_paths=Counter()
    for rec in table_records:
        for item in rec["candidate_content_paths"]:
            content_paths[item["path"]]+=1
    arg_paths=Counter()
    call_sites_with_args=set()
    for key,recs in call_records.items():
        for rec in recs:
            if rec["arg_like_paths"]:
                call_sites_with_args.add(key)
            for item in rec["arg_like_paths"]:
                arg_paths[item["path"]]+=1

    return {
        "schema":SCHEMA,
        "source_r181g":str(r181g_path),
        "checkpoint":obj["checkpoint"],
        "requirements":{
            "table_ref":table_ref,
            "table_tid":tid,
            "table_lookup_instances":len(table_rows),
            "required_table_keys":dict(required_keys.most_common()),
            "builtin_ref":builtin_ref,
            "call_instances":len(call_rows),
            "call_argc":2,
            "unique_call_sites":len(call_ids),
        },
        "summary":{
            "scanned_json_roots":scanned,
            "table_reference_records":len(table_records),
            "table_records_with_candidate_content":sum(bool(x["candidate_content_paths"]) for x in table_records),
            "unique_table_candidate_content_paths":len(content_paths),
            "call_sites_with_matched_underflow_records":sum(bool(call_records.get(k)) for k in call_ids),
            "call_sites_with_arg_like_fields":len(call_sites_with_args),
            "unique_call_arg_like_paths":len(arg_paths),
            "global_builtin_reference_records":builtin_records,
        },
        "table_candidate_content_paths":dict(content_paths.most_common()),
        "call_arg_like_paths":dict(arg_paths.most_common()),
        "table_records":table_records,
        "call_sites":[
            {"function_id":k[0],"state_id":k[1],
             "matched_records":len(call_records.get(k,[])),
             "records":call_records.get(k,[])}
            for k in sorted(call_ids)
        ],
        "interpretation_gate":{
            "table_reference_record_proves_contents":False,
            "candidate_content_field_proves_required_key_present":False,
            "arg_like_field_proves_call_argument_values":False,
            "zero_candidate_fields_means_not_captured_in_scanned_evidence_only":True,
            "rhs_evaluated":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,
        "no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181g",type=Path)
    ap.add_argument("evidence",nargs="+",type=Path)
    ap.add_argument("--table-ref",default="LTable#369")
    ap.add_argument("--builtin-ref",default="Builtin(bit32.bxor)")
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r181g,a.evidence,a.table_ref,a.builtin_ref)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"]; r=out["requirements"]
        print(f"R181H: table_instances={r['table_lookup_instances']} call_instances={r['call_instances']} call_sites={r['unique_call_sites']}")
        print("required_table_keys:",json.dumps(r["required_table_keys"],sort_keys=True))
        print(f"table_records={s['table_reference_records']} with_content_candidates={s['table_records_with_candidate_content']} content_paths={s['unique_table_candidate_content_paths']}")
        print(f"call_sites_matched={s['call_sites_with_matched_underflow_records']} with_arg_fields={s['call_sites_with_arg_like_fields']} arg_paths={s['unique_call_arg_like_paths']}")
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
