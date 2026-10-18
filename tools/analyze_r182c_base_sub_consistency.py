#!/usr/bin/env python3
"""R182C: join frozen Sub instances with one selected R182B base-table snapshot."""
from __future__ import annotations
import argparse, json, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r182c-base-sub-consistency.v1"

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def integer_like(v):
    if isinstance(v,bool) or v is None: return None
    if isinstance(v,int): return v
    if isinstance(v,float): return int(v) if v.is_integer() else None
    if isinstance(v,str) and re.fullmatch(r"[+-]?\d+",v.strip()):
        return int(v.strip(),10)
    return None

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def select_base(receipt,prefix):
    if receipt.get("schema")!="luraph-deobf.r182b-base-table-resolution.v1":
        raise ValueError("expected R182B receipt")
    if len(prefix)<8 or not re.fullmatch(r"[0-9a-fA-F]+",prefix):
        raise ValueError("protos SHA prefix must be >=8 hex chars")
    hits=[f for f in receipt.get("files",[]) if isinstance(f,dict)
          and isinstance(f.get("sha256"),str) and f["sha256"].lower().startswith(prefix.lower())]
    if len(hits)!=1:
        raise ValueError(f"protos SHA prefix matched {len(hits)} candidates")
    row=hits[0]
    if row.get("status")!="TABLE_FOUND":
        raise ValueError("selected snapshot does not contain table")
    if row.get("table_id") != 369:
        raise ValueError(f"selected snapshot table_id is not 369: {row.get('table_id')!r}")
    values={}
    for item in row.get("requested_keys",[]):
        if not isinstance(item,dict): continue
        key=integer_like(item.get("key"))
        if key is None: continue
        if item.get("late"):
            raise ValueError(f"selected base key {key} is late")
        if item.get("status")!="FOUND_SCALAR":
            raise ValueError(f"selected base key {key} is not scalar")
        val=integer_like((item.get("value") or {}).get("value"))
        if val is None:
            raise ValueError(f"selected base key {key} is not integer-like")
        values[key]=val
    return row,values

def left_value(inst):
    bind=inst.get("left_binding",{})
    if bind.get("classification")!="STRUCTURED_MATCH_VALUE_OTHER":
        raise ValueError(f"unexpected left binding class {bind.get('classification')!r}")
    entries=bind.get("matched_local_entries",[])
    vals=[]
    for e in entries:
        if isinstance(e,dict):
            v=integer_like(e.get("value"))
            if v is not None: vals.append(v)
    vals=set(vals)
    if len(vals)!=1:
        raise ValueError(f"left binding does not have one integer value: {sorted(vals)}")
    return next(iter(vals))

def dep_name(dep):
    names=(dep.get("binding") or {}).get("identity",{}).get("names",[])
    vals={x.get("value") for x in names if isinstance(x,dict) and isinstance(x.get("value"),str)}
    return next(iter(vals)) if len(vals)==1 else None

def dep_value(dep):
    ms=(dep.get("binding") or {}).get("matches",[])
    vals=[]
    for m in ms:
        if isinstance(m,dict): vals.append(m.get("value"))
    uniq={repr(v):v for v in vals}
    return next(iter(uniq.values())) if len(uniq)==1 else None

def require_inputs(f,g):
    if f.get("schema")!="luraph-deobf.r181f-local-identity-rhs-census.v1":
        raise ValueError("expected R181F receipt")
    if g.get("schema")!="luraph-deobf.r181g-rhs-local-dependency-census.v1":
        raise ValueError("expected R181G receipt")
    if checkpoint(f)!=(78,64,0,594) or checkpoint(g)!=(78,64,0,594):
        raise ValueError("checkpoint != 78/64/0/594")
    fi=f.get("instances",[]); gi=g.get("instances",[])
    if len(fi)!=136 or len(gi)!=136:
        raise ValueError(f"expected 136 instances in each receipt, found {len(fi)}/{len(gi)}")
    return fi,gi

def analyze(f_path,g_path,b_path,sha_prefix):
    f=load(f_path); g=load(g_path); b=load(b_path)
    fi,gi=require_inputs(f,g)
    selected,base=select_base(b,sha_prefix)
    rows=[]; result_counts=Counter(); pair_counts=Counter(); by_w=defaultdict(Counter)
    index_count=call_count=0
    for idx,(fr,gr) in enumerate(zip(fi,gi)):
        if gr.get("instance_index")!=idx:
            raise ValueError(f"R181G instance_index mismatch at {idx}")
        for key in ("function_id","state_id","right_type"):
            if fr.get(key)!=gr.get(key):
                raise ValueError(f"R181F/R181G join mismatch at {idx}: {key}")
        left=left_value(fr)
        rt=gr.get("right_type")
        if rt=="AstExprIndexExpr":
            index_count+=1
            deps={dep_name(d):dep_value(d) for d in gr.get("rhs_local_dependencies",[]) if dep_name(d)}
            if deps.get("K")!="LTable#369":
                raise ValueError(f"instance {idx}: K is not LTable#369")
            w=integer_like(deps.get("W"))
            if w is None: raise ValueError(f"instance {idx}: W not integer-like")
            if w not in base: raise ValueError(f"instance {idx}: no selected base value for W={w}")
            rhs=base[w]; result=left-rhs
            cls="BASE_CONSISTENT_NEG1" if result==-1 else "BASE_INCONSISTENT_NEG1"
            result_counts[cls]+=1
            pair_counts[(left,w,rhs,result)]+=1
            by_w[w][cls]+=1
            rows.append({"instance_index":idx,"function_id":fr.get("function_id"),"state_id":fr.get("state_id"),
                         "right_type":rt,"left_snapshot":left,"w":w,"base_rhs":rhs,
                         "base_result":result,"classification":cls})
        elif rt=="AstExprCall":
            call_count+=1
            result_counts["CALL_RHS_UNRESOLVED"]+=1
            rows.append({"instance_index":idx,"function_id":fr.get("function_id"),"state_id":fr.get("state_id"),
                         "right_type":rt,"left_snapshot":left,"classification":"CALL_RHS_UNRESOLVED"})
        else:
            raise ValueError(f"unexpected right type {rt!r}")
    if index_count!=95 or call_count!=41:
        raise ValueError(f"expected 95 index / 41 call, found {index_count}/{call_count}")
    return {
        "schema":SCHEMA,
        "sources":{"r181f":str(f_path),"r181g":str(g_path),"r182b":str(b_path)},
        "checkpoint":f["checkpoint"],
        "selected_base_snapshot":{"path":selected.get("path"),"sha256":selected.get("sha256"),
                                  "table_id":selected.get("table_id"),"base_values":{str(k):v for k,v in sorted(base.items())}},
        "summary":{"instances":136,"index_instances":index_count,"call_instances":call_count,
                   "base_consistent_neg1":result_counts["BASE_CONSISTENT_NEG1"],
                   "base_inconsistent_neg1":result_counts["BASE_INCONSISTENT_NEG1"],
                   "call_rhs_unresolved":result_counts["CALL_RHS_UNRESOLVED"]},
        "index_pair_histogram":[
            {"left":k[0],"w":k[1],"base_rhs":k[2],"base_result":k[3],"instances":n}
            for k,n in sorted(pair_counts.items())
        ],
        "by_w":{str(w):dict(c) for w,c in sorted(by_w.items())},
        "instances":rows,
        "interpretation_gate":{
            "base_consistent_is_failure_time_proof":False,
            "base_inconsistent_disproves_actual_neg1":False,
            "left_snapshot_timing_proved":False,
            "per_state_overlay_applied":False,
            "call_rhs_evaluated":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,"no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181f",type=Path); ap.add_argument("r181g",type=Path); ap.add_argument("r182b",type=Path)
    ap.add_argument("--protos-sha-prefix",required=True)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r181f,a.r181g,a.r182b,a.protos_sha_prefix)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"]
        print(f"R182C: index={s['index_instances']} call={s['call_instances']} base_consistent={s['base_consistent_neg1']} base_inconsistent={s['base_inconsistent_neg1']} call_unresolved={s['call_rhs_unresolved']}")
        print("selected_sha256:",out["selected_base_snapshot"]["sha256"])
        print("pairs:",json.dumps(out["index_pair_histogram"],sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
