#!/usr/bin/env python3
"""R183A: extract exact failure-time Sub operands from DEVIRT_FRAME_DEBUG logs."""
from __future__ import annotations
import argparse, json, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r183a-exact-sub-operands.v1"
FRAME_MARK="[FRAMEFAIL]"

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def require_r181f(obj):
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r181f-local-identity-rhs-census.v1":
        raise ValueError("expected R181F receipt")
    if checkpoint(obj)!=(78,64,0,594):
        raise ValueError("R181F checkpoint != 78/64/0/594")
    sites=[]
    seen=set()
    by_mp={}
    for row in obj.get("sites",[]):
        if not isinstance(row,dict) or row.get("operation")!="read":
            continue
        fid,sid=row.get("function_id"),row.get("state_id")
        mode,pc=row.get("mode"),row.get("pc")
        if fid is None or sid is None or mode is None or pc is None:
            raise ValueError("R181F site missing composite identity or mode/pc")
        key=(str(fid),str(sid))
        if key in seen:raise ValueError(f"duplicate R181F composite site {key}")
        seen.add(key)
        mp=(mode,pc)
        if mp in by_mp and by_mp[mp]!=key:
            raise ValueError(f"mode/pc {mp} is not unique across R181F sites")
        by_mp[mp]=key
        sites.append({"function_id":key[0],"state_id":key[1],"mode":mode,"pc":pc,
                      "sub_instances":row.get("sub_instances")})
    if len(sites)!=7:
        raise ValueError(f"expected 7 R181F read/Sub sites, found {len(sites)}")
    return sites,by_mp

def numeric_value(v):
    if not isinstance(v,dict):return None
    x=v.get("value")
    if isinstance(x,bool) or not isinstance(x,(int,float)):return None
    return x

def parse_framefails(paths):
    out=[]
    for p in paths:
        if not p.is_file():raise ValueError(f"log not found: {p}")
        for n,line in enumerate(p.read_text(encoding="utf-8",errors="replace").splitlines(),1):
            pos=line.find(FRAME_MARK)
            if pos<0:continue
            raw=line[pos+len(FRAME_MARK):].strip()
            try:rec=json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(rec,dict):
                out.append({"source":str(p),"line":n,"record":rec})
    return out

def classify(rec):
    ie=rec.get("index_eval")
    ia=rec.get("index_ast")
    if not isinstance(ia,dict) or ia.get("type")!="AstExprBinary" or ia.get("op")!="Sub":
        return "NOT_SUB_AST",None
    if not isinstance(ie,dict) or ie.get("op")!="Sub":
        return "NO_EXACT_SUB_EVAL",None
    left=numeric_value(ie.get("left"))
    right=numeric_value(ie.get("right"))
    result=numeric_value(ie.get("result"))
    if left is None or right is None or result is None:
        return "NONNUMERIC_SUB_EVAL",{"left":left,"right":right,"result":result}
    arithmetic_ok=(left-right)==result
    if not arithmetic_ok:
        return "ARITHMETIC_MISMATCH",{"left":left,"right":right,"result":result}
    if result==-1 and rec.get("register")==-1:
        return "EXACT_SUB_NEG1",{"left":left,"right":right,"result":result}
    return "EXACT_SUB_OTHER",{"left":left,"right":right,"result":result}

def dedupe_records(rows):
    out=[];seen=set()
    for x in rows:
        rec=x["record"]
        sig=json.dumps({
            "mode":rec.get("mode"),"pc":rec.get("pc"),"kind":rec.get("kind"),
            "register":rec.get("register"),"stack_base":rec.get("stack_base"),
            "proto_tid":rec.get("proto_tid"),"vm_tag":rec.get("vm_tag"),
            "index_ast":rec.get("index_ast"),"index_eval":rec.get("index_eval"),
        },sort_keys=True,ensure_ascii=False,default=repr)
        if sig in seen:continue
        seen.add(sig);out.append(x)
    return out

def analyze(r181f_path,logs):
    r181f=load(r181f_path)
    sites,by_mp=require_r181f(r181f)
    raw=parse_framefails(logs)
    matched=defaultdict(list)
    unmatched=0
    for x in raw:
        rec=x["record"]
        if rec.get("kind")!="below_stack" or rec.get("register")!=-1 or rec.get("stack_base")!=1:
            continue
        mp=(rec.get("mode"),rec.get("pc"))
        key=by_mp.get(mp)
        if key is None:
            unmatched+=1;continue
        matched[key].append(x)

    site_rows=[];global_classes=Counter();right_types=Counter();tuple_counts=Counter()
    for site in sites:
        key=(site["function_id"],site["state_id"])
        records=dedupe_records(matched.get(key,[]))
        classes=Counter();tuples=Counter();out_records=[]
        for x in records:
            rec=x["record"]
            cls,vals=classify(rec)
            classes[cls]+=1;global_classes[cls]+=1
            ia=rec.get("index_ast") or {}
            rt=((ia.get("right") or {}).get("type") if isinstance(ia.get("right"),dict) else None)
            if rt:right_types[rt]+=1
            if vals and all(vals.get(k) is not None for k in ("left","right","result")):
                tup=f"{vals['left']}|{vals['right']}|{vals['result']}"
                tuples[tup]+=1;tuple_counts[tup]+=1
            out_records.append({
                "source":x["source"],"line":x["line"],
                "proto_tid":rec.get("proto_tid"),"vm_tag":rec.get("vm_tag"),
                "last_op":rec.get("last_op"),
                "right_ast_type":rt,
                "classification":cls,"values":vals,
                "index_ast_location":rec.get("index_ast_location"),
                "index_eval":rec.get("index_eval"),
            })
        exact=classes["EXACT_SUB_NEG1"]
        nonexact=sum(classes.values())-exact
        site_rows.append({
            **site,
            "matched_unique_framefails":len(records),
            "exact_sub_neg1_records":exact,
            "nonexact_records":nonexact,
            "classification_counts":dict(classes.most_common()),
            "runtime_tuple_counts":dict(tuples.most_common()),
            "all_matched_records_exact_sub_neg1":bool(records) and nonexact==0,
            "records":out_records,
        })

    exact_sites=sum(x["all_matched_records_exact_sub_neg1"] for x in site_rows)
    covered=sum(x["matched_unique_framefails"]>0 for x in site_rows)
    conflicts=sum(x["nonexact_records"]>0 for x in site_rows)
    return {
        "schema":SCHEMA,
        "source_r181f":str(r181f_path),
        "logs":[str(x) for x in logs],
        "checkpoint":r181f["checkpoint"],
        "summary":{
            "cohort_sites":7,
            "sites_with_matched_framefail":covered,
            "sites_all_exact_sub_neg1":exact_sites,
            "sites_with_nonexact_records":conflicts,
            "unique_matched_records":sum(x["matched_unique_framefails"] for x in site_rows),
            "classification_counts":dict(global_classes.most_common()),
            "right_ast_type_counts":dict(right_types.most_common()),
            "runtime_tuple_counts":dict(tuple_counts.most_common()),
            "unmatched_neg1_framefails":unmatched,
        },
        "sites":site_rows,
        "interpretation_gate":{
            "all_seven_sites_have_exact_failure_time_sub_neg1":
                covered==7 and exact_sites==7 and conflicts==0,
            "failure_time_sub_neg1_proves_arithmetic_origin_for_covered_sites":
                covered==7 and exact_sites==7 and conflicts==0,
            "arithmetic_origin_proves_frame_base_bug":False,
            "arithmetic_origin_proves_negative_slot_is_nil":False,
            "experimental_negative_slot_lane_is_accepted_semantics":False,
            "semantic_change_authorized":False,
        },
        "no_live_fetch":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181f",type=Path)
    ap.add_argument("logs",nargs="+",type=Path)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r181f,a.logs)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"]
        print(f"R183A: covered={s['sites_with_matched_framefail']}/7 exact={s['sites_all_exact_sub_neg1']}/7 conflicts={s['sites_with_nonexact_records']}")
        print("classes:",json.dumps(s["classification_counts"],sort_keys=True))
        print("right_types:",json.dumps(s["right_ast_type_counts"],sort_keys=True))
        print("tuples:",json.dumps(s["runtime_tuple_counts"],sort_keys=True))
        print("gate:",out["interpretation_gate"]["all_seven_sites_have_exact_failure_time_sub_neg1"])
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
