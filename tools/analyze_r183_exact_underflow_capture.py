#!/usr/bin/env python3
"""R183A-v2: exact failure-time Sub operands with accepted-baseline location gate."""
from __future__ import annotations
import argparse,json,re
from collections import Counter,defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r183a-exact-sub-operands.v2"
FRAME_MARK="[FRAMEFAIL]"
ERR_RE=re.compile(r'read below the stack VM\'s frame \(register -1\) \(at (?P<mode>-?\d+):(?P<pc>-?\d+)\)')
SOURCE_SHA="02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"
OUTPUT_SHA="a26d509d79dfbc8cd41c0d751707f6fff3689d36fc193cc3de15e418d2c24075"

def load(path): return json.loads(Path(path).read_text(encoding="utf-8"))

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def require_r181f(obj):
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r181f-local-identity-rhs-census.v1":
        raise ValueError("expected R181F receipt")
    if checkpoint(obj)!=(78,64,0,594):
        raise ValueError("R181F checkpoint != 78/64/0/594")
    rows=[]
    seen=set()
    for x in obj.get("sites",[]):
        if not isinstance(x,dict) or x.get("operation")!="read": continue
        fid,sid=x.get("function_id"),x.get("state_id")
        if fid is None or sid is None: raise ValueError("R181F site missing composite identity")
        key=(str(fid),str(sid))
        if key in seen: raise ValueError(f"duplicate R181F composite site {key}")
        seen.add(key)
        rows.append({"function_id":key[0],"state_id":key[1],"mode":x.get("mode"),"pc":x.get("pc"),
                     "sub_instances":x.get("sub_instances")})
    if len(rows)!=7: raise ValueError(f"expected 7 R181F read/Sub sites, found {len(rows)}")
    mp={}
    complete=True
    for x in rows:
        if x["mode"] is None or x["pc"] is None:
            complete=False; continue
        k=(x["mode"],x["pc"])
        if k in mp: raise ValueError(f"R181F mode/pc collision {k}")
        mp[k]=(x["function_id"],x["state_id"])
    if complete and len(mp)!=7: raise ValueError("R181F complete mode/pc mapping is not 7 unique sites")
    return rows,mp if complete else None

def require_baseline(obj):
    if not isinstance(obj,dict): raise ValueError("baseline summary is not an object")
    st=obj.get("stats")
    if not isinstance(st,dict): raise ValueError("baseline stats is not an object")
    got=(st.get("functions"),st.get("errors"),st.get("fallbacks"),obj.get("requests"))
    if got!=(78,64,0,594): raise ValueError(f"baseline checkpoint mismatch: {got}")
    if obj.get("source_sha256")!=SOURCE_SHA: raise ValueError("baseline source SHA mismatch")
    if obj.get("output_sha256")!=OUTPUT_SHA: raise ValueError("baseline output SHA mismatch")
    locs=[]
    for err in obj.get("errors",[]):
        m=ERR_RE.search(str(err))
        if m: locs.append((int(m.group("mode")),int(m.group("pc"))))
    counts=Counter(locs)
    uniq=sorted(counts)
    if len(uniq)!=7:
        raise ValueError(f"baseline must contain exactly 7 unique read/-1 locations, got {len(locs)}/{len(uniq)}")
    # Duplicate serialization of the same accepted error does not create a
    # second site.  Preserve multiplicity for audit and require every duplicate
    # to normalize to one of the same seven exact (mode,pc) identities.
    multiplicity={f"{m}:{p}":counts[(m,p)] for m,p in uniq}
    return uniq,multiplicity

def numeric(v):
    if not isinstance(v,dict): return None
    x=v.get("value")
    if isinstance(x,bool) or not isinstance(x,(int,float)): return None
    return x

def parse_framefails(paths):
    out=[]
    for p in paths:
        if not p.is_file(): continue
        for n,line in enumerate(p.read_text(encoding="utf-8",errors="replace").splitlines(),1):
            pos=line.find(FRAME_MARK)
            if pos<0: continue
            try: rec=json.loads(line[pos+len(FRAME_MARK):].strip())
            except json.JSONDecodeError: continue
            if isinstance(rec,dict): out.append({"source":str(p),"line":n,"record":rec})
    return out

def classify(rec):
    ia,ie=rec.get("index_ast"),rec.get("index_eval")
    if not isinstance(ia,dict) or ia.get("type")!="AstExprBinary" or ia.get("op")!="Sub":
        return "NOT_SUB_AST",None
    if not isinstance(ie,dict) or ie.get("op")!="Sub":
        return "NO_EXACT_SUB_EVAL",None
    left,right,result=numeric(ie.get("left")),numeric(ie.get("right")),numeric(ie.get("result"))
    vals={"left":left,"right":right,"result":result}
    if None in (left,right,result): return "NONNUMERIC_SUB_EVAL",vals
    if left-right!=result: return "ARITHMETIC_MISMATCH",vals
    if result==-1 and rec.get("register")==-1 and rec.get("stack_base")==1:
        return "EXACT_SUB_NEG1",vals
    return "EXACT_SUB_OTHER",vals

def dedupe(rows):
    out=[];seen=set()
    for x in rows:
        r=x["record"]
        sig=json.dumps({"mode":r.get("mode"),"pc":r.get("pc"),"kind":r.get("kind"),
          "register":r.get("register"),"stack_base":r.get("stack_base"),
          "proto_tid":r.get("proto_tid"),"vm_tag":r.get("vm_tag"),
          "index_ast":r.get("index_ast"),"index_eval":r.get("index_eval")},
          sort_keys=True,ensure_ascii=False,default=repr)
        if sig not in seen: seen.add(sig);out.append(x)
    return out

def analyze(r181f_path,baseline_path,logs):
    r181f=load(r181f_path); sites,canonical_mp=require_r181f(r181f)
    baseline=load(baseline_path); baseline_locs,baseline_multiplicity=require_baseline(baseline)
    raw=parse_framefails(logs)
    by_loc=defaultdict(list);extra=[]
    for x in raw:
        rec=x["record"]
        if rec.get("kind")!="below_stack" or rec.get("register")!=-1 or rec.get("stack_base")!=1: continue
        if not isinstance(rec.get("mode"),int) or not isinstance(rec.get("pc"),int):
            extra.append({**x,"reason":"MISSING_MODE_PC"}); continue
        loc=(rec["mode"],rec["pc"])
        if loc in baseline_locs: by_loc[loc].append(x)
        else: extra.append({**x,"reason":"LOCATION_OUTSIDE_ACCEPTED_BASELINE"})

    rows=[];classes=Counter();right_types=Counter();tuples=Counter()
    for loc in baseline_locs:
        rs=dedupe(by_loc.get(loc,[])); cc=Counter(); recs=[]
        for x in rs:
            rec=x["record"]; cls,vals=classify(rec);cc[cls]+=1;classes[cls]+=1
            ia=rec.get("index_ast") or {}
            rt=(ia.get("right") or {}).get("type") if isinstance(ia.get("right"),dict) else None
            if rt:right_types[rt]+=1
            if vals and None not in (vals["left"],vals["right"],vals["result"]):
                tuples[f'{vals["left"]}|{vals["right"]}|{vals["result"]}']+=1
            recs.append({"source":x["source"],"line":x["line"],"classification":cls,"values":vals,
                         "proto_tid":rec.get("proto_tid"),"vm_tag":rec.get("vm_tag"),
                         "right_ast_type":rt,"index_ast_location":rec.get("index_ast_location"),
                         "index_eval":rec.get("index_eval")})
        exact=cc["EXACT_SUB_NEG1"];nonexact=sum(cc.values())-exact
        row={"mode":loc[0],"pc":loc[1],"matched_unique_framefails":len(rs),
             "exact_sub_neg1_records":exact,"nonexact_records":nonexact,
             "all_matched_records_exact_sub_neg1":bool(rs) and nonexact==0,
             "classification_counts":dict(cc.most_common()),"records":recs}
        if canonical_mp is not None:
            fid,sid=canonical_mp[loc];row["function_id"]=fid;row["state_id"]=sid
        rows.append(row)

    covered=sum(x["matched_unique_framefails"]>0 for x in rows)
    exact=sum(x["all_matched_records_exact_sub_neg1"] for x in rows)
    conflicts=sum(x["nonexact_records"]>0 for x in rows)
    location_gate=(covered==7 and exact==7 and conflicts==0 and len(extra)==0)
    canonical_available=canonical_mp is not None
    canonical_gate=bool(location_gate and canonical_available)
    return {
      "schema":SCHEMA,"source_r181f":str(r181f_path),"source_baseline_summary":str(baseline_path),
      "logs":[str(x) for x in logs],"checkpoint":r181f["checkpoint"],
      "accepted_baseline":{"source_sha256":SOURCE_SHA,"output_sha256":OUTPUT_SHA,
                           "read_neg1_locations":[{"mode":m,"pc":p} for m,p in baseline_locs],
                           "read_neg1_location_multiplicity":baseline_multiplicity,
                           "serialized_read_neg1_rows":sum(baseline_multiplicity.values()),
                           "unique_read_neg1_locations":len(baseline_locs)},
      "summary":{"cohort_sites":7,"sites_with_matched_framefail":covered,
                 "sites_all_exact_sub_neg1":exact,"sites_with_nonexact_records":conflicts,
                 "extra_read_neg1_framefails":len(extra),
                 "unique_matched_records":sum(x["matched_unique_framefails"] for x in rows),
                 "classification_counts":dict(classes.most_common()),
                 "right_ast_type_counts":dict(right_types.most_common()),
                 "runtime_tuple_counts":dict(tuples.most_common())},
      "sites":rows,"extra_framefails":extra,
      "identity_join":{"canonical_mode_pc_available":canonical_available,
                       "canonical_composite_join_proved":canonical_gate,
                       "r181f_sites":[{"function_id":x["function_id"],"state_id":x["state_id"],
                                      "mode":x["mode"],"pc":x["pc"]} for x in sites]},
      "interpretation_gate":{
        "exact_accepted_location_gate_for_diagnostic_experiment":location_gate,
        "canonical_composite_identity_gate":canonical_gate,
        "failure_time_sub_neg1_proved_at_all_accepted_locations":location_gate,
        "failure_time_sub_neg1_proved_for_all_canonical_sites":canonical_gate,
        "location_gate_authorizes_permanent_semantic_change":False,
        "arithmetic_origin_proves_frame_base_bug":False,
        "arithmetic_origin_proves_negative_slot_is_nil":False,
        "experimental_negative_slot_lane_is_accepted_semantics":False,
        "semantic_change_authorized":False},
      "no_live_fetch":True}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181f",type=Path);ap.add_argument("baseline_summary",type=Path)
    ap.add_argument("logs",nargs="+",type=Path);ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r181f,a.baseline_summary,a.logs)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"];g=out["interpretation_gate"]
        print(f"R183A-v2: covered={s['sites_with_matched_framefail']}/7 exact={s['sites_all_exact_sub_neg1']}/7 conflicts={s['sites_with_nonexact_records']} extra={s['extra_read_neg1_framefails']}")
        print("diagnostic_gate:",g["exact_accepted_location_gate_for_diagnostic_experiment"])
        print("canonical_gate:",g["canonical_composite_identity_gate"])
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc
if __name__=="__main__": raise SystemExit(main())
