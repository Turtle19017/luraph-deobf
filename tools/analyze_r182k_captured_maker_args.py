#!/usr/bin/env python3
"""R182K: join frozen proto identity to captured maker arguments and resolve base parameter paths."""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r182k-captured-maker-arg-join.v1"
SUFFIX={".json",".jsonl",".log",".txt",".md"}

def load(path):
    try:return json.loads(Path(path).read_text(encoding="utf-8",errors="strict"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError):return None

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()

def require_schema(obj,schema,name):
    if not isinstance(obj,dict) or obj.get("schema")!=schema:
        raise ValueError(f"expected {name} schema {schema}")
    if checkpoint(obj)!=(78,64,0,594):
        raise ValueError(f"{name} checkpoint != 78/64/0/594")
    return obj

def evidence_files(inputs):
    out=[]
    for p in inputs:
        if p.is_file():out.append(p)
        elif p.is_dir():out.extend(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in SUFFIX)
        else:raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(x.resolve() for x in out))

def walk_dicts(v,path="$"):
    if isinstance(v,dict):
        yield path,v
        for k,x in v.items():
            if isinstance(x,(dict,list)):yield from walk_dicts(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v):yield from walk_dicts(x,f"{path}[{i}]")

def atom(v):
    if v is None or isinstance(v,bool):return None
    return str(v) if isinstance(v,(str,int)) else None

def ident(rec):
    if not isinstance(rec,dict):return None
    f,s=atom(rec.get("function_id")),atom(rec.get("state_id"))
    return (f,s) if f is not None and s is not None else None

def json_line(line):
    for i in sorted(x for x in {0,line.find("{"),line.find("[")} if x>=0):
        try:return json.loads(line[i:].strip())
        except json.JSONDecodeError:pass
    return None

def scalar_candidates(rec,field,root_ident):
    out=[]
    def walk(v,path="$",is_root=False):
        if isinstance(v,dict):
            here=ident(v)
            if not is_root and here is not None and here!=root_ident:
                return
            if field in v and isinstance(v[field],(str,int)) and not isinstance(v[field],bool):
                out.append({"path":f"{path}.{field}","value":v[field]})
            for k,x in v.items():
                if isinstance(x,(dict,list)):walk(x,f"{path}.{k}",False)
        elif isinstance(v,list):
            for i,x in enumerate(v):walk(x,f"{path}[{i}]",False)
    walk(rec,"$",True)
    return out

def scan_state_proto_meta(inputs,state_ids):
    rows=defaultdict(list);seen=set()
    def consume(source,line,obj):
        for jp,rec in walk_dicts(obj):
            key=ident(rec)
            if key not in state_ids:continue
            proto=scalar_candidates(rec,"proto_tid",key)
            vm=scalar_candidates(rec,"vm_tag",key)
            if not proto and not vm:continue
            sig=(source,line,jp)
            if sig in seen:continue
            seen.add(sig)
            rows[key].append({"source":source,"line":line,"json_path":jp,
                              "proto_tid_candidates":proto,"vm_tag_candidates":vm})
    for p in evidence_files(inputs):
        if p.suffix.lower()==".json":
            obj=load(p)
            if obj is not None:consume(str(p),None,obj)
            continue
        try:lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError:continue
        for n,line in enumerate(lines,1):
            obj=json_line(line)
            if obj is not None:consume(str(p),n,obj)
    return rows

def unique_field(records,field):
    vals={}
    evidence=[]
    for r in records:
        for hit in r[field]:
            v=hit["value"]
            vals[str(v)]=v
            evidence.append({**hit,"source":r["source"],"line":r["line"],"json_path":r["json_path"]})
    if len(vals)==1:return next(iter(vals.values())),evidence
    return None,evidence

def selected_protos(r182c):
    sel=r182c.get("selected_base_snapshot") or {}
    p=Path(sel.get("path",""))
    sha=sel.get("sha256")
    if not p.is_file():raise ValueError(f"selected protos file not found: {p}")
    got=sha256_file(p)
    if not isinstance(sha,str) or got.lower()!=sha.lower():
        raise ValueError(f"selected protos SHA mismatch: got {got}, expected {sha}")
    return sel,p

def r182j_roles(obj):
    params={x.get("name"):x for x in obj.get("parameters",[]) if isinstance(x,dict)}
    if set(("B","c"))-set(params):raise ValueError("R182J-v2 missing B/c parameters")
    B,c=params["B"],params["c"]
    br=B.get("maker_role") or {};cr=c.get("maker_role") or {}
    if br.get("role")!="VMOBJ" or cr.get("role")!="PROTO":
        raise ValueError(f"unexpected maker roles B={br.get('role')!r} c={cr.get('role')!r}")
    if br.get("maker_function_location")!=cr.get("maker_function_location"):
        raise ValueError("B/c maker locations differ")
    if br.get("param_index")!=0 or cr.get("param_index")!=cr.get("proto_index"):
        raise ValueError("B/c maker indices do not satisfy VMOBJ/PROTO roles")
    return br.get("maker_function_location"),br,cr

def extract_boundary_paths(r182i):
    rows={x.get("name"):x for x in r182i.get("roots",[]) if isinstance(x,dict)}
    out={}
    for root_name in ("r","K","h"):
        if root_name not in rows:raise ValueError(f"R182I missing root {root_name}")
        res=rows[root_name].get("resolution") or {}
        # For a direct indexed expression whose base stopped at a parameter,
        # R182I records root_name/root_decl/index_path at the failing index node.
        path=res.get("index_path")
        root=res.get("root_name")
        if not isinstance(path,list) or not path:
            raise ValueError(f"R182I root {root_name} lacks constant index_path")
        if root not in ("B","c"):
            raise ValueError(f"R182I root {root_name} unexpected parameter root {root!r}")
        out[root_name]={"parameter":root,"path":path,"resolution":res}
    if out["r"]["parameter"]!="B" or out["K"]["parameter"]!="c" or out["h"]["parameter"]!="c":
        raise ValueError("R182I parameter roots do not match R182J roles")
    return out

def state_ids_from_r182e(obj):
    ids={(str(x.get("function_id")),str(x.get("state_id"))) for x in obj.get("instances",[])
         if isinstance(x,dict) and x.get("function_id") is not None and x.get("state_id") is not None}
    if len(ids)!=2:raise ValueError(f"expected 2 composite states from R182E-v2, found {len(ids)}")
    return ids

def build_program(source_path,protos_path):
    core=Path(__file__).resolve().parents[1]/"core"
    if str(core) not in sys.path:sys.path.insert(0,str(core))
    from obfuscators.luraph_v15 import devirt as D
    return D.Program(str(source_path),str(protos_path)),D

def summarize_value(v,D):
    S=D.S
    if v is None or isinstance(v,(bool,int,float,str)):
        return {"kind":"scalar","value":v}
    if isinstance(v,bytes):
        return {"kind":"bytes","hex":v.hex(),"length":len(v)}
    if isinstance(v,S.Builtin):
        return {"kind":"builtin","name":v.name,"repr":repr(v)}
    if isinstance(v,S.LTable):
        return {"kind":"table","tid":v.tid,"repr":repr(v),"entry_count":len(v.h),
                "key_preview":[repr(k) for k in list(v.h.keys())[:32]]}
    if isinstance(v,D.OpaqueFn):
        return {"kind":"opaque-function","lfid":v.lfid,"pf_tid":v.pf_tid,
                "node_location":v.node.get("location") if isinstance(v.node,dict) else None}
    return {"kind":"other","type":type(v).__name__,"repr":repr(v)[:500]}

def lookup_path(root,path,dump,D):
    S=D.S
    cur=root;steps=[]
    for raw_key in path:
        key=raw_key.encode("latin-1") if isinstance(raw_key,str) else raw_key
        if not isinstance(cur,S.LTable):
            return {"status":"UNRESOLVED","reason":"BASE_NOT_TABLE","steps":steps,
                    "remaining_path":path[len(steps):],"base":summarize_value(cur,D)}
        tid=cur.tid
        nk=S.norm_key(key)
        late=(tid,nk) in dump.late if tid is not None else False
        base=cur.h.get(nk)
        step={"table_tid":tid,"key":raw_key,"late":late,
              "base_present":nk in cur.h,
              "base_value":summarize_value(base,D) if nk in cur.h else None}
        steps.append(step)
        if late:
            return {"status":"UNRESOLVED","reason":"CAPTURED_PATH_KEY_IS_LATE","steps":steps}
        if nk not in cur.h:
            return {"status":"UNRESOLVED","reason":"CAPTURED_PATH_KEY_MISSING","steps":steps}
        cur=base
    return {"status":"VALUE","value":summarize_value(cur,D),"steps":steps,
            "provenance":"CAPTURED_BASE_PARAMETER_PATH"}

def capture_candidates(prog,maker_location,proto_tid,D):
    out=[]
    for cap_key,cap in prog.dump.protos.items():
        try:vm=prog.vm_of(cap)
        except Exception:continue
        if vm.maker.get("location")!=maker_location:continue
        try:proto=vm.proto_of(cap);vmobj=vm.vmobj_of(cap)
        except Exception:continue
        ptid=getattr(proto,"tid",None)
        if ptid!=proto_tid:continue
        out.append({"cap_key":cap_key,"vm":vm,"cap":cap,"proto":proto,"vmobj":vmobj,
                    "vm_tag":getattr(vm,"tag",None),
                    "proto_tid":ptid,
                    "proto_pid":prog.dump.pid_of_table.get(ptid)})
    return out

def analyze(c_path,i_path,j_path,e_path,source_path,evidence,expect_source_sha):
    c=require_schema(load(c_path),"luraph-deobf.r182c-base-sub-consistency.v1","R182C")
    i=require_schema(load(i_path),"luraph-deobf.r182i-static-path-resolution.v1","R182I")
    j=require_schema(load(j_path),"luraph-deobf.r182j-parameter-provenance-census.v2","R182J-v2")
    e=require_schema(load(e_path),"luraph-deobf.r182e-source-call-arg-recovery.v2","R182E-v2")
    if sha256_file(source_path).lower()!=expect_source_sha.lower():
        raise ValueError("source SHA-256 mismatch")
    sel,protos_path=selected_protos(c)
    maker_location,bro,cr=r182j_roles(j)
    paths=extract_boundary_paths(i)
    states=state_ids_from_r182e(e)
    meta=scan_state_proto_meta(evidence,states)

    prog,D=build_program(source_path,protos_path)
    state_rows=[];resolved_caps={}
    for key in sorted(states):
        recs=meta.get(key,[])
        ptid_raw,ptid_ev=unique_field(recs,"proto_tid_candidates")
        vmtag,vmtag_ev=unique_field(recs,"vm_tag_candidates")
        try:ptid=int(ptid_raw) if ptid_raw is not None else None
        except (TypeError,ValueError):ptid=None
        row={"function_id":key[0],"state_id":key[1],"matched_meta_records":len(recs),
             "proto_tid":ptid,"vm_tag":vmtag,
             "proto_tid_evidence":ptid_ev,"vm_tag_evidence":vmtag_ev}
        if ptid is None:
            row["classification"]="PROTO_TID_UNRESOLVED"
        else:
            caps=capture_candidates(prog,maker_location,ptid,D)
            row["capture_candidates"]=[{"cap_key":x["cap_key"],"vm_tag":x["vm_tag"],
                                         "proto_tid":x["proto_tid"],"proto_pid":x["proto_pid"]}
                                        for x in caps]
            if vmtag is not None:
                exact=[x for x in caps if x["vm_tag"]==vmtag]
                if exact:caps=exact
            if len(caps)==1:
                x=caps[0];row["classification"]="UNIQUE_CAPTURE_JOIN"
                row["selected_capture"]={"cap_key":x["cap_key"],"vm_tag":x["vm_tag"],
                                          "proto_tid":x["proto_tid"],"proto_pid":x["proto_pid"]}
                resolved_caps[key]=x
            elif not caps:row["classification"]="NO_CAPTURE_JOIN"
            else:row["classification"]="AMBIGUOUS_CAPTURE_JOIN"
        state_rows.append(row)

    # Resolve roots per unique capture; same capture may serve both states.
    cap_results={}
    for key,x in resolved_caps.items():
        cid=(str(x["cap_key"]),x["proto_tid"],x["vm_tag"])
        if cid in cap_results:continue
        vals={}
        for root_name,spec in paths.items():
            base=x["vmobj"] if spec["parameter"]=="B" else x["proto"]
            vals[root_name]={"parameter_role":"VMOBJ" if spec["parameter"]=="B" else "PROTO",
                             "path":spec["path"],
                             "result":lookup_path(base,spec["path"],prog.dump,D)}
        cap_results[cid]={"cap_key":x["cap_key"],"vm_tag":x["vm_tag"],"proto_tid":x["proto_tid"],
                          "proto_pid":x["proto_pid"],
                          "vmobj":summarize_value(x["vmobj"],D),
                          "proto":summarize_value(x["proto"],D),
                          "roots":vals}

    root_classes=Counter()
    for x in cap_results.values():
        for r in x["roots"].values():
            root_classes[r["result"]["status"]]+=1
    return {
        "schema":SCHEMA,
        "sources":{"r182c":str(c_path),"r182i":str(i_path),"r182j":str(j_path),
                   "r182e":str(e_path),"source":str(source_path),"protos":str(protos_path)},
        "checkpoint":c["checkpoint"],"source_sha256":expect_source_sha,
        "selected_protos":{"path":str(protos_path),"sha256":sel.get("sha256")},
        "maker":{"location":maker_location,"B_role":bro,"c_role":cr},
        "boundary_paths":paths,
        "summary":{"composite_states":len(states),
                   "states_with_unique_capture_join":sum(x["classification"]=="UNIQUE_CAPTURE_JOIN" for x in state_rows),
                   "unique_capture_values":len(cap_results),
                   "root_result_counts":dict(root_classes.most_common())},
        "states":state_rows,
        "captures":list(cap_results.values()),
        "interpretation_gate":{
            "capture_join_is_failure_time_parameter_value":False,
            "captured_base_path_is_failure_time_value":False,
            "dump_proto_is_runtime_proto_identity_candidate":True,
            "vmobj_role_is_semantic_not_timing_proof":True,
            "per_state_overlay_applied":False,
            "late_values_replayed":False,
            "candidate_evaluation_authorized":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,"no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r182c",type=Path);ap.add_argument("r182i",type=Path)
    ap.add_argument("r182j",type=Path);ap.add_argument("r182e",type=Path)
    ap.add_argument("source",type=Path);ap.add_argument("evidence",nargs="+",type=Path)
    ap.add_argument("--expect-source-sha256",required=True)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r182c,a.r182i,a.r182j,a.r182e,a.source,a.evidence,a.expect_source_sha256)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        print("R182K:",json.dumps(out["summary"],sort_keys=True))
        for st in out["states"]:
            print(f"state {st['function_id']}::{st['state_id']}: {st['classification']} proto_tid={st.get('proto_tid')} vm_tag={st.get('vm_tag')}")
        for cap in out["captures"]:
            print("capture",cap["cap_key"],"proto_tid",cap["proto_tid"],"pid",cap["proto_pid"])
            for name,row in cap["roots"].items():
                print(" ",name,row["parameter_role"],row["path"],json.dumps(row["result"],sort_keys=True,ensure_ascii=False))
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
