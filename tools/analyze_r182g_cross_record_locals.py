#!/usr/bin/env python3
"""R182G: cross-record provenance census for missing call-local snapshots."""
from __future__ import annotations
import argparse, json, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r182g-cross-record-local-census.v1"
SUFFIX={".json",".jsonl",".log",".txt",".md"}
LOCAL_FIELDS=("local_values","carried_locals")
LOC_KEYS={"location","loc","decl_location","declaration_location","local_location","decl_id","local_id"}

def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8",errors="strict"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError):
        return None

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def ident(rec):
    if not isinstance(rec,dict):return None
    f,s=rec.get("function_id"),rec.get("state_id")
    if isinstance(f,(str,int)) and not isinstance(f,bool) and isinstance(s,(str,int)) and not isinstance(s,bool):
        return (str(f),str(s))
    return None

def files(inputs):
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
            yield from walk_dicts(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v):
            yield from walk_dicts(x,f"{path}[{i}]")

def find_named(rec,name):
    out=[]
    for path,obj in walk_dicts(rec):
        if not isinstance(obj,dict):continue
        for k,v in obj.items():
            if str(k).lower()==name.lower():
                out.append((f"{path}.{k}",v))
    return out

def json_line(line):
    for i in sorted(x for x in {0,line.find("{"),line.find("[")} if x>=0):
        try:return json.loads(line[i:].strip())
        except json.JSONDecodeError:pass
    return None

def canon(v):
    try:return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(",",":"))
    except TypeError:return repr(v)

def equal_atom(a,b):
    return canon(a)==canon(b)

def location_atoms(obj,path="$"):
    out=[]
    if isinstance(obj,dict):
        for k,v in obj.items():
            p=f"{path}.{k}"
            if str(k).lower() in LOC_KEYS and not isinstance(v,(dict,list)):
                out.append({"path":p,"value":v})
            if isinstance(v,(dict,list)):
                out.extend(location_atoms(v,p))
    elif isinstance(obj,list):
        for i,v in enumerate(obj):
            out.extend(location_atoms(v,f"{path}[{i}]"))
    return out

def local_entries(obj,path="$"):
    if isinstance(obj,list):
        # Handle tuple/list-shaped entries conservatively: [name, value].
        if len(obj)==2 and isinstance(obj[0],str) and not isinstance(obj[1],(dict,list)):
            yield {"path":path,"name":obj[0],"value":obj[1],"locations":[],"encoding":"pair"}
            return
        for i,item in enumerate(obj):
            yield from local_entries(item,f"{path}[{i}]")
        return
    if not isinstance(obj,dict):return

    explicit=False
    decl=obj.get("decl")
    if isinstance(decl,dict) and isinstance(decl.get("name"),str) and "value" in decl:
        explicit=True
        yield {"path":f"{path}.decl","name":decl["name"],"value":decl.get("value"),
               "locations":location_atoms(decl,f"{path}.decl"),"encoding":"decl-name-value"}
    elif isinstance(obj.get("name"),str) and "value" in obj:
        explicit=True
        yield {"path":path,"name":obj["name"],"value":obj.get("value"),
               "locations":location_atoms(obj,path),"encoding":"name-value"}

    if not explicit:
        for k,v in obj.items():
            if isinstance(k,str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",k) and not isinstance(v,(dict,list)):
                if k not in {"name","value","location","loc","decl_id","local_id"}:
                    yield {"path":f"{path}.{k}","name":k,"value":v,
                           "locations":[],"encoding":"direct-map"}

    for k,v in obj.items():
        if isinstance(v,(dict,list)):
            if k=="decl" and explicit:continue
            yield from local_entries(v,f"{path}.{k}")

def extract_entries(rec):
    out=[];seen=set()
    for label in LOCAL_FIELDS:
        for path,obj in find_named(rec,label):
            for e in local_entries(obj,path):
                sig=(e["path"],e["name"],canon(e["value"]),e["encoding"])
                if sig not in seen:
                    seen.add(sig);out.append(e)
    return out

def local_event_hits(rec,target_decl):
    hits=[]
    for path,obj in find_named(rec,"local_events"):
        for jp,v in walk_values(obj,path):
            if isinstance(v,list) and len(v)>=2 and v[0] in ("read","write") and equal_atom(v[1],target_decl):
                hits.append({"path":jp,"kind":v[0],"decl":v[1],"raw":v})
            elif isinstance(v,dict):
                kind=v.get("kind",v.get("event",v.get("op")))
                decl=v.get("decl",v.get("decl_location",v.get("key")))
                if kind in ("read","write") and equal_atom(decl,target_decl):
                    hits.append({"path":jp,"kind":kind,"decl":decl,"raw":v})
    return hits

def walk_values(v,path="$"):
    yield path,v
    if isinstance(v,dict):
        for k,x in v.items():yield from walk_values(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v):yield from walk_values(x,f"{path}[{i}]")

def source_locals(instance):
    out={}
    def rec(node):
        if isinstance(node,dict):
            if node.get("type")=="AstExprLocal" and isinstance(node.get("name"),str):
                name=node["name"];decl=node.get("decl")
                if decl is not None:
                    prev=out.get(name)
                    if prev is not None and not equal_atom(prev,decl):
                        raise ValueError(f"source local {name} has multiple decl locations in one call instance")
                    out[name]=decl
            for v in node.values():
                if isinstance(v,(dict,list)):rec(v)
        elif isinstance(node,list):
            for v in node:rec(v)
    rec(instance.get("args",[]))
    return out

def require_e(obj):
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r182e-source-call-arg-recovery.v2":
        raise ValueError("expected R182E-v2 receipt")
    if checkpoint(obj)!=(78,64,0,594):raise ValueError("checkpoint != 78/64/0/594")
    rows=obj.get("instances",[])
    if len(rows)!=41:raise ValueError(f"expected 41 call instances, found {len(rows)}")
    return rows

def collect_records(inputs,ids):
    out=defaultdict(list);seen=set()
    def consume(source,line,obj):
        for jp,rec in walk_dicts(obj):
            key=ident(rec)
            if key not in ids:continue
            sig=(source,line,jp)
            if sig in seen:continue
            seen.add(sig);out[key].append({"source":source,"line":line,"json_path":jp,"record":rec})
    for p in files(inputs):
        if p.suffix.lower()==".json":
            obj=load(p)
            if obj is not None:consume(str(p),None,obj)
            continue
        try:lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError:continue
        for n,line in enumerate(lines,1):
            obj=json_line(line)
            if obj is not None:consume(str(p),n,obj)
    return out

def classify_local(name,decl,recs):
    exact=[];event_name=[];name_only=[];event_hits=[]
    for rr in recs:
        rec=rr["record"];entries=extract_entries(rec);events=local_event_hits(rec,decl)
        if events:event_hits.extend({**x,"source":rr["source"],"line":rr["line"],"json_path":rr["json_path"]} for x in events)
        named=[e for e in entries if e["name"]==name]
        for e in named:
            base={**e,"source":rr["source"],"line":rr["line"],"json_path":rr["json_path"]}
            name_only.append(base)
            if any(equal_atom(loc["value"],decl) for loc in e.get("locations",[])):
                exact.append(base)
            if events:
                event_name.append(base)

    def vals(rows):
        u={}
        for e in rows:u[canon(e["value"])]=e["value"]
        return list(u.values())

    exact_vals=vals(exact);event_vals=vals(event_name);name_vals=vals(name_only)
    if exact:
        cls="EXACT_DECL_UNIQUE" if len(exact_vals)==1 else "EXACT_DECL_CONFLICT"
        chosen=exact_vals[0] if len(exact_vals)==1 else None
    elif event_name:
        cls="EVENT_PLUS_NAME_UNIQUE" if len(event_vals)==1 else "EVENT_PLUS_NAME_CONFLICT"
        chosen=event_vals[0] if len(event_vals)==1 else None
    elif name_only:
        cls="NAME_ONLY_UNIQUE" if len(name_vals)==1 else "NAME_ONLY_CONFLICT"
        chosen=name_vals[0] if len(name_vals)==1 else None
    else:
        cls="NO_VALUE";chosen=None
    return {
        "name":name,"decl":decl,"classification":cls,"chosen_value":chosen,
        "exact_decl_values":exact_vals,"event_plus_name_values":event_vals,"name_only_values":name_vals,
        "exact_entries":exact,"event_plus_name_entries":event_name,"name_only_entries":name_only,
        "local_event_hits":event_hits,
    }

def analyze(e_path,evidence_inputs):
    e=load(e_path);instances=require_e(e)
    ids=set()
    for x in instances:
        fid=x.get("function_id");sid=x.get("state_id")
        if fid is None or sid is None:
            raise ValueError("call instance missing composite identity")
        ids.add((str(fid),str(sid)))
    recs=collect_records(evidence_inputs,ids)
    req_by_id=defaultdict(dict)
    for inst in instances:
        key=(str(inst.get("function_id")),str(inst.get("state_id")))
        for name,decl in source_locals(inst).items():
            prev=req_by_id[key].get(name)
            if prev is not None and not equal_atom(prev,decl):
                raise ValueError(f"same composite identity has conflicting source decl for {name}")
            req_by_id[key][name]=decl

    state_rows=[];classes=Counter();name_classes=defaultdict(Counter)
    for key in sorted(ids):
        locals_out={}
        for name,decl in sorted(req_by_id[key].items()):
            row=classify_local(name,decl,recs.get(key,[]))
            locals_out[name]=row;classes[row["classification"]]+=1;name_classes[name][row["classification"]]+=1
        state_rows.append({"function_id":key[0],"state_id":key[1],
                           "matched_records":len(recs.get(key,[])),"locals":locals_out})

    # Project each recovered instance onto its composite-state census without claiming timing.
    inst_rows=[]
    for inst in instances:
        key=(str(inst.get("function_id")),str(inst.get("state_id")))
        state=next(x for x in state_rows if (x["function_id"],x["state_id"])==key)
        inst_rows.append({"instance_index":inst.get("instance_index"),"function_id":key[0],"state_id":key[1],
                          "locals":{n:{"classification":v["classification"],"chosen_value":v["chosen_value"],"decl":v["decl"]}
                                    for n,v in state["locals"].items()}})
    return {
        "schema":SCHEMA,"source_r182e":str(e_path),"checkpoint":e["checkpoint"],
        "summary":{"call_instances":41,"unique_composite_states":len(ids),
                   "matched_states":sum(bool(recs.get(k)) for k in ids),
                   "classification_counts":dict(classes.most_common())},
        "by_local":{n:dict(c.most_common()) for n,c in sorted(name_classes.items())},
        "states":state_rows,"instances":inst_rows,
        "interpretation_gate":{
            "exact_decl_unique_is_failure_time_value":False,
            "event_plus_name_unique_is_exact_decl_value":False,
            "name_only_unique_is_decl_proof":False,
            "cross_record_value_is_timing_proof":False,
            "candidate_evaluation_authorized":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,"no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r182e",type=Path);ap.add_argument("evidence",nargs="+",type=Path)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r182e,a.evidence)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"]
        print(f"R182G: calls={s['call_instances']} states={s['unique_composite_states']} matched_states={s['matched_states']}")
        print("classes:",json.dumps(s["classification_counts"],sort_keys=True))
        print("by_local:",json.dumps(out["by_local"],sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
