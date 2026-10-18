#!/usr/bin/env python3
"""R181E: artifact-only operand-schema census for the seven read/Sub negative-slot sites."""
from __future__ import annotations
import argparse, json, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "luraph-deobf.r181e-sub-operand-schema.v1"
SUFFIX = {".json", ".jsonl", ".log", ".txt", ".md"}
UF = re.compile(r"(?:read|store) below the stack VM's frame \(register (?P<r>-?\d+)\)")
META_KEYS = {"op","repr","text","span","loc","location","line","column","start","end","type","kind","tag"}
LOCAL_FIELDS = ("local_values","carried_locals")

def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

def atom(v):
    if v is None or isinstance(v,bool): return None
    return str(v) if isinstance(v,(str,int)) else None

def numeric(v):
    return None if isinstance(v,bool) else v if isinstance(v,(int,float)) else None

def ident(rec):
    f,s=atom(rec.get("function_id")),atom(rec.get("state_id"))
    return (f,s) if f is not None and s is not None else None

def files(inputs):
    out=[]
    for p in inputs:
        if p.is_file(): out.append(p)
        elif p.is_dir(): out.extend(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in SUFFIX)
        else: raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(out))

def walk_dicts(v,path="$"):
    if isinstance(v,dict):
        yield path,v
        for k,x in v.items(): yield from walk_dicts(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v): yield from walk_dicts(x,f"{path}[{i}]")

def find_named_subtrees(rec,suffix):
    out=[]
    for path,obj in walk_dicts(rec):
        if not isinstance(obj,dict): continue
        for key,value in obj.items():
            if str(key).lower()==suffix.lower():
                out.append((f"{path}.{key}",value))
    seen=set(); uniq=[]
    for path,value in out:
        key=(path,repr(value))
        if key not in seen:
            seen.add(key); uniq.append((path,value))
    return uniq

def json_line(line):
    for i in sorted(x for x in {0,line.find("{"),line.find("[")} if x>=0):
        try: return json.loads(line[i:].strip())
        except json.JSONDecodeError: pass
    return None

def underflow_match(rec,site):
    if ident(rec)!=(site["function_id"],site["state_id"]): return False
    if rec.get("kind") in ("below_stack","below_stack_store"):
        return numeric(rec.get("register"))==-1
    err=rec.get("error") or rec.get("exception")
    if isinstance(err,str):
        m=UF.search(err); return bool(m and int(m.group("r"))==-1)
    return False

def cohort(path,expect=7):
    obj=load(path)
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r181d-index-local-linkage.v2":
        raise ValueError("expected R181D-v2 linkage census")
    cp=obj.get("checkpoint",{}).get("expected",{})
    if (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))!=(78,64,0,594):
        raise ValueError("checkpoint != 78/64/0/594")
    sites=[]; seen=set()
    for rec in obj.get("sites",[]):
        if not isinstance(rec,dict): continue
        if rec.get("operation")!="read" or rec.get("classification")!="NO_LINK": continue
        key=ident(rec)
        if key is None: raise ValueError("read/Sub candidate missing composite identity")
        if key in seen: raise ValueError(f"duplicate read/Sub composite identity: {key}")
        seen.add(key); sites.append(dict(rec,function_id=key[0],state_id=key[1]))
    if len(sites)!=expect:
        raise ValueError(f"expected {expect} read/NO_LINK sites, found {len(sites)}")
    return obj,sites

def matching_records(inputs,sites):
    lookup={(x["function_id"],x["state_id"]):x for x in sites}
    out=defaultdict(list)
    for p in files(inputs):
        if p.suffix.lower()==".json":
            obj=load(p)
            if obj is not None:
                for jp,rec in walk_dicts(obj):
                    key=ident(rec)
                    if key in lookup and underflow_match(rec,lookup[key]):
                        out[key].append((str(p),None,jp,rec))
            continue
        try: lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError: continue
        for line_no,line in enumerate(lines,1):
            obj=json_line(line)
            if obj is None: continue
            for jp,rec in walk_dicts(obj):
                key=ident(rec)
                if key in lookup and underflow_match(rec,lookup[key]):
                    out[key].append((str(p),line_no,jp,rec))
    return out

def node_shape(v):
    if isinstance(v,dict):
        for key in ("op","kind","type","tag"):
            value=v.get(key)
            if isinstance(value,str): return f"{key}:{value}"
        rep=v.get("repr")
        if isinstance(rep,str): return f"repr:{rep[:80]}"
        keys=sorted(str(k) for k in v)
        return "dict{"+",".join(keys[:12])+("..." if len(keys)>12 else "")+"}"
    if isinstance(v,list): return f"list[{len(v)}]"
    if isinstance(v,bool): return f"bool:{v}"
    if v is None: return "null"
    if isinstance(v,(int,float)): return f"number:{v}"
    if isinstance(v,str): return f"str:{v[:80]}"
    return type(v).__name__

def sub_layout(ast_obj):
    if not isinstance(ast_obj,dict) or ast_obj.get("op")!="Sub": return None
    children=[]
    for key,value in ast_obj.items():
        if str(key).lower() in META_KEYS: continue
        children.append({"field":str(key),"shape":node_shape(value),
                         "value":value if isinstance(value,(str,int,float,bool)) or value is None else None})
    return {"child_fields":[x["field"] for x in children],"children":children,
            "repr":ast_obj.get("repr") if isinstance(ast_obj.get("repr"),str) else None}

def scalar_leaves(v,path="$"):
    if isinstance(v,dict):
        for k,x in v.items(): yield from scalar_leaves(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v): yield from scalar_leaves(x,f"{path}[{i}]")
    elif isinstance(v,(str,int,float,bool)) or v is None:
        yield path,v

def local_schema_shapes(rec):
    rows=[]
    for label in LOCAL_FIELDS:
        for path,value in find_named_subtrees(rec,label):
            rows.append({"field":label,"path":path,"shape":node_shape(value)})
    return rows

def analyze(r181d_path,evidence_inputs,expect_cohort=7):
    src,sites=cohort(r181d_path,expect_cohort)
    matches=matching_records(evidence_inputs,sites)
    layout_counts=Counter(); child_field_counts=Counter(); child_shape_counts=Counter(); scalar_path_counts=Counter()
    rows=[]
    for site in sites:
        key=(site["function_id"],site["state_id"]); recs=matches.get(key,[])
        evidence=[]; sub_count=0; site_layouts=Counter()
        for source,line,json_path,rec in recs:
            asts=find_named_subtrees(rec,"index_ast")
            sub_asts=[(p,v) for p,v in asts if isinstance(v,dict) and v.get("op")=="Sub"]
            rec_layouts=[]
            for ap,av in sub_asts:
                layout=sub_layout(av)
                if layout is None: continue
                sub_count+=1; signature=tuple(layout["child_fields"])
                layout_counts[str(signature)]+=1; site_layouts[str(signature)]+=1
                for child in layout["children"]:
                    child_field_counts[child["field"]]+=1
                    child_shape_counts[f"{child['field']}::{child['shape']}"]+=1
                scalars=[]
                for sp,sv in scalar_leaves(av):
                    scalar_path_counts[sp]+=1; scalars.append({"path":sp,"value":sv})
                rec_layouts.append({"path":ap,**layout,"scalar_leaves":scalars})
            evidence.append({"source":source,"line":line,"json_path":json_path,
                             "sub_asts":rec_layouts,"local_schema_shapes":local_schema_shapes(rec)})
        rows.append({"function_id":key[0],"state_id":key[1],"mode":site.get("mode"),"pc":site.get("pc"),
                     "matched_records":len(recs),"sub_ast_instances":sub_count,
                     "sub_layouts":dict(site_layouts.most_common()),"evidence":evidence})
    missing=[(x["function_id"],x["state_id"]) for x in rows if x["sub_ast_instances"]==0]
    if missing: raise ValueError(f"read/NO_LINK site lacks frozen Sub AST evidence: {missing}")
    return {"schema":SCHEMA,"source_r181d":str(r181d_path),"checkpoint":src["checkpoint"],
            "cohort_sites":len(sites),
            "summary":{"sites_with_sub_ast":sum(x["sub_ast_instances"]>0 for x in rows),
                       "sub_ast_instances":sum(x["sub_ast_instances"] for x in rows),
                       "unique_layouts":len(layout_counts),"unique_child_fields":len(child_field_counts),
                       "unique_child_shapes":len(child_shape_counts)},
            "sub_layouts":dict(layout_counts.most_common()),"child_fields":dict(child_field_counts.most_common()),
            "child_shapes":dict(child_shape_counts.most_common()),"scalar_paths":dict(scalar_path_counts.most_common()),
            "sites":sorted(rows,key=lambda x:(x["function_id"],x["state_id"])),
            "interpretation_gate":{"schema_inventory_only":True,"sub_layout_proves_operand_semantics":False,
                                   "scalar_leaf_proves_arithmetic_origin":False,"semantic_change_authorized":False,
                                   "requires_exact_composite_identity":True},
            "no_lift_rerun":True}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181d",type=Path); ap.add_argument("evidence",nargs="+",type=Path)
    ap.add_argument("--expect-cohort",type=int,default=7); ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r181d,a.evidence,a.expect_cohort)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"]
        print(f"R181E: cohort={out['cohort_sites']} sites_with_sub={s['sites_with_sub_ast']} sub_instances={s['sub_ast_instances']}")
        print(f"layouts={s['unique_layouts']} child_fields={s['unique_child_fields']} child_shapes={s['unique_child_shapes']}")
        print("sub_layouts:",json.dumps(out["sub_layouts"],sort_keys=True))
        print("child_fields:",json.dumps(out["child_fields"],sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
