#!/usr/bin/env python3
"""R182H: static source declaration/write provenance for the missing bxor locals."""
from __future__ import annotations
import argparse, hashlib, json, sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r182h-source-local-provenance.v1"
TARGET_NAMES=("K","W","f","h","r")

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def parse_loc(loc):
    if not isinstance(loc,str) or " - " not in loc:return None
    try:
        a,b=loc.split(" - ",1)
        l1,c1=map(int,a.split(","))
        l2,c2=map(int,b.split(","))
        return (l1,c1,l2,c2)
    except Exception:
        return None

def compact(node,depth=0,max_depth=6):
    if not isinstance(node,dict):
        if isinstance(node,list):return [compact(x,depth+1,max_depth) for x in node]
        return node
    out={"type":node.get("type"),"location":node.get("location")}
    if depth>=max_depth:
        out["cut"]=True;return out
    t=node.get("type")
    if t=="AstExprLocal":
        local=node.get("local") or {}
        out["name"]=local.get("name")
        out["decl"]=local.get("location")
    elif t=="AstExprGlobal":
        out["global"]=node.get("global")
    elif t in ("AstExprConstantNumber","AstExprConstantString","AstExprConstantBool"):
        out["value"]=node.get("value")
    elif t=="AstExprConstantNil":
        out["value"]=None
    elif t in ("AstExprGroup","AstExprTypeAssertion"):
        out["expr"]=compact(node.get("expr"),depth+1,max_depth)
    elif t=="AstExprIndexExpr":
        out["expr"]=compact(node.get("expr"),depth+1,max_depth)
        out["index"]=compact(node.get("index"),depth+1,max_depth)
    elif t=="AstExprIndexName":
        out["expr"]=compact(node.get("expr"),depth+1,max_depth)
        out["index"]=node.get("index");out["op"]=node.get("op")
    elif t=="AstExprCall":
        args=node.get("args") or []
        out["func"]=compact(node.get("func"),depth+1,max_depth)
        out["argc"]=len(args)
        out["args"]=[compact(x,depth+1,max_depth) for x in args]
    elif t=="AstExprBinary":
        out["op"]=node.get("op")
        out["left"]=compact(node.get("left"),depth+1,max_depth)
        out["right"]=compact(node.get("right"),depth+1,max_depth)
    elif t=="AstExprUnary":
        out["op"]=node.get("op")
        out["expr"]=compact(node.get("expr"),depth+1,max_depth)
    elif t=="AstExprFunction":
        out["argc"]=len(node.get("args") or [])
    return out

def source_local_decls(instance):
    out={}
    def rec(v):
        if isinstance(v,dict):
            if v.get("type")=="AstExprLocal" and isinstance(v.get("name"),str) and v.get("decl") is not None:
                name=v["name"];decl=v["decl"]
                prev=out.get(name)
                if prev is not None and prev!=decl:
                    raise ValueError(f"recovered call contains multiple decls for local {name}")
                out[name]=decl
            for x in v.values():
                if isinstance(x,(dict,list)):rec(x)
        elif isinstance(v,list):
            for x in v:rec(x)
    rec(instance.get("args",[]))
    return out

def require_e(obj):
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r182e-source-call-arg-recovery.v2":
        raise ValueError("expected R182E-v2 receipt")
    if checkpoint(obj)!=(78,64,0,594):raise ValueError("checkpoint != 78/64/0/594")
    rows=obj.get("instances",[])
    if len(rows)!=41:raise ValueError(f"expected 41 call instances, found {len(rows)}")
    locs={x.get("call_location") for x in rows}
    if len(locs)!=1 or None in locs:
        raise ValueError(f"expected exactly one recovered call location, found {len(locs)}")
    return rows,next(iter(locs))

def parse_source(path,expect_sha):
    raw=Path(path).read_bytes()
    got=sha256_bytes(raw)
    if got.lower()!=expect_sha.lower():
        raise ValueError(f"source SHA-256 mismatch: got {got}, expected {expect_sha}")
    core=Path(__file__).resolve().parents[1]/"core"
    if str(core) not in sys.path:sys.path.insert(0,str(core))
    import luauast
    return got,luauast.parse(raw.decode("latin-1"))

def local_decl_of_expr(expr):
    if isinstance(expr,dict) and expr.get("type")=="AstExprLocal":
        local=expr.get("local") or {}
        return local.get("location")
    return None

def walk_source(root):
    declarations=defaultdict(list)
    writes=defaultdict(list)
    uses=defaultdict(list)
    calls=defaultdict(list)

    def walk(v,path="$",fn_stack=()):
        if isinstance(v,list):
            for i,x in enumerate(v):walk(x,f"{path}[{i}]",fn_stack)
            return
        if not isinstance(v,dict):return
        t=v.get("type")
        stack=fn_stack
        if t=="AstExprFunction":
            stack=fn_stack+(v.get("location"),)
            for pos,a in enumerate(v.get("args") or []):
                declarations[a.get("location")].append({
                    "kind":"PARAMETER","name":a.get("name"),"decl":a.get("location"),
                    "owner_function":v.get("location"),"path":f"{path}.args[{pos}]",
                    "statement_location":None,"initializer":None,"initializer_count":0,
                })
        if t=="AstStatLocal":
            vals=v.get("values") or [];vars_=v.get("vars") or []
            for pos,a in enumerate(vars_):
                init=vals[pos] if pos<len(vals) else None
                declarations[a.get("location")].append({
                    "kind":"LOCAL","name":a.get("name"),"decl":a.get("location"),
                    "owner_function":stack[-1] if stack else None,"path":f"{path}.vars[{pos}]",
                    "statement_location":v.get("location"),
                    "initializer":compact(init) if init is not None else None,
                    "initializer_count":1 if init is not None else 0,
                    "parallel_value_count":len(vals),"parallel_var_count":len(vars_),
                })
        elif t=="AstStatLocalFunction":
            a=v.get("name") or {}
            declarations[a.get("location")].append({
                "kind":"LOCAL_FUNCTION","name":a.get("name"),"decl":a.get("location"),
                "owner_function":stack[-1] if stack else None,"path":f"{path}.name",
                "statement_location":v.get("location"),
                "initializer":compact(v.get("func")),"initializer_count":1,
            })
        elif t=="AstStatFor":
            a=v.get("var") or {}
            declarations[a.get("location")].append({
                "kind":"FOR_VARIABLE","name":a.get("name"),"decl":a.get("location"),
                "owner_function":stack[-1] if stack else None,"path":f"{path}.var",
                "statement_location":v.get("location"),"initializer":None,"initializer_count":0,
            })
        elif t=="AstStatForIn":
            for pos,a in enumerate(v.get("vars") or []):
                declarations[a.get("location")].append({
                    "kind":"FORIN_VARIABLE","name":a.get("name"),"decl":a.get("location"),
                    "owner_function":stack[-1] if stack else None,"path":f"{path}.vars[{pos}]",
                    "statement_location":v.get("location"),"initializer":None,"initializer_count":0,
                })

        if t=="AstStatAssign":
            vals=v.get("values") or []
            for pos,target in enumerate(v.get("vars") or []):
                decl=local_decl_of_expr(target)
                if decl is not None:
                    writes[decl].append({
                        "kind":"ASSIGN","path":f"{path}.vars[{pos}]","statement_location":v.get("location"),
                        "owner_function":stack[-1] if stack else None,
                        "rhs":compact(vals[pos]) if pos<len(vals) else None,
                        "rhs_count":len(vals),"target_count":len(v.get("vars") or []),
                    })
        elif t=="AstStatCompoundAssign":
            target=v.get("var");decl=local_decl_of_expr(target)
            if decl is not None:
                writes[decl].append({
                    "kind":"COMPOUND_ASSIGN","path":f"{path}.var","statement_location":v.get("location"),
                    "owner_function":stack[-1] if stack else None,
                    "op":v.get("op"),"rhs":compact(v.get("value")),
                })

        if t=="AstExprLocal":
            local=v.get("local") or {};decl=local.get("location")
            if decl is not None:
                uses[decl].append({"name":local.get("name"),"use_location":v.get("location"),
                                   "path":path,"owner_function":stack[-1] if stack else None})
        if t=="AstExprCall":
            calls[v.get("location")].append({"path":path,"node":v,"owner_function":stack[-1] if stack else None})

        for k,x in v.items():
            if k.startswith("_"):continue
            if isinstance(x,(dict,list)):
                walk(x,f"{path}.{k}",stack)

    walk(root)
    return declarations,writes,uses,calls

def lexical_relation(stmt_loc,call_loc):
    a=parse_loc(stmt_loc);b=parse_loc(call_loc)
    if a is None or b is None:return "UNKNOWN"
    start=(a[0],a[1]);call=(b[0],b[1])
    return "BEFORE" if start<call else "AFTER" if start>call else "SAME_START"

def analyze(e_path,source_path,expect_sha):
    e=load(e_path);instances,call_loc=require_e(e)
    source_sha,root=parse_source(source_path,expect_sha)
    declarations,writes,uses,calls=walk_source(root)
    if len(calls.get(call_loc,[]))!=1:
        raise ValueError(f"recovered call location matched {len(calls.get(call_loc,[]))} source calls")
    call_owner=calls[call_loc][0]["owner_function"]

    required={}
    for inst in instances:
        for name,decl in source_local_decls(inst).items():
            if name not in TARGET_NAMES:continue
            prev=required.get(name)
            if prev is not None and prev!=decl:
                raise ValueError(f"call instances disagree on source decl for {name}")
            required[name]=decl
    missing=[n for n in TARGET_NAMES if n not in required]
    if missing:raise ValueError(f"recovered call AST missing required locals: {missing}")

    rows=[];classes=Counter()
    for name in TARGET_NAMES:
        decl=required[name]
        ds=declarations.get(decl,[])
        if len(ds)>1:
            raise ValueError(f"declaration location {decl!r} for {name} matched {len(ds)} declarations")
        d=ds[0] if ds else None
        ws=writes.get(decl,[])
        us=uses.get(decl,[])
        if d is None:
            cls="UNKNOWN_DECL"
            owner=None;init_count=0
        else:
            owner=d.get("owner_function");init_count=d.get("initializer_count",0)
            kind=d["kind"]
            if kind=="PARAMETER":cls="PARAMETER"
            elif kind=="LOCAL_FUNCTION":cls="LOCAL_FUNCTION"
            elif kind=="FOR_VARIABLE":cls="FOR_VARIABLE"
            elif kind=="FORIN_VARIABLE":cls="FORIN_VARIABLE"
            elif kind=="LOCAL":
                if init_count==1 and not ws:cls="LOCAL_SINGLE_INIT_NO_REASSIGN"
                elif init_count==1 and ws:cls="LOCAL_INIT_MUTATED"
                elif init_count==0 and not ws:cls="LOCAL_NO_INIT_NO_ASSIGN"
                elif init_count==0 and ws:cls="LOCAL_NO_INIT_ASSIGNED"
                else:cls="LOCAL_COMPLEX_INIT"
            else:cls="UNKNOWN_DECL_KIND"
        nested=sum(1 for w in ws if owner is not None and w.get("owner_function")!=owner)
        rows.append({
            "name":name,"decl":decl,"classification":cls,
            "declaration":d,
            "direct_write_count":len(ws),
            "nested_closure_write_count":nested,
            "writes":[{**w,"lexical_relation_to_call":lexical_relation(w.get("statement_location"),call_loc)} for w in ws],
            "use_count":len(us),
            "call_owner_function":call_owner,
            "decl_owner_function":owner,
            "same_owner_as_call":owner==call_owner if d is not None else None,
            "single_static_origin_candidate":cls in ("LOCAL_SINGLE_INIT_NO_REASSIGN","LOCAL_FUNCTION"),
        })
        classes[cls]+=1
    return {
        "schema":SCHEMA,
        "source_r182e":str(e_path),"source_file":str(source_path),
        "checkpoint":e["checkpoint"],"source_sha256":source_sha,
        "call_location":call_loc,"call_owner_function":call_owner,
        "summary":{"locals":len(rows),"classification_counts":dict(classes.most_common()),
                   "single_static_origin_candidates":sum(bool(x["single_static_origin_candidate"]) for x in rows)},
        "locals":rows,
        "interpretation_gate":{
            "single_static_origin_candidate_proves_runtime_value":False,
            "lexical_before_proves_executed_before":False,
            "no_reassignment_proves_immutable_object_contents":False,
            "parameter_has_static_value":False,
            "source_provenance_authorizes_candidate_evaluation":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,"no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r182e",type=Path);ap.add_argument("source",type=Path)
    ap.add_argument("--expect-source-sha256",required=True)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r182e,a.source,a.expect_source_sha256)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        print("R182H:",json.dumps(out["summary"],sort_keys=True))
        for row in out["locals"]:
            print(f"{row['name']}: {row['classification']} writes={row['direct_write_count']} nested={row['nested_closure_write_count']} same_owner={row['same_owner_as_call']}")
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
