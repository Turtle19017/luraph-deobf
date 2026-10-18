#!/usr/bin/env python3
"""R182E: recover omitted bit32.bxor argument ASTs from the exact original source by AST location."""
from __future__ import annotations
import argparse, hashlib, json, sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "luraph-deobf.r182e-source-call-arg-recovery.v1"

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def node_type(node):
    return node.get("type") if isinstance(node,dict) else None

def local_name(node):
    if not isinstance(node,dict) or node.get("type")!="AstExprLocal":
        return None
    local=node.get("local")
    if isinstance(local,dict) and isinstance(local.get("name"),str):
        return local["name"]
    name=node.get("name")
    return name if isinstance(name,str) else None

def walk_nodes(v,path="$"):
    if isinstance(v,dict):
        if isinstance(v.get("type"),str):
            yield path,v
        for k,x in v.items():
            if isinstance(x,(dict,list)):
                yield from walk_nodes(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v):
            yield from walk_nodes(x,f"{path}[{i}]")

def index_calls(root):
    by=defaultdict(list)
    for path,node in walk_nodes(root):
        if node.get("type")=="AstExprCall":
            loc=node.get("location")
            try:
                hash(loc)
            except TypeError:
                raise ValueError(f"unhashable call location at {path}: {loc!r}")
            by[loc].append((path,node))
    return by

def require_receipts(f,g):
    if f.get("schema")!="luraph-deobf.r181f-local-identity-rhs-census.v1":
        raise ValueError("expected R181F receipt")
    if g.get("schema")!="luraph-deobf.r181g-rhs-local-dependency-census.v1":
        raise ValueError("expected R181G receipt")
    if checkpoint(f)!=(78,64,0,594) or checkpoint(g)!=(78,64,0,594):
        raise ValueError("checkpoint != 78/64/0/594")
    fi=f.get("instances",[]); gi=g.get("instances",[])
    if len(fi)!=136 or len(gi)!=136:
        raise ValueError(f"expected 136 instances in each receipt, found {len(fi)}/{len(gi)}")
    rows=[]
    for i,(fr,gr) in enumerate(zip(fi,gi)):
        if gr.get("instance_index")!=i:
            raise ValueError(f"R181G instance_index mismatch at {i}")
        for key in ("function_id","state_id","right_type"):
            if fr.get(key)!=gr.get(key):
                raise ValueError(f"R181F/R181G join mismatch at {i}: {key}")
        if gr.get("right_type")=="AstExprCall":
            rows.append((i,fr,gr))
    if len(rows)!=41:
        raise ValueError(f"expected 41 call instances, found {len(rows)}")
    return rows

def debug_call_identity(gr):
    right=gr.get("right_node")
    if not isinstance(right,dict) or right.get("type")!="AstExprCall":
        raise ValueError("R181G call instance lacks debug AstExprCall right_node")
    loc=right.get("location")
    if loc is None:
        raise ValueError("R181G call instance lacks call location")
    argc=gr.get("rhs_schema",{}).get("argc")
    if argc!=2:
        raise ValueError(f"R181G call argc != 2: {argc!r}")
    func=right.get("func")
    name=None
    if isinstance(func,dict):
        name=func.get("name")
    if name!="v":
        raise ValueError(f"R181G call func debug name != v: {name!r}")
    return loc,argc,name

def compact(node,depth=0,max_depth=8):
    if not isinstance(node,dict):
        if isinstance(node,list):
            return [compact(x,depth+1,max_depth) for x in node]
        return node
    out={"type":node.get("type"),"location":node.get("location")}
    if depth>=max_depth:
        out["cut"]=True
        return out
    t=node.get("type")
    if t=="AstExprConstantNumber":
        out["value"]=node.get("value")
    elif t=="AstExprConstantString":
        out["value"]=node.get("value")
    elif t=="AstExprConstantBool":
        out["value"]=node.get("value")
    elif t=="AstExprConstantNil":
        out["value"]=None
    elif t=="AstExprLocal":
        loc=node.get("local") or {}
        out["name"]=loc.get("name")
        out["decl"]=loc.get("location")
    elif t=="AstExprGlobal":
        out["global"]=node.get("global")
    elif t=="AstExprBinary":
        out["op"]=node.get("op")
        out["left"]=compact(node.get("left"),depth+1,max_depth)
        out["right"]=compact(node.get("right"),depth+1,max_depth)
    elif t=="AstExprUnary":
        out["op"]=node.get("op")
        out["expr"]=compact(node.get("expr"),depth+1,max_depth)
    elif t in ("AstExprGroup","AstExprTypeAssertion"):
        out["expr"]=compact(node.get("expr"),depth+1,max_depth)
    elif t=="AstExprIndexExpr":
        out["expr"]=compact(node.get("expr"),depth+1,max_depth)
        out["index"]=compact(node.get("index"),depth+1,max_depth)
    elif t=="AstExprIndexName":
        out["expr"]=compact(node.get("expr"),depth+1,max_depth)
        out["index"]=node.get("index")
        out["op"]=node.get("op")
    elif t=="AstExprCall":
        args=node.get("args") or []
        out["func"]=compact(node.get("func"),depth+1,max_depth)
        out["argc"]=len(args)
        out["args"]=[compact(x,depth+1,max_depth) for x in args]
    else:
        for k,v in node.items():
            if k in ("type","location"): continue
            if isinstance(v,(str,int,float,bool)) or v is None:
                out[k]=v
    return out

def arg_shape(node):
    if not isinstance(node,dict): return type(node).__name__
    t=node.get("type")
    if t=="AstExprLocal":
        return f"AstExprLocal:{local_name(node)}"
    if t=="AstExprConstantNumber":
        return f"AstExprConstantNumber:{node.get('value')!r}"
    if t=="AstExprCall":
        return f"AstExprCall:{local_name(node.get('func')) or node_type(node.get('func'))}"
    return str(t)

def recover_from_ast(f,g,root):
    rows=require_receipts(f,g)
    calls=index_calls(root)
    out=[];shape_counts=Counter();loc_counts=Counter()
    for idx,fr,gr in rows:
        loc,argc,_=debug_call_identity(gr)
        hits=calls.get(loc,[])
        if len(hits)!=1:
            raise ValueError(f"call location {loc!r} matched {len(hits)} source AstExprCall nodes")
        ast_path,node=hits[0]
        args=node.get("args") or []
        if len(args)!=argc:
            raise ValueError(f"source call argc mismatch at {loc!r}: expected {argc}, found {len(args)}")
        fname=local_name(node.get("func"))
        if fname!="v":
            raise ValueError(f"source call func at {loc!r} is not local v: {fname!r}")
        shapes=[arg_shape(x) for x in args]
        for pos,shape in enumerate(shapes):
            shape_counts[f"arg{pos}:{shape}"]+=1
        loc_counts[repr(loc)]+=1
        out.append({
            "instance_index":idx,
            "function_id":fr.get("function_id"),
            "state_id":fr.get("state_id"),
            "call_location":loc,
            "source_ast_path":ast_path,
            "func_name":fname,
            "argc":len(args),
            "arg_shapes":shapes,
            "args":[compact(x) for x in args],
            "local_snapshot_entries":fr.get("local_snapshot_entries",[]),
        })
    return out,shape_counts,loc_counts

def parse_source(path,expect_sha256):
    raw=Path(path).read_bytes()
    got=sha256_bytes(raw)
    if got.lower()!=expect_sha256.lower():
        raise ValueError(f"source SHA-256 mismatch: got {got}, expected {expect_sha256}")
    core=Path(__file__).resolve().parents[1]/"core"
    sys.path.insert(0,str(core))
    import luauast
    text=raw.decode("latin-1")
    root=luauast.parse(text)
    return got,root

def analyze(f_path,g_path,source_path,expect_sha256):
    f=load(f_path);g=load(g_path)
    source_sha,root=parse_source(source_path,expect_sha256)
    rows,shapes,locs=recover_from_ast(f,g,root)
    return {
        "schema":SCHEMA,
        "sources":{"r181f":str(f_path),"r181g":str(g_path),"source":str(source_path)},
        "checkpoint":f["checkpoint"],
        "source_sha256":source_sha,
        "summary":{
            "call_instances":len(rows),
            "unique_call_locations":len(locs),
            "all_source_calls_recovered":len(rows)==41,
            "arg_shape_classes":len(shapes),
        },
        "arg_shapes":dict(shapes.most_common()),
        "call_location_instance_counts":dict(locs.most_common()),
        "instances":rows,
        "interpretation_gate":{
            "source_ast_location_match_is_structural_recovery":True,
            "source_arg_ast_proves_runtime_arg_value":False,
            "local_snapshot_timing_proved":False,
            "bit32_bxor_evaluated":False,
            "subtraction_evaluated":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,
        "no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r181f",type=Path)
    ap.add_argument("r181g",type=Path)
    ap.add_argument("source",type=Path)
    ap.add_argument("--expect-source-sha256",required=True)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r181f,a.r181g,a.source,a.expect_source_sha256)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"]
        print(f"R182E: calls={s['call_instances']} unique_locations={s['unique_call_locations']} recovered={s['all_source_calls_recovered']} arg_shape_classes={s['arg_shape_classes']}")
        print("arg_shapes:",json.dumps(out["arg_shapes"],sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
