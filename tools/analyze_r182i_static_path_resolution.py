#!/usr/bin/env python3
"""R182I: exact-declaration static-path resolution for r/K/h source origins."""
from __future__ import annotations
import argparse, hashlib, json, math, sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r182i-static-path-resolution.v1"
ROOTS=("r","K","h")

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def parse_source(path,expect_sha):
    raw=Path(path).read_bytes();got=sha256_bytes(raw)
    if got.lower()!=expect_sha.lower():
        raise ValueError(f"source SHA-256 mismatch: got {got}, expected {expect_sha}")
    core=Path(__file__).resolve().parents[1]/"core"
    if str(core) not in sys.path:sys.path.insert(0,str(core))
    import luauast
    return got,luauast.parse(raw.decode("latin-1"))

def import_core():
    core=Path(__file__).resolve().parents[1]/"core"
    if str(core) not in sys.path:sys.path.insert(0,str(core))
    from obfuscators.luraph_v15 import devirt
    return devirt

def unwrap(e):
    while isinstance(e,dict) and e.get("type") in ("AstExprGroup","AstExprTypeAssertion"):
        e=e.get("expr")
    return e

def local_decl(e):
    e=unwrap(e)
    if isinstance(e,dict) and e.get("type")=="AstExprLocal":
        local=e.get("local") or {}
        return local.get("location"),local.get("name")
    return None,None

def const_key(e):
    e=unwrap(e)
    if not isinstance(e,dict):return None
    t=e.get("type")
    if t=="AstExprConstantNumber":
        v=e.get("value")
        if isinstance(v,bool):return None
        if isinstance(v,float) and math.isfinite(v) and v.is_integer():return int(v)
        return v if isinstance(v,(int,float)) else None
    if t=="AstExprConstantString":
        return e.get("value")
    return None

def index_root_path(expr):
    path=[];e=unwrap(expr)
    while isinstance(e,dict) and e.get("type") in ("AstExprIndexExpr","AstExprIndexName"):
        if e.get("type")=="AstExprIndexExpr":
            key=const_key(e.get("index"))
            if key is None:return None,None,None
        else:
            key=e.get("index")
            if not isinstance(key,str):return None,None,None
        path.append(key);e=unwrap(e.get("expr"))
    decl,name=local_decl(e)
    if decl is None:return None,None,None
    return decl,name,tuple(reversed(path))

def value_summary(v,D):
    S=D.S
    if v is None or isinstance(v,(bool,int,float,str)):
        return {"kind":"scalar","value":v}
    if isinstance(v,bytes):
        return {"kind":"bytes","hex":v.hex(),"length":len(v)}
    if isinstance(v,S.Builtin):
        return {"kind":"builtin","name":v.name,"repr":repr(v)}
    if isinstance(v,S.LTable):
        keys=sorted((repr(k) for k in v.h.keys()))
        return {"kind":"table","tid":v.tid,"repr":repr(v),"entry_count":len(v.h),"key_preview":keys[:32]}
    if isinstance(v,S.LuaFunc):
        return {"kind":"lua-function","location":v.node.get("location"),"repr":repr(v)}
    return {"kind":"other","type":type(v).__name__,"repr":repr(v)}

def canon_summary(x):
    return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(",",":"))

def source_index(root):
    decls=defaultdict(list);direct=defaultdict(list);path_writes=defaultdict(list)
    def walk(v,path="$",owner=None):
        if isinstance(v,list):
            for i,x in enumerate(v):walk(x,f"{path}[{i}]",owner)
            return
        if not isinstance(v,dict):return
        t=v.get("type");own=owner
        if t=="AstExprFunction":own=v.get("location")
        if t=="AstStatLocal":
            vals=v.get("values") or []
            for i,a in enumerate(v.get("vars") or []):
                decls[a.get("location")].append({"kind":"LOCAL","name":a.get("name"),"node":a,
                    "initializer":vals[i] if i<len(vals) else None,"statement":v,"owner":own,"path":f"{path}.vars[{i}]"})
        elif t=="AstStatLocalFunction":
            a=v.get("name") or {}
            decls[a.get("location")].append({"kind":"LOCAL_FUNCTION","name":a.get("name"),"node":a,
                "initializer":v.get("func"),"statement":v,"owner":own,"path":f"{path}.name"})
        elif t=="AstExprFunction":
            for i,a in enumerate(v.get("args") or []):
                decls[a.get("location")].append({"kind":"PARAMETER","name":a.get("name"),"node":a,
                    "initializer":None,"statement":None,"owner":own,"path":f"{path}.args[{i}]"})
        elif t=="AstStatFor":
            a=v.get("var") or {}
            decls[a.get("location")].append({"kind":"FOR_VARIABLE","name":a.get("name"),"node":a,
                "initializer":None,"statement":v,"owner":own,"path":f"{path}.var"})
        elif t=="AstStatForIn":
            for i,a in enumerate(v.get("vars") or []):
                decls[a.get("location")].append({"kind":"FORIN_VARIABLE","name":a.get("name"),"node":a,
                    "initializer":None,"statement":v,"owner":own,"path":f"{path}.vars[{i}]"})

        if t=="AstStatAssign":
            vals=v.get("values") or []
            for i,target in enumerate(v.get("vars") or []):
                rhs=vals[i] if i<len(vals) else None
                d,n=local_decl(target)
                if d is not None:
                    direct[d].append({"name":n,"rhs":rhs,"statement":v,"owner":own,"path":f"{path}.vars[{i}]"})
                else:
                    rd,rn,rp=index_root_path(target)
                    if rd is not None:
                        path_writes[(rd,rp)].append({"root_name":rn,"rhs":rhs,"statement":v,"owner":own,
                                                    "path":f"{path}.vars[{i}]"})
        elif t=="AstStatCompoundAssign":
            d,n=local_decl(v.get("var"))
            if d is not None:
                direct[d].append({"name":n,"rhs":None,"compound_op":v.get("op"),"statement":v,
                                  "owner":own,"path":f"{path}.var"})
            else:
                rd,rn,rp=index_root_path(v.get("var"))
                if rd is not None:
                    path_writes[(rd,rp)].append({"root_name":rn,"rhs":None,"compound_op":v.get("op"),
                                                "statement":v,"owner":own,"path":f"{path}.var"})
        for k,x in v.items():
            if k.startswith("_"):continue
            if isinstance(x,(dict,list)):walk(x,f"{path}.{k}",own)
    walk(root)
    return decls,direct,path_writes

class Resolver:
    def __init__(self,root,D):
        self.root=root;self.D=D
        self.decls,self.direct,self.path_writes=source_index(root)
        self.memo={};self.active=set()
        D._bind_value._top=D._top_table(root)

    def bind_plain(self,expr):
        try:return self.D._bind_value(expr,self.D.Scope())
        except Exception:return None

    def resolve_decl(self,decl,depth=0):
        if depth>20:return {"status":"UNRESOLVED","reason":"MAX_DEPTH","decl":decl}
        if decl in self.memo:return self.memo[decl]
        if decl in self.active:return {"status":"UNRESOLVED","reason":"DECL_CYCLE","decl":decl}
        self.active.add(decl)
        try:
            ds=self.decls.get(decl,[])
            if len(ds)!=1:
                out={"status":"UNRESOLVED","reason":f"DECL_MATCH_COUNT:{len(ds)}","decl":decl}
            else:
                d=ds[0];kind=d["kind"];writes=self.direct.get(decl,[])
                if kind=="LOCAL" and d.get("initializer") is not None and not writes:
                    out=self.resolve_expr(d["initializer"],depth+1)
                    out={**out,"decl":decl,"decl_name":d.get("name"),"origin":"LOCAL_SINGLE_INIT"}
                elif kind=="LOCAL" and d.get("initializer") is None and len(writes)==1 and writes[0].get("rhs") is not None:
                    out=self.resolve_expr(writes[0]["rhs"],depth+1)
                    out={**out,"decl":decl,"decl_name":d.get("name"),"origin":"LOCAL_SINGLE_ASSIGN"}
                elif kind=="LOCAL_FUNCTION" and not writes:
                    val=self.bind_plain(d.get("initializer"))
                    out={"status":"VALUE","value":value_summary(val,self.D),"decl":decl,
                         "decl_name":d.get("name"),"origin":"LOCAL_FUNCTION"} if val is not None else                         {"status":"UNRESOLVED","reason":"LOCAL_FUNCTION_BIND_FAILED","decl":decl}
                elif kind=="PARAMETER":
                    out={"status":"UNRESOLVED","reason":"PARAMETER","decl":decl,"decl_name":d.get("name")}
                else:
                    out={"status":"UNRESOLVED","reason":f"MUTABLE_OR_COMPLEX:{kind}:writes={len(writes)}",
                         "decl":decl,"decl_name":d.get("name")}
            self.memo[decl]=out
            return out
        finally:
            self.active.discard(decl)

    def path_candidates(self,decl,path,depth):
        rows=self.path_writes.get((decl,tuple(path)),[])
        vals=[];unresolved=[]
        for row in rows:
            rhs=row.get("rhs")
            if rhs is None:
                unresolved.append("COMPOUND_OR_MISSING_RHS");continue
            r=self.resolve_expr(rhs,depth+1)
            if r.get("status")=="VALUE":
                vals.append({"value":r["value"],"source_path":row["path"],
                             "statement_location":row["statement"].get("location")})
            else:
                unresolved.append(r.get("reason","UNRESOLVED"))
        uniq={canon_summary(x["value"]):x["value"] for x in vals}
        if len(uniq)==1 and vals:
            return {"status":"VALUE","value":next(iter(uniq.values())),
                    "origin":"STATIC_PATH_WRITES","root_decl":decl,"index_path":list(path),
                    "candidate_write_count":len(rows),"resolved_write_count":len(vals),
                    "unresolved_write_reasons":sorted(set(unresolved))}
        if len(uniq)>1:
            return {"status":"UNRESOLVED","reason":"CONFLICTING_STATIC_PATH_VALUES",
                    "root_decl":decl,"index_path":list(path),"values":list(uniq.values())}
        return {"status":"UNRESOLVED","reason":"NO_RESOLVED_STATIC_PATH_VALUE",
                "root_decl":decl,"index_path":list(path),"candidate_write_count":len(rows),
                "unresolved_write_reasons":sorted(set(unresolved))}

    def resolve_expr(self,expr,depth=0):
        if depth>20:return {"status":"UNRESOLVED","reason":"MAX_DEPTH"}
        e=unwrap(expr)
        if not isinstance(e,dict):return {"status":"UNRESOLVED","reason":"NON_DICT_EXPR"}
        t=e.get("type")
        if t in ("AstExprConstantNumber","AstExprConstantBool","AstExprConstantString"):
            return {"status":"VALUE","value":{"kind":"scalar","value":e.get("value")},"origin":t}
        if t=="AstExprConstantNil":
            return {"status":"VALUE","value":{"kind":"scalar","value":None},"origin":t}
        if t=="AstExprLocal":
            d,_=local_decl(e)
            return self.resolve_decl(d,depth+1)
        if t in ("AstExprTable","AstExprFunction","AstExprGlobal","AstExprIndexName"):
            val=self.bind_plain(e)
            if val is not None:
                return {"status":"VALUE","value":value_summary(val,self.D),"origin":"BIND_VALUE"}
            if t=="AstExprIndexName":
                # Fall through to generic index handling if the base is a reconstructable local.
                pass
            else:
                return {"status":"UNRESOLVED","reason":f"STATIC_BIND_FAILED:{t}"}
        if t in ("AstExprIndexExpr","AstExprIndexName"):
            rd,rn,rp=index_root_path(e)
            if rd is not None and rp:
                direct=self.path_candidates(rd,rp,depth+1)
                if direct.get("status")=="VALUE":
                    return {**direct,"root_name":rn}
                if direct.get("reason")=="CONFLICTING_STATIC_PATH_VALUES":
                    return {**direct,"root_name":rn}
                if direct.get("candidate_write_count",0)>0:
                    return {**direct,"root_name":rn}
            base_expr=e.get("expr")
            base=self.resolve_expr(base_expr,depth+1)
            if base.get("status")!="VALUE":
                return {"status":"UNRESOLVED","reason":"INDEX_BASE_UNRESOLVED","base":base,
                        "root_decl":rd,"root_name":rn,"index_path":list(rp) if rp else None}
            key=const_key(e.get("index")) if t=="AstExprIndexExpr" else e.get("index")
            if key is None:return {"status":"UNRESOLVED","reason":"INDEX_KEY_NOT_CONSTANT","base":base}
            # We serialize table values, so generic table dereference is intentionally not attempted here.
            return {"status":"UNRESOLVED","reason":"INDEX_BASE_VALUE_NOT_DEREFERENCEABLE",
                    "base":base,"key":key}
        return {"status":"UNRESOLVED","reason":f"UNSUPPORTED_EXPR:{t}"}

def require_h(obj):
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r182h-source-local-provenance.v1":
        raise ValueError("expected R182H receipt")
    if checkpoint(obj)!=(78,64,0,594):raise ValueError("checkpoint != 78/64/0/594")
    rows={x.get("name"):x for x in obj.get("locals",[]) if isinstance(x,dict)}
    for n in ROOTS:
        if n not in rows:raise ValueError(f"R182H missing root local {n}")
    return rows

def analyze(h_path,source_path,expect_sha):
    h=load(h_path);roots=require_h(h)
    got,root=parse_source(source_path,expect_sha)
    D=import_core();R=Resolver(root,D)
    out_rows=[];classes=Counter()
    for name in ROOTS:
        decl=roots[name].get("decl")
        if decl is None:raise ValueError(f"root {name} has no declaration location")
        r=R.resolve_decl(decl)
        cls="STATIC_VALUE_CANDIDATE" if r.get("status")=="VALUE" else "UNRESOLVED"
        classes[cls]+=1
        out_rows.append({"name":name,"decl":decl,"r182h_classification":roots[name].get("classification"),
                         "resolution_class":cls,"resolution":r})
    return {
        "schema":SCHEMA,"source_r182h":str(h_path),"source_file":str(source_path),
        "checkpoint":h["checkpoint"],"source_sha256":got,
        "summary":{"roots":len(out_rows),"classification_counts":dict(classes.most_common()),
                   "static_value_candidates":classes["STATIC_VALUE_CANDIDATE"],
                   "unresolved":classes["UNRESOLVED"]},
        "roots":out_rows,
        "interpretation_gate":{
            "static_value_candidate_is_runtime_value":False,
            "static_path_write_is_execution_order_proof":False,
            "same_static_value_across_writes_proves_call_time_value":False,
            "candidate_builtin_authorizes_r182f_replay":False,
            "table_overlay_state_reconstructed":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,"no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r182h",type=Path);ap.add_argument("source",type=Path)
    ap.add_argument("--expect-source-sha256",required=True)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r182h,a.source,a.expect_source_sha256)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        print("R182I:",json.dumps(out["summary"],sort_keys=True))
        for row in out["roots"]:
            print(f"{row['name']}: {row['resolution_class']} {json.dumps(row['resolution'],sort_keys=True,ensure_ascii=False)}")
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
