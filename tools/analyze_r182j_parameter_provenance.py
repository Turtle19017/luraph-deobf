#!/usr/bin/env python3
"""R182J: exact source parameter-owner and callsite provenance census for R182I boundaries."""
from __future__ import annotations
import argparse, hashlib, json, sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r182j-parameter-provenance-census.v2"

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
    from obfuscators.luraph_v15 import vmmap,devirt
    return vmmap,devirt

def unwrap(e):
    while isinstance(e,dict) and e.get("type") in ("AstExprGroup","AstExprTypeAssertion"):
        e=e.get("expr")
    return e

def local_decl(e):
    e=unwrap(e)
    if isinstance(e,dict) and e.get("type")=="AstExprLocal":
        loc=e.get("local") or {}
        return loc.get("location"),loc.get("name")
    return None,None

def compact(node,depth=0,max_depth=6):
    if not isinstance(node,dict):
        if isinstance(node,list):return [compact(x,depth+1,max_depth) for x in node]
        return node
    out={"type":node.get("type"),"location":node.get("location")}
    if depth>=max_depth:
        out["cut"]=True;return out
    t=node.get("type")
    if t=="AstExprLocal":
        loc=node.get("local") or {}
        out["name"]=loc.get("name");out["decl"]=loc.get("location")
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
        out["argc"]=len(args);out["args"]=[compact(x,depth+1,max_depth) for x in args]
    elif t=="AstExprFunction":
        out["argc"]=len(node.get("args") or [])
    elif t=="AstExprTable":
        out["item_count"]=len(node.get("items") or [])
    return out

def collect_parameter_boundaries(v,out=None):
    if out is None:out=[]
    if isinstance(v,dict):
        if v.get("reason")=="PARAMETER" and v.get("decl") is not None:
            out.append({"decl":v.get("decl"),"name":v.get("decl_name")})
        for x in v.values():
            if isinstance(x,(dict,list)):collect_parameter_boundaries(x,out)
    elif isinstance(v,list):
        for x in v:collect_parameter_boundaries(x,out)
    return out

def require_i(obj):
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r182i-static-path-resolution.v1":
        raise ValueError("expected R182I receipt")
    if checkpoint(obj)!=(78,64,0,594):raise ValueError("checkpoint != 78/64/0/594")
    params={}
    roots=defaultdict(set)
    for row in obj.get("roots",[]):
        if not isinstance(row,dict):continue
        root_name=row.get("name")
        for p in collect_parameter_boundaries(row.get("resolution")):
            decl=p["decl"];name=p.get("name")
            prev=params.get(decl)
            if prev is not None and prev!=name:
                raise ValueError(f"parameter decl {decl!r} has conflicting names")
            params[decl]=name;roots[decl].add(root_name)
    if not params:
        raise ValueError("R182I contains no PARAMETER boundary")
    return params,roots

class SourceIndex:
    def __init__(self,root):
        self.root=root
        self.functions=[]
        self.param_owner={}
        self.local_sources=defaultdict(list)
        self.local_writes=defaultdict(list)
        self.calls=[]
        self._walk(root)

    def _walk(self,v,path="$",owner=None):
        if isinstance(v,list):
            for i,x in enumerate(v):self._walk(x,f"{path}[{i}]",owner)
            return
        if not isinstance(v,dict):return
        t=v.get("type");own=owner
        if t=="AstExprFunction":
            own=v
            self.functions.append({"node":v,"path":path})
            for i,a in enumerate(v.get("args") or []):
                decl=a.get("location")
                if decl in self.param_owner:
                    raise ValueError(f"duplicate parameter declaration location {decl!r}")
                self.param_owner[decl]={"function":v,"function_path":path,"param_index":i,
                                        "param_name":a.get("name"),"param_decl":decl}

        if t=="AstStatLocal":
            vals=v.get("values") or []
            for i,a in enumerate(v.get("vars") or []):
                decl=a.get("location")
                init=vals[i] if i<len(vals) else None
                self.local_sources[decl].append({"kind":"LOCAL_INIT","expr":init,
                    "statement_location":v.get("location"),"owner":own.get("location") if own else None})
        elif t=="AstStatLocalFunction":
            a=v.get("name") or {};decl=a.get("location")
            self.local_sources[decl].append({"kind":"LOCAL_FUNCTION","expr":v.get("func"),
                "statement_location":v.get("location"),"owner":own.get("location") if own else None})

        if t=="AstStatAssign":
            vals=v.get("values") or []
            for i,target in enumerate(v.get("vars") or []):
                decl,name=local_decl(target)
                if decl is not None:
                    rhs=vals[i] if i<len(vals) else None
                    self.local_writes[decl].append({"kind":"ASSIGN","name":name,"expr":rhs,
                        "statement_location":v.get("location"),"owner":own.get("location") if own else None})
        elif t=="AstStatCompoundAssign":
            decl,name=local_decl(v.get("var"))
            if decl is not None:
                self.local_writes[decl].append({"kind":"COMPOUND_ASSIGN","name":name,"expr":None,
                    "statement_location":v.get("location"),"owner":own.get("location") if own else None})

        if t=="AstExprCall":
            self.calls.append({"node":v,"path":path,"owner":own.get("location") if own else None})

        for k,x in v.items():
            if k.startswith("_"):continue
            if isinstance(x,(dict,list)):self._walk(x,f"{path}.{k}",own)

    def static_local_origin(self,decl,seen=None):
        if seen is None:seen=set()
        if decl in seen:return {"status":"UNRESOLVED","reason":"ALIAS_CYCLE","decl":decl}
        seen=set(seen);seen.add(decl)
        src=self.local_sources.get(decl,[]);writes=self.local_writes.get(decl,[])
        candidates=[]
        if len(src)==1 and src[0].get("expr") is not None:
            candidates.append(src[0])
        if not src and len(writes)==1 and writes[0].get("expr") is not None:
            candidates.append(writes[0])
        if len(src)==1 and src[0].get("expr") is None and len(writes)==1 and writes[0].get("expr") is not None:
            candidates.append(writes[0])
        # Any reassignment beyond the selected single source makes callee identity unsafe.
        effective_writes=len(writes)
        if len(candidates)!=1:
            return {"status":"UNRESOLVED","reason":f"ORIGIN_COUNT:{len(candidates)}",
                    "decl":decl,"source_records":len(src),"write_records":len(writes)}
        chosen=candidates[0]
        if chosen in src and effective_writes:
            return {"status":"UNRESOLVED","reason":f"REASSIGNED:{effective_writes}","decl":decl}
        if chosen in writes and effective_writes!=1:
            return {"status":"UNRESOLVED","reason":f"WRITE_COUNT:{effective_writes}","decl":decl}
        e=unwrap(chosen.get("expr"))
        if isinstance(e,dict) and e.get("type")=="AstExprLocal":
            nxt=(e.get("local") or {}).get("location")
            sub=self.static_local_origin(nxt,seen)
            # Preserve terminal callee identity across an immutable alias chain.
            # Keep the nested record as provenance, but surface function_location
            # and node when (and only when) the recursively resolved origin is
            # already a FUNCTION.
            out={"status":sub.get("status"),"decl":decl,"origin":"LOCAL_ALIAS",
                 "alias_decl":nxt,"next":sub}
            if sub.get("status")=="FUNCTION":
                out["function_location"]=sub.get("function_location")
                out["node"]=sub.get("node")
            return out
        if isinstance(e,dict) and e.get("type")=="AstExprFunction":
            return {"status":"FUNCTION","decl":decl,"function_location":e.get("location"),"node":e,
                    "origin":chosen.get("kind")}
        return {"status":"EXPR","decl":decl,"expr":e,"origin":chosen.get("kind")}

    def callee_function(self,expr):
        e=unwrap(expr)
        if not isinstance(e,dict):return {"status":"UNRESOLVED","reason":"NON_DICT_CALLEE"}
        if e.get("type")=="AstExprFunction":
            return {"status":"FUNCTION","function_location":e.get("location"),"node":e,"origin":"DIRECT_FUNCTION"}
        if e.get("type")=="AstExprLocal":
            decl=(e.get("local") or {}).get("location")
            return self.static_local_origin(decl)
        return {"status":"UNRESOLVED","reason":f"UNSUPPORTED_CALLEE:{e.get('type')}"}

def maker_roles(root,vmmap):
    out={}
    try: infos=vmmap.maker_info(root)
    except Exception as exc:
        return {},{"status":"ERROR","type":type(exc).__name__,"message":str(exc)}
    for info in infos:
        maker=info.get("maker")
        if not isinstance(maker,dict):continue
        floc=maker.get("location")
        pi=info.get("proto_index");ui=info.get("upvals_index")
        roles={}
        for idx,a in enumerate(maker.get("args") or []):
            role="VMOBJ" if idx==0 else "PROTO" if idx==pi else "UPVALS" if idx==ui else "OTHER"
            roles[a.get("location")]={"role":role,"param_index":idx,"param_name":a.get("name"),
                                      "maker_function_location":floc,
                                      "proto_index":pi,"upvals_index":ui}
        out.update(roles)
    return out,{"status":"OK","maker_count":len(infos)}

def bind_static(expr,D):
    if not isinstance(expr,dict):return None
    t=expr.get("type")
    if t in ("AstExprConstantNumber","AstExprConstantString","AstExprConstantBool"):
        return {"kind":"scalar","value":expr.get("value")}
    if t=="AstExprConstantNil":
        return {"kind":"scalar","value":None}
    try:v=D._bind_value(expr,D.Scope())
    except Exception:return None
    S=D.S
    if isinstance(v,S.Builtin):return {"kind":"builtin","name":v.name,"repr":repr(v)}
    if isinstance(v,S.LTable):return {"kind":"table","tid":v.tid,"repr":repr(v),"entry_count":len(v.h)}
    if isinstance(v,S.LuaFunc):return {"kind":"lua-function","location":v.node.get("location")}
    if v is None or isinstance(v,(bool,int,float,str)):return {"kind":"scalar","value":v}
    if isinstance(v,bytes):return {"kind":"bytes","hex":v.hex(),"length":len(v)}
    return None

def analyze(i_path,source_path,expect_sha):
    ri=load(i_path);params,root_uses=require_i(ri)
    got,root=parse_source(source_path,expect_sha)
    vmmap,D=import_core();idx=SourceIndex(root)
    roles,role_meta=maker_roles(root,vmmap)
    # Set top table once for static argument summaries.
    try:D._bind_value._top=D._top_table(root)
    except Exception:pass

    rows=[];class_counts=Counter();call_counts=Counter()
    for decl,name in sorted(params.items()):
        owner=idx.param_owner.get(decl)
        if owner is None:
            rows.append({"decl":decl,"name":name,"roots":sorted(root_uses[decl]),
                         "classification":"PARAM_OWNER_NOT_FOUND","call_sites":[]})
            class_counts["PARAM_OWNER_NOT_FOUND"]+=1
            continue
        fn=owner["function"];floc=fn.get("location");pidx=owner["param_index"]
        calls=[]
        for call in idx.calls:
            cres=idx.callee_function(call["node"].get("func"))
            if cres.get("status")!="FUNCTION" or cres.get("function_location")!=floc:
                continue
            args=call["node"].get("args") or []
            if pidx>=len(args):
                argrec={"status":"MISSING_ARGUMENT","arg_index":pidx}
            else:
                arg=args[pidx]
                adecl,aname=local_decl(arg)
                aowner=idx.param_owner.get(adecl) if adecl is not None else None
                argrec={
                    "status":"ARGUMENT",
                    "arg_index":pidx,
                    "arg_ast":compact(arg),
                    "arg_local_decl":adecl,
                    "arg_local_name":aname,
                    "arg_is_parameter":aowner is not None,
                    "arg_parameter_owner_function":aowner["function"].get("location") if aowner else None,
                    "arg_parameter_index":aowner["param_index"] if aowner else None,
                    "static_value_candidate":bind_static(unwrap(arg),D),
                }
            calls.append({"call_location":call["node"].get("location"),"call_path":call["path"],
                          "call_owner_function":call["owner"],"callee_resolution":{
                              k:v for k,v in cres.items() if k!="node"},"argument":argrec})
        if not calls:cls="NO_DIRECT_STATIC_CALLS"
        elif any(c["argument"]["status"]=="MISSING_ARGUMENT" for c in calls):cls="CALLS_WITH_MISSING_ARGUMENT"
        else:cls="DIRECT_STATIC_CALLS"
        class_counts[cls]+=1;call_counts[name]+=len(calls)
        rows.append({
            "decl":decl,"name":name,"roots":sorted(root_uses[decl]),"classification":cls,
            "owner_function_location":floc,"owner_function_path":owner["function_path"],
            "param_index":pidx,"owner_arg_count":len(fn.get("args") or []),
            "maker_role":roles.get(decl),"call_site_count":len(calls),"call_sites":calls,
        })
    return {
        "schema":SCHEMA,"source_r182i":str(i_path),"source_file":str(source_path),
        "checkpoint":ri["checkpoint"],"source_sha256":got,
        "summary":{"parameters":len(rows),"classification_counts":dict(class_counts.most_common()),
                   "direct_call_sites":sum(x["call_site_count"] for x in rows if "call_site_count" in x)},
        "maker_info":role_meta,"parameters":rows,
        "interpretation_gate":{
            "direct_static_call_census_is_complete_dynamic_callgraph":False,
            "argument_ast_is_runtime_parameter_value":False,
            "static_value_candidate_is_runtime_value":False,
            "maker_role_proves_concrete_parameter_value":False,
            "parameter_recursion_authorized":False,
            "candidate_evaluation_authorized":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,"no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r182i",type=Path);ap.add_argument("source",type=Path)
    ap.add_argument("--expect-source-sha256",required=True)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r182i,a.source,a.expect_source_sha256)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        print("R182J:",json.dumps(out["summary"],sort_keys=True))
        print("maker_info:",json.dumps(out["maker_info"],sort_keys=True))
        for row in out["parameters"]:
            print(f"{row['name']} @ {row['decl']}: {row['classification']} param_index={row.get('param_index')} calls={row.get('call_site_count',0)} maker_role={json.dumps(row.get('maker_role'),sort_keys=True)}")
            for c in row.get("call_sites",[]):
                print("  call",c["call_location"],"arg",json.dumps(c["argument"],sort_keys=True,ensure_ascii=False))
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
