#!/usr/bin/env python3
"""R182F: candidate-evaluate recovered bxor argument ASTs from frozen snapshots and the selected base dump."""
from __future__ import annotations
import argparse, json, math, re, sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r182f-bxor-candidate-evaluation.v1"
TABLE_RE=re.compile(r"^LTable#(?P<tid>\d+)$")
BUILTIN_RE=re.compile(r"^Builtin\((?P<name>[^)]+)\)$")

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def load_loose(path):
    raw=Path(path).read_text(encoding="utf-8",errors="strict")
    try:
        return json.loads(raw)
    except ValueError:
        pass
    out=[];ins=False;esc=False;i=0
    while i<len(raw):
        ch=raw[i]
        if ins:
            out.append(ch)
            if esc:esc=False
            elif ch=="\\":esc=True
            elif ch=='"':ins=False
        elif ch=='"':
            ins=True;out.append(ch)
        elif ch==",":
            j=i+1
            while j<len(raw) and raw[j] in " \t\r\n":j+=1
            if j<len(raw) and raw[j] in "}]":
                i+=1;continue
            out.append(ch)
        else:
            out.append(ch)
        i+=1
    return json.loads("".join(out))

def checkpoint(obj):
    cp=obj.get("checkpoint",{}).get("expected",{})
    return (cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))

def integer_like(v):
    if isinstance(v,bool) or v is None:return None
    if isinstance(v,int):return v
    if isinstance(v,float):return int(v) if math.isfinite(v) and v.is_integer() else None
    if isinstance(v,str) and re.fullmatch(r"[+-]?\d+",v.strip()):
        return int(v.strip(),10)
    return None

def snapshot_env(entries):
    by=defaultdict(list)
    for e in entries:
        if isinstance(e,dict) and isinstance(e.get("name"),str):
            by[e["name"]].append(e.get("value"))
    out={};ambiguous={}
    for name,vals in by.items():
        uniq={repr(v):v for v in vals}
        if len(uniq)==1:
            out[name]=next(iter(uniq.values()))
        else:
            ambiguous[name]=list(uniq.values())
    return out,ambiguous

def local_names(node):
    out=set()
    if isinstance(node,dict):
        if node.get("type")=="AstExprLocal" and isinstance(node.get("name"),str):
            out.add(node["name"])
        for v in node.values():
            if isinstance(v,(dict,list)):out|=local_names(v)
    elif isinstance(node,list):
        for v in node:out|=local_names(v)
    return out

def raw_key(v):
    if isinstance(v,bool) or v is None:return None
    if isinstance(v,int):return v
    if isinstance(v,float) and math.isfinite(v) and v.is_integer():return int(v)
    if isinstance(v,str):return v
    if isinstance(v,dict):
        if "s" in v and isinstance(v["s"],str):
            try:return bytes.fromhex(v["s"])
            except ValueError:return ("bad-string",v["s"])
        if "num" in v:return ("special-number",v["num"])
        if "t" in v:return ("table",v["t"])
        if "f" in v:return ("builtin",v["f"])
    return ("opaque",repr(v))

def decode_value(v):
    if v is None or isinstance(v,(bool,int,float,str)):
        return {"kind":"scalar","value":v}
    if isinstance(v,dict):
        if "t" in v and isinstance(v["t"],int):
            return {"kind":"table","tid":v["t"],"value":f"LTable#{v['t']}"}
        if "f" in v and isinstance(v["f"],str):
            return {"kind":"builtin","name":v["f"],"value":f"Builtin({v['f']})"}
        if "num" in v:
            n=v["num"]
            if n=="inf":return {"kind":"scalar","value":float("inf")}
            if n=="-inf":return {"kind":"scalar","value":float("-inf")}
            if n=="-0":return {"kind":"scalar","value":-0.0}
            return {"kind":"unresolved","reason":f"special-number:{n}"}
        if "s" in v and isinstance(v["s"],str):
            try:return {"kind":"scalar","value":bytes.fromhex(v["s"])}
            except ValueError:return {"kind":"unresolved","reason":"invalid-hex-string"}
    return {"kind":"unresolved","reason":f"unsupported-dump-value:{type(v).__name__}"}

class BaseDump:
    def __init__(self,path):
        self.path=Path(path)
        self.obj=load_loose(self.path)
        tables=self.obj.get("tables") if isinstance(self.obj,dict) else None
        if not isinstance(tables,dict):
            raise ValueError("selected protos file lacks tables")
        self.tables=tables
        self.cache={}

    def raw_table(self,tid):
        raw=self.tables.get(str(tid),self.tables.get(tid))
        return raw if isinstance(raw,dict) else None

    def entries(self,tid):
        if tid in self.cache:return self.cache[tid]
        raw=self.raw_table(tid)
        if raw is None:
            self.cache[tid]=({},set());return self.cache[tid]
        entries={}
        arr=raw.get("arr") or []
        if not isinstance(arr,list):raise ValueError(f"table {tid} arr is not list")
        for i,v in enumerate(arr,1):
            if v is not None:entries[i]=v
        kv=raw.get("kv") or []
        if not isinstance(kv,list):raise ValueError(f"table {tid} kv is not list")
        for pos,pair in enumerate(kv):
            if not isinstance(pair,list) or len(pair)!=2:
                raise ValueError(f"table {tid} bad kv at {pos}")
            k,v=pair;key=raw_key(k)
            if v is None:entries.pop(key,None)
            else:entries[key]=v
        late=set(raw_key(x) for x in (raw.get("late") or []))
        self.cache[tid]=(entries,late)
        return self.cache[tid]

    def lookup(self,tid,key):
        entries,late=self.entries(tid)
        if key in late:
            return {"status":"UNRESOLVED","reason":"BASE_KEY_IS_LATE","tid":tid,"key":key}
        if key not in entries:
            return {"status":"UNRESOLVED","reason":"BASE_KEY_MISSING","tid":tid,"key":key}
        dec=decode_value(entries[key])
        if dec["kind"]=="unresolved":
            return {"status":"UNRESOLVED","reason":dec["reason"],"tid":tid,"key":key}
        return {"status":"VALUE","value":dec["value"],"value_kind":dec["kind"],
                "tid":tid,"key":key,"provenance":"BASE_DUMP_VALUE"}

def value_result(value,trace=None):
    return {"status":"VALUE","value":value,"trace":trace or []}

def unresolved(reason,trace=None):
    return {"status":"UNRESOLVED","reason":reason,"trace":trace or []}

def as_table(v):
    if isinstance(v,str):
        m=TABLE_RE.fullmatch(v)
        if m:return int(m.group("tid"))
    return None

def as_builtin(v):
    if isinstance(v,str):
        m=BUILTIN_RE.fullmatch(v)
        if m:return m.group("name")
    return None

def import_luasym():
    core=Path(__file__).resolve().parents[1]/"core"
    if str(core) not in sys.path:sys.path.insert(0,str(core))
    import luasym as S
    return S

def eval_ast(node,env,ambiguous,base,S,depth=0):
    if depth>16:return unresolved("MAX_DEPTH")
    if not isinstance(node,dict):return unresolved("NON_DICT_AST")
    t=node.get("type")
    if t=="AstExprConstantNumber":
        return value_result(node.get("value"),[{"op":"constant-number","value":node.get("value")}])
    if t=="AstExprConstantBool":
        return value_result(node.get("value"),[{"op":"constant-bool","value":node.get("value")}])
    if t=="AstExprConstantNil":
        return value_result(None,[{"op":"constant-nil"}])
    if t=="AstExprLocal":
        name=node.get("name")
        if not isinstance(name,str):return unresolved("LOCAL_WITHOUT_NAME")
        if name in ambiguous:return unresolved(f"AMBIGUOUS_LOCAL:{name}")
        if name not in env:return unresolved(f"LOCAL_NOT_IN_SNAPSHOT:{name}")
        return value_result(env[name],[{"op":"snapshot-local","name":name,"value":env[name]}])
    if t in ("AstExprGroup","AstExprTypeAssertion"):
        inner=eval_ast(node.get("expr"),env,ambiguous,base,S,depth+1)
        inner["trace"]=[{"op":"group","type":t}]+inner.get("trace",[])
        return inner
    if t=="AstExprIndexExpr":
        a=eval_ast(node.get("expr"),env,ambiguous,base,S,depth+1)
        if a["status"]!="VALUE":return unresolved("INDEX_BASE_UNRESOLVED",[a])
        b=eval_ast(node.get("index"),env,ambiguous,base,S,depth+1)
        if b["status"]!="VALUE":return unresolved("INDEX_KEY_UNRESOLVED",[a,b])
        tid=as_table(a["value"])
        if tid is None:return unresolved(f"INDEX_BASE_NOT_TABLE:{a['value']!r}",[a,b])
        key=b["value"]
        ik=integer_like(key)
        if ik is not None:key=ik
        hit=base.lookup(tid,key)
        if hit["status"]!="VALUE":
            return unresolved(hit["reason"],[a,b,hit])
        return value_result(hit["value"],[a,b,hit])
    if t=="AstExprCall":
        fn=eval_ast(node.get("func"),env,ambiguous,base,S,depth+1)
        if fn["status"]!="VALUE":return unresolved("CALL_FUNC_UNRESOLVED",[fn])
        builtin=as_builtin(fn["value"])
        if builtin is None:return unresolved(f"CALL_FUNC_NOT_BUILTIN:{fn['value']!r}",[fn])
        if not builtin.startswith("bit32."):
            return unresolved(f"CALL_BUILTIN_NOT_ALLOWED:{builtin}",[fn])
        func=S.CONCRETE.get(builtin)
        if func is None:return unresolved(f"CALL_BUILTIN_UNSUPPORTED:{builtin}",[fn])
        args=[]
        traces=[fn]
        for arg in node.get("args") or []:
            r=eval_ast(arg,env,ambiguous,base,S,depth+1)
            traces.append(r)
            if r["status"]!="VALUE":return unresolved(f"CALL_ARG_UNRESOLVED:{builtin}",traces)
            nv=integer_like(r["value"])
            if nv is None:
                if not isinstance(r["value"],(int,float)) or isinstance(r["value"],bool):
                    return unresolved(f"CALL_ARG_NONNUMERIC:{builtin}:{r['value']!r}",traces)
                nv=r["value"]
            args.append(nv)
        try:
            val=func(*args)
        except Exception as exc:
            return unresolved(f"CALL_EVAL_FAILED:{builtin}:{type(exc).__name__}",traces)
        return value_result(val,traces+[{"op":"bit32-call","builtin":builtin,"args":args,"value":val}])
    return unresolved(f"UNSUPPORTED_AST_TYPE:{t}")

def collect_unresolved_reasons(result):
    out=[]
    if isinstance(result,dict):
        if result.get("status")=="UNRESOLVED" and isinstance(result.get("reason"),str):
            out.append(result["reason"])
        for item in result.get("trace",[]) if isinstance(result.get("trace"),list) else []:
            out.extend(collect_unresolved_reasons(item))
    elif isinstance(result,list):
        for item in result:out.extend(collect_unresolved_reasons(item))
    return out

def require_inputs(c,e):
    if c.get("schema")!="luraph-deobf.r182c-base-sub-consistency.v1":
        raise ValueError("expected R182C receipt")
    if e.get("schema")!="luraph-deobf.r182e-source-call-arg-recovery.v2":
        raise ValueError("expected R182E-v2 receipt")
    if checkpoint(c)!=(78,64,0,594) or checkpoint(e)!=(78,64,0,594):
        raise ValueError("checkpoint != 78/64/0/594")
    crows=c.get("instances",[]);erows=e.get("instances",[])
    calls=[x for x in crows if isinstance(x,dict) and x.get("right_type")=="AstExprCall"]
    if len(calls)!=41 or len(erows)!=41:
        raise ValueError(f"expected 41 call rows, found {len(calls)}/{len(erows)}")
    by={x.get("instance_index"):x for x in calls}
    if len(by)!=41 or None in by:raise ValueError("R182C call instance_index is not unique/complete")
    return by,erows

def selected_base(c):
    sel=c.get("selected_base_snapshot") or {}
    path=Path(sel.get("path",""))
    sha=sel.get("sha256")
    if not path.is_file():raise ValueError(f"selected protos file not found: {path}")
    import hashlib
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    got=h.hexdigest()
    if not isinstance(sha,str) or got.lower()!=sha.lower():
        raise ValueError(f"selected protos SHA mismatch: got {got}, expected {sha}")
    return sel,path

def analyze(c_path,e_path):
    c=load(c_path);e=load(e_path)
    cby,erows=require_inputs(c,e)
    sel,protos=selected_base(c)
    base=BaseDump(protos);S=import_luasym()
    rows=[];classes=Counter();reasons=Counter();shape=Counter();local_inventory=Counter()
    bxor_values=Counter();sub_values=Counter()
    for er in erows:
        idx=er.get("instance_index")
        cr=cby.get(idx)
        if cr is None:raise ValueError(f"R182E instance {idx} has no R182C call row")
        for key in ("function_id","state_id"):
            if er.get(key)!=cr.get(key):raise ValueError(f"R182C/R182E join mismatch at {idx}: {key}")
        args=er.get("args")
        if not isinstance(args,list) or len(args)!=2:raise ValueError(f"R182E instance {idx} argc != 2")
        env,amb=snapshot_env(er.get("local_snapshot_entries",[]))
        needed=sorted(local_names(args))
        for name in needed:
            if name in amb:local_inventory[f"{name}=AMBIGUOUS"]+=1
            elif name in env:local_inventory[f"{name}={env[name]!r}"]+=1
            else:local_inventory[f"{name}=MISSING"]+=1
        a0=eval_ast(args[0],env,amb,base,S)
        a1=eval_ast(args[1],env,amb,base,S)
        if a0["status"]=="VALUE" and a1["status"]=="VALUE":
            try:
                bx=S.CONCRETE["bit32.bxor"](a0["value"],a1["value"])
            except Exception as exc:
                cls="OUTER_BXOR_EVAL_FAILED";reasons[type(exc).__name__]+=1
                row={"instance_index":idx,"function_id":er.get("function_id"),"state_id":er.get("state_id"),
                     "left_snapshot":cr.get("left_snapshot"),"arg0":a0,"arg1":a1,"classification":cls}
            else:
                left=integer_like(cr.get("left_snapshot"))
                if left is None:
                    cls="LEFT_NOT_INTEGER_LIKE";reasons[cls]+=1
                    row={"instance_index":idx,"function_id":er.get("function_id"),"state_id":er.get("state_id"),
                         "left_snapshot":cr.get("left_snapshot"),"arg0":a0,"arg1":a1,
                         "candidate_bxor":bx,"classification":cls}
                else:
                    sub=left-bx
                    cls="FULL_CANDIDATE_NEG1" if sub==-1 else "FULL_CANDIDATE_OTHER"
                    bxor_values[repr(bx)]+=1;sub_values[repr(sub)]+=1
                    row={"instance_index":idx,"function_id":er.get("function_id"),"state_id":er.get("state_id"),
                         "left_snapshot":left,"arg0":a0,"arg1":a1,
                         "candidate_bxor":bx,"candidate_sub":sub,"classification":cls}
        else:
            cls="ARGUMENT_UNRESOLVED"
            for ar in (a0,a1):
                if ar["status"]!="VALUE":
                    found=collect_unresolved_reasons(ar)
                    if not found:found=["UNKNOWN"]
                    for reason in found:reasons[reason]+=1
            row={"instance_index":idx,"function_id":er.get("function_id"),"state_id":er.get("state_id"),
                 "left_snapshot":cr.get("left_snapshot"),"arg0":a0,"arg1":a1,"classification":cls}
        classes[cls]+=1
        shape[(er.get("arg_shapes") or ["?","?"])[0]+" | "+(er.get("arg_shapes") or ["?","?"])[1]]+=1
        rows.append(row)
    return {
        "schema":SCHEMA,
        "sources":{"r182c":str(c_path),"r182e":str(e_path),"protos":str(protos)},
        "checkpoint":c["checkpoint"],
        "selected_base_snapshot":sel,
        "summary":{"call_instances":41,
                   "full_candidate_neg1":classes["FULL_CANDIDATE_NEG1"],
                   "full_candidate_other":classes["FULL_CANDIDATE_OTHER"],
                   "argument_unresolved":classes["ARGUMENT_UNRESOLVED"],
                   "left_not_integer_like":classes["LEFT_NOT_INTEGER_LIKE"],
                   "outer_bxor_eval_failed":classes["OUTER_BXOR_EVAL_FAILED"]},
        "unresolved_reasons":dict(reasons.most_common()),
        "arg_shape_pairs":dict(shape.most_common()),
        "snapshot_local_inventory":dict(local_inventory.most_common()),
        "candidate_bxor_values":dict(bxor_values.most_common()),
        "candidate_sub_values":dict(sub_values.most_common()),
        "instances":rows,
        "interpretation_gate":{
            "snapshot_local_value_is_failure_time_value":False,
            "base_table_lookup_is_failure_time_value":False,
            "candidate_bit32_evaluation_is_runtime_proof":False,
            "full_candidate_neg1_is_arithmetic_origin_proof":False,
            "per_state_overlay_applied":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,"no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r182c",type=Path);ap.add_argument("r182e",type=Path)
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r182c,a.r182e)
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False,default=repr)+"\n",encoding="utf-8")
        s=out["summary"]
        print(f"R182F: calls={s['call_instances']} neg1={s['full_candidate_neg1']} other={s['full_candidate_other']} unresolved={s['argument_unresolved']} left_bad={s['left_not_integer_like']} bxor_fail={s['outer_bxor_eval_failed']}")
        print("unresolved_reasons:",json.dumps(out["unresolved_reasons"],sort_keys=True))
        print("snapshot_locals:",json.dumps(out["snapshot_local_inventory"],sort_keys=True))
        print("bxor_values:",json.dumps(out["candidate_bxor_values"],sort_keys=True))
        print("sub_values:",json.dumps(out["candidate_sub_values"],sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
