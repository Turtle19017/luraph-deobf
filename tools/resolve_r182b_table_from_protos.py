#!/usr/bin/env python3
"""R182B: resolve selected base entries of a captured Luraph table from saved .protos.json files."""
from __future__ import annotations
import argparse, hashlib, json, math
from pathlib import Path

SCHEMA = "luraph-deobf.r182b-base-table-resolution.v1"

def load_loose(path):
    raw = Path(path).read_text(encoding="utf-8", errors="strict")
    try:
        return json.loads(raw)
    except ValueError:
        pass
    out=[]; in_str=False; esc=False; i=0
    while i < len(raw):
        ch=raw[i]
        if in_str:
            out.append(ch)
            if esc: esc=False
            elif ch=="\\": esc=True
            elif ch=='"': in_str=False
        elif ch=='"':
            in_str=True; out.append(ch)
        elif ch==",":
            j=i+1
            while j<len(raw) and raw[j] in " \t\r\n": j+=1
            if j<len(raw) and raw[j] in "}]":
                i+=1; continue
            out.append(ch)
        else:
            out.append(ch)
        i+=1
    return json.loads("".join(out))

def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def candidate_files(inputs):
    out=[]
    for p in inputs:
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(x for x in p.rglob("*.protos.json") if x.is_file())
        else:
            raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(x.resolve() for x in out))

def decode_key(v):
    if isinstance(v,bool) or v is None:
        return None
    if isinstance(v,int):
        return v
    if isinstance(v,float):
        return int(v) if math.isfinite(v) and v.is_integer() else v
    if isinstance(v,str):
        return v
    if isinstance(v,dict):
        if "s" in v and isinstance(v["s"],str):
            try: return bytes.fromhex(v["s"])
            except ValueError: return ("encoded-string",v["s"])
        if "num" in v:
            n=v["num"]
            return {"inf":float("inf"),"-inf":float("-inf"),"nan":float("nan"),"-0":-0.0}.get(n,("num",n))
        if "t" in v: return ("table",v["t"])
        if "f" in v: return ("builtin",v["f"])
        if "g" in v: return ("global",v["g"])
    return ("opaque-key",repr(v))

def value_summary(v):
    if v is None:
        return {"kind":"nil","known_scalar":True,"value":None}
    if isinstance(v,bool):
        return {"kind":"bool","known_scalar":True,"value":v}
    if isinstance(v,int):
        return {"kind":"int","known_scalar":True,"value":v}
    if isinstance(v,float):
        return {"kind":"float","known_scalar":True,"value":v}
    if isinstance(v,str):
        return {"kind":"str","known_scalar":True,"value":v}
    if isinstance(v,dict):
        if "s" in v and isinstance(v["s"],str):
            try:
                b=bytes.fromhex(v["s"])
                return {"kind":"bytes","known_scalar":True,"hex":v["s"],"length":len(b),
                        "latin1_preview":b[:80].decode("latin-1","replace")}
            except ValueError:
                return {"kind":"encoded-string-invalid","known_scalar":False,"raw":v}
        if "t" in v:
            return {"kind":"table-ref","known_scalar":False,"table_id":v["t"],"repr":f"LTable#{v['t']}"}
        if "f" in v:
            return {"kind":"builtin","known_scalar":False,"name":v["f"],"repr":f"Builtin({v['f']})"}
        if "lf" in v:
            return {"kind":"lua-func-ref","known_scalar":False,"id":v["lf"]}
        if "num" in v:
            return {"kind":"special-number","known_scalar":True,"value":v["num"]}
        if "b" in v and isinstance(v["b"],str):
            return {"kind":"buffer","known_scalar":False,"hex_length":len(v["b"])}
        if "g" in v:
            return {"kind":"global-or-builtin","known_scalar":False,"value":v["g"]}
        if "vec" in v:
            return {"kind":"vector","known_scalar":False,"length":len(v["vec"]) if isinstance(v["vec"],list) else None}
    return {"kind":"opaque","known_scalar":False,"raw":v}

def table_entries(raw_table):
    entries={}
    arr=raw_table.get("arr") or []
    if not isinstance(arr,list):
        raise ValueError("table arr is not a list")
    for i,v in enumerate(arr,1):
        if v is not None:
            entries[i]={"source":"arr","raw":v}
    kv=raw_table.get("kv") or []
    if not isinstance(kv,list):
        raise ValueError("table kv is not a list")
    for pos,pair in enumerate(kv):
        if not isinstance(pair,list) or len(pair)!=2:
            raise ValueError(f"bad kv entry at position {pos}")
        k,v=pair
        key=decode_key(k)
        if v is not None:
            entries[key]={"source":"kv","kv_position":pos,"raw_key":k,"raw":v}
        else:
            entries.pop(key,None)
    return entries

def inspect_file(path,table_id,keys):
    obj=load_loose(path)
    tables=obj.get("tables") if isinstance(obj,dict) else None
    if not isinstance(tables,dict):
        return {"path":str(path),"sha256":sha256_file(path),"status":"NO_TABLES"}
    raw=tables.get(str(table_id))
    if raw is None:
        raw=tables.get(table_id)
    if not isinstance(raw,dict):
        return {"path":str(path),"sha256":sha256_file(path),"status":"TABLE_ABSENT","table_id":table_id}

    entries=table_entries(raw)
    late=set()
    for item in raw.get("late") or []:
        late.add(decode_key(item))
    rows=[]
    for key in keys:
        entry=entries.get(key)
        if entry is None:
            rows.append({"key":key,"status":"MISSING","late":key in late})
            continue
        summary=value_summary(entry["raw"])
        rows.append({
            "key":key,
            "status":"FOUND_SCALAR" if summary.get("known_scalar") else "FOUND_NONSCALAR",
            "late":key in late,
            "source":entry["source"],
            "kv_position":entry.get("kv_position"),
            "value":summary,
        })
    pid=(obj.get("pid_of_table") or {}).get(str(table_id)) if isinstance(obj.get("pid_of_table"),dict) else None
    return {
        "path":str(path),"sha256":sha256_file(path),"status":"TABLE_FOUND","table_id":table_id,
        "arr_len":len(raw.get("arr") or []),"kv_len":len(raw.get("kv") or []),
        "has_mt":bool(raw.get("mt")),"has_mtf":bool(raw.get("mtf")),"pid":pid,
        "late_key_count":len(late),"requested_keys":rows,
        "all_requested_found":all(x["status"]!="MISSING" for x in rows),
        "all_requested_scalar":all(x["status"]=="FOUND_SCALAR" for x in rows),
    }

def analyze(inputs,table_id=369,keys=(165,356,1008,1490,1524)):
    paths=candidate_files(inputs)
    if not paths:
        raise ValueError("no .protos.json candidates found")
    reports=[inspect_file(p,table_id,keys) for p in paths]
    found=[x for x in reports if x.get("status")=="TABLE_FOUND"]
    return {
        "schema":SCHEMA,
        "requirements":{"table_id":table_id,"keys":list(keys)},
        "summary":{
            "candidate_files":len(paths),
            "files_with_table":len(found),
            "files_with_all_requested_keys":sum(bool(x.get("all_requested_found")) for x in found),
            "files_with_all_requested_scalar":sum(bool(x.get("all_requested_scalar")) for x in found),
        },
        "files":reports,
        "interpretation_gate":{
            "base_dump_only":True,
            "per_state_overlay_applied":False,
            "base_value_proves_failure_time_value":False,
            "late_value_is_reported_not_replayed":True,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,
        "no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs",nargs="+",type=Path,help="saved .protos.json files or directories to search")
    ap.add_argument("--table-id",type=int,default=369)
    ap.add_argument("--keys",type=int,nargs="+",default=[165,356,1008,1490,1524])
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.inputs,a.table_id,tuple(a.keys))
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"]
        print(f"R182B: candidates={s['candidate_files']} with_table={s['files_with_table']} all_keys={s['files_with_all_requested_keys']} all_scalar={s['files_with_all_requested_scalar']}")
        for f in out["files"]:
            if f.get("status")=="TABLE_FOUND":
                vals={str(x["key"]):x.get("value",{}).get("value",x.get("value",{}).get("repr",x["status"])) for x in f["requested_keys"]}
                print(f"{f['path']}: {json.dumps(vals,sort_keys=True)}")
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
