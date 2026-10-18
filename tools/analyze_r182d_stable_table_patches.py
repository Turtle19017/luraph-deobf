#!/usr/bin/env python3
"""R182D: recover serialized stable table-patch candidates for table 369 from frozen artifacts."""
from __future__ import annotations
import argparse, json, math, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA="luraph-deobf.r182d-stable-table-patch-census.v1"
SUFFIX={".json",".jsonl",".log",".txt",".md"}
TABLE_OP_RE=re.compile(r"/=(?P<key>-?\d+):(?P<value>[^/;\r\n]+)")
SEG_RE=re.compile(r"(?:^|;)(?P<head>[^;\r\n]+?)(?P<ops>(?:/=-?\d+:[^/;\r\n]+)+)(?=;|$)")

def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8",errors="strict"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError):
        return None

def load_loose(path):
    raw=Path(path).read_text(encoding="utf-8",errors="strict")
    try: return json.loads(raw)
    except ValueError: pass
    out=[];ins=False;esc=False;i=0
    while i<len(raw):
        ch=raw[i]
        if ins:
            out.append(ch)
            if esc: esc=False
            elif ch=="\\": esc=True
            elif ch=='"': ins=False
        elif ch=='"':
            ins=True;out.append(ch)
        elif ch==",":
            j=i+1
            while j<len(raw) and raw[j] in " \t\r\n":j+=1
            if j<len(raw) and raw[j] in "}]":
                i+=1;continue
            out.append(ch)
        else: out.append(ch)
        i+=1
    return json.loads("".join(out))

def evidence_files(inputs):
    out=[]
    for p in inputs:
        if p.is_file(): out.append(p)
        elif p.is_dir(): out.extend(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in SUFFIX)
        else: raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(x.resolve() for x in out))

def strings(v,path="$"):
    if isinstance(v,dict):
        for k,x in v.items(): yield from strings(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v): yield from strings(x,f"{path}[{i}]")
    elif isinstance(v,str):
        yield path,v

def table_ref(v):
    if isinstance(v,dict) and isinstance(v.get("t"),int) and not isinstance(v.get("t"),bool):
        return v["t"]
    return None

def raw_int_key(v):
    if isinstance(v,bool) or v is None:return None
    if isinstance(v,int):return v
    if isinstance(v,float) and math.isfinite(v) and v.is_integer():return int(v)
    return None

def child_refs(raw_table):
    arr=raw_table.get("arr") or []
    if isinstance(arr,list):
        for i,v in enumerate(arr,1):
            tid=table_ref(v)
            if tid is not None: yield i,tid
    kv=raw_table.get("kv") or []
    if isinstance(kv,list):
        for pair in kv:
            if isinstance(pair,list) and len(pair)==2:
                key=raw_int_key(pair[0]); tid=table_ref(pair[1])
                if key is not None and tid is not None: yield key,tid

def derive_paths(protos_path):
    obj=load_loose(protos_path)
    tables=obj.get("tables") if isinstance(obj,dict) else None
    protos=obj.get("protos") if isinstance(obj,dict) else None
    if not isinstance(tables,dict) or not isinstance(protos,dict):
        raise ValueError("selected .protos.json lacks tables/protos")
    paths={};queue=[]
    for cap in protos.values():
        if not isinstance(cap,dict):continue
        seq=cap.get("__seq")
        if isinstance(seq,bool) or not isinstance(seq,(int,float)):continue
        if isinstance(seq,float):
            if not seq.is_integer():continue
            seq=int(seq)
        for name,v in cap.items():
            tid=table_ref(v)
            if tid is not None and tid not in paths:
                paths[tid]=[seq,name]
                if name!="e":queue.append(tid)
    overrides=obj.get("overrides") or []
    if isinstance(overrides,list):
        for pair in overrides:
            if not isinstance(pair,list) or len(pair)!=2:continue
            path,v=pair
            tid=table_ref(v)
            if tid is not None and tid not in paths and isinstance(path,str) and not path.startswith("!"):
                paths[tid]=path.split(",");queue.append(tid)
    pos=0
    while pos<len(queue):
        tid=queue[pos];pos+=1
        raw=tables.get(str(tid),tables.get(tid))
        if not isinstance(raw,dict):continue
        for key,child in child_refs(raw):
            if child not in paths:
                paths[child]=paths[tid]+[key];queue.append(child)
    return obj,paths

def select_snapshot(r182b,prefix):
    obj=load_json(r182b)
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r182b-base-table-resolution.v1":
        raise ValueError("expected R182B receipt")
    if len(prefix)<8 or not re.fullmatch(r"[0-9a-fA-F]+",prefix):
        raise ValueError("protos SHA prefix must be >=8 hex chars")
    hits=[f for f in obj.get("files",[]) if isinstance(f,dict) and isinstance(f.get("sha256"),str)
          and f["sha256"].lower().startswith(prefix.lower())]
    if len(hits)!=1:raise ValueError(f"protos SHA prefix matched {len(hits)} candidates")
    row=hits[0]
    if row.get("status")!="TABLE_FOUND" or row.get("table_id")!=369:
        raise ValueError("selected R182B candidate is not TABLE_FOUND tid 369")
    p=Path(row.get("path",""))
    if not p.is_file():raise ValueError(f"selected .protos.json not found: {p}")
    return obj,row,p

def parse_num(text):
    t=text.strip()
    if re.fullmatch(r"[+-]?\d+",t):return int(t,10)
    try:
        v=float(t)
        return v
    except ValueError:
        return None

def parse_patch_string(text,target_path,required_keys):
    hits=[]
    probe=text.strip()
    if probe.startswith("+"):probe=probe[1:]
    for m in SEG_RE.finditer(probe):
        head=m.group("head")
        # A prefix such as "patches=" may wrap the first segment in plain logs.
        if head!=target_path:
            if head.endswith(target_path):
                prefix=head[:-len(target_path)]
                if prefix and prefix[-1] not in "=:+ \t":
                    continue
            else:
                continue
        for op in TABLE_OP_RE.finditer(m.group("ops")):
            key=int(op.group("key"));raw=op.group("value").strip()
            if key in required_keys:
                hits.append({"key":key,"raw_value":raw,"numeric_value":parse_num(raw)})
    return hits

def scan(inputs,target_path,required_keys):
    events=[];seen=set()
    def add(source,line,json_path,text):
        for hit in parse_patch_string(text,target_path,required_keys):
            sig=(source,line,json_path,hit["key"],hit["raw_value"])
            if sig in seen:continue
            seen.add(sig)
            events.append({"source":source,"line":line,"json_path":json_path,**hit})
    for p in evidence_files(inputs):
        if p.suffix.lower()==".json":
            obj=load_json(p)
            if obj is not None:
                for jp,text in strings(obj):add(str(p),None,jp,text)
            continue
        try:lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError:continue
        for n,line in enumerate(lines,1):
            add(str(p),n,None,line)
            for start in sorted(x for x in {line.find("{"),line.find("[")} if x>=0):
                try:obj=json.loads(line[start:].strip())
                except json.JSONDecodeError:continue
                for jp,text in strings(obj):add(str(p),n,jp,text)
                break
    return events

def analyze(r182b_path,evidence_inputs,sha_prefix,table_id=369,keys=(165,356,1008,1490,1524)):
    _,selected,p=select_snapshot(r182b_path,sha_prefix)
    _,paths=derive_paths(p)
    if table_id not in paths:
        raise ValueError(f"no canonical captured path for table {table_id}")
    target=",".join(str(x) for x in paths[table_id])
    required=set(keys)
    events=scan(evidence_inputs,target,required)
    by=defaultdict(list)
    for e in events:by[e["key"]].append(e)
    rows=[];classes=Counter()
    for key in keys:
        ev=by.get(key,[])
        nums={repr(x["numeric_value"]):x["numeric_value"] for x in ev if x["numeric_value"] is not None}
        raws=sorted({x["raw_value"] for x in ev})
        if not ev:cls="NO_SERIALIZED_PATCH"
        elif len(nums)==1 and all(x["numeric_value"] is not None for x in ev):cls="UNIQUE_NUMERIC_PATCH_CANDIDATE"
        elif len(nums)>1:cls="CONFLICTING_NUMERIC_PATCH_CANDIDATES"
        else:cls="NONNUMERIC_OR_MIXED_PATCH_CANDIDATE"
        classes[cls]+=1
        rows.append({"key":key,"classification":cls,"unique_raw_values":raws,
                     "unique_numeric_values":list(nums.values()),"events":ev})
    return {
        "schema":SCHEMA,
        "selected_snapshot":{"path":str(p),"sha256":selected["sha256"],"table_id":table_id,
                             "canonical_table_path":target},
        "required_keys":list(keys),
        "summary":{"patch_events":len(events),"keys_with_any_patch":sum(bool(by.get(k)) for k in keys),
                   "unique_numeric_patch_keys":classes["UNIQUE_NUMERIC_PATCH_CANDIDATE"],
                   "conflicting_numeric_patch_keys":classes["CONFLICTING_NUMERIC_PATCH_CANDIDATES"],
                   "no_serialized_patch_keys":classes["NO_SERIALIZED_PATCH"]},
        "keys":rows,
        "interpretation_gate":{
            "stable_patch_candidate_is_failure_time_overlay":False,
            "absence_means_no_serialized_patch_in_scanned_evidence_only":True,
            "conflicting_patch_values_are_not_resolved":True,
            "base_value_replacement_authorized":False,
            "arithmetic_origin_proved":False,
            "frame_base_bug_proved":False,
            "semantic_change_authorized":False,
        },
        "no_lift_rerun":True,"no_attribution_rerun":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("r182b",type=Path);ap.add_argument("evidence",nargs="+",type=Path)
    ap.add_argument("--protos-sha-prefix",required=True)
    ap.add_argument("--table-id",type=int,default=369)
    ap.add_argument("--keys",type=int,nargs="+",default=[165,356,1008,1490,1524])
    ap.add_argument("--json-out",type=Path,required=True)
    a=ap.parse_args()
    try:
        out=analyze(a.r182b,a.evidence,a.protos_sha_prefix,a.table_id,tuple(a.keys))
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        s=out["summary"]
        print(f"R182D: path={out['selected_snapshot']['canonical_table_path']} events={s['patch_events']} keys_with_patch={s['keys_with_any_patch']} unique={s['unique_numeric_patch_keys']} conflicting={s['conflicting_numeric_patch_keys']} no_patch={s['no_serialized_patch_keys']}")
        for row in out["keys"]:
            print(f"key {row['key']}: {row['classification']} values={row['unique_raw_values']}")
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
