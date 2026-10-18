#!/usr/bin/env python3
"""R179B v3: accepted underflow census keyed only by graph_error_states.state_id."""
from __future__ import annotations
import argparse,json,re
from collections import Counter,defaultdict
from pathlib import Path
SCHEMA="luraph-deobf.r179b-underflow-artifact-census.v3"
SUFFIX={".json",".jsonl",".log",".md",".txt"}
UF=re.compile(r"(?P<op>read|store) below the stack VM's frame \(register (?P<reg>-?\d+)\)")
AT=re.compile(r"\(at (?P<mode>-?\d+):(?P<pc>-?\d+)\)")
FAMS={"underflow":49,"symbolic_control":5,"missing_condition":9,"nil_bxor":1}
IDKEYS={"state_id","graph_state_id","error_state_id","source_state_id","backend_state_id","resolved_state_id","final_state_id"}
def family(e):
 if UF.search(e):return"underflow"
 if"symbolic next pc/mode:"in e:return"symbolic_control"
 if"needs a constant that is not decoded yet"in e:return"missing_condition"
 if"bit32.bxor failed:"in e:return"nil_bxor"
 return"other"
def fs(inputs):
 out=[]
 for p in inputs:
  if p.is_file():out.append(p)
  elif p.is_dir():out += [x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in SUFFIX]
  else:raise ValueError(f"input not found: {p}")
 return sorted(dict.fromkeys(out))
def load(p):
 try:return json.loads(p.read_text(encoding="utf-8",errors="strict"))
 except(OSError,UnicodeDecodeError,json.JSONDecodeError):return None
def lists(v,path="$"):
 if isinstance(v,list):
  yield path,v
  for i,x in enumerate(v):yield from lists(x,f"{path}[{i}]")
 elif isinstance(v,dict):
  for k,x in v.items():yield from lists(x,f"{path}.{k}")
def dicts(v):
 if isinstance(v,dict):
  yield v
  for x in v.values():yield from dicts(x)
 elif isinstance(v,list):
  for x in v:yield from dicts(x)
def checkpoint(F):
 hits=[]
 for p in F:
  o=load(p) if p.suffix.lower()==".json" else None
  if isinstance(o,dict) and isinstance(o.get("stats"),dict):
   s=o["stats"]
   if(s.get("functions"),s.get("errors"),s.get("fallbacks"),o.get("requests"))==(78,64,0,594):hits.append((p,o.get("output_sha256")))
 if not hits:raise ValueError("accepted checkpoint manifest (78,64,0,594) not found")
 h={x for _,x in hits if x}
 if len(h)>1:raise ValueError("checkpoint output hash conflict")
 return{"sources":[str(p)for p,_ in hits],"output_sha256":next(iter(h),None)}
def graph(F):
 C=[]
 for p in F:
  if p.name!="graph_error_states.json":continue
  o=load(p)
  if o is None:continue
  for jp,xs in lists(o):
   if len(xs)!=64 or not all(isinstance(x,dict)for x in xs):continue
   ids=[x.get("state_id")for x in xs]
   if not all(isinstance(x,(str,int))and not isinstance(x,bool)for x in ids):continue
   ids=[str(x)for x in ids]
   if len(set(ids))==64:C.append((p,jp,xs,tuple(sorted(ids))))
 if not C:raise ValueError("graph_error_states.json has no 64-record list with 64 unique state_id values")
 G=defaultdict(list)
 for c in C:G[c[3]].append(c)
 if len(G)!=1:raise ValueError("conflicting graph_error_states state_id universes")
 g=next(iter(G.values()));p,jp,xs,ids=g[0]
 return{"records":xs,"ids":set(ids),"source":f"{p}:{jp}","files":{str(x[0])for x in g}}
def refs(v,valid):
 out=set()
 if isinstance(v,dict):
  for k,x in v.items():
   kl=str(k).lower()
   if kl in IDKEYS or kl.endswith("_state_id"):
    if isinstance(x,(str,int))and not isinstance(x,bool)and str(x)in valid:out.add(str(x))
   out|=refs(x,valid)
 elif isinstance(v,list):
  for x in v:out|=refs(x,valid)
 return out
def err(rec):
 x=rec.get("error")
 return x if isinstance(x,str)and x else None
def error_map(F,G):
 d={}
 for r in G["records"]:
  e=err(r)
  if not e:d={};break
  d[str(r["state_id"]) ]={"error":e,"record":r,"source":G["source"],"join":"graph_record.error"}
 if len(d)==64 and dict(Counter(family(x["error"])for x in d.values()))==FAMS:return d
 C=[]
 for p in F:
  if str(p)in G["files"]or p.suffix.lower()!=".json":continue
  o=load(p)
  if o is None:continue
  for jp,xs in lists(o):
   if len(xs)!=64 or not all(isinstance(x,dict)for x in xs):continue
   m={}
   for r in xs:
    e=err(r);rr=refs(r,G["ids"])
    if not e or len(rr)!=1:m={};break
    sid=next(iter(rr))
    if sid in m:m={};break
    m[sid]={"error":e,"record":r,"source":f"{p}:{jp}","join":"explicit_state_id_reference"}
   if set(m)==G["ids"]and dict(Counter(family(x["error"])for x in m.values()))==FAMS:C.append(m)
 if not C:raise ValueError("no provenance-complete 64-record error census maps to graph_error_states.state_id; refusing order/diagnostic-based identity synthesis")
 U=defaultdict(list)
 for m in C:U[tuple(sorted((k,v["error"])for k,v in m.items()))].append(m)
 if len(U)!=1:raise ValueError("conflicting provenance-complete error censuses")
 return next(iter(U.values()))[0]
def parse(e):
 m=UF.search(e)
 if not m:return None
 a=AT.search(e)
 return{"operation":m.group("op"),"register":int(m.group("reg")),"mode":int(a.group("mode"))if a else None,"pc":int(a.group("pc"))if a else None}
def jline(line):
 for i in sorted(x for x in{0,line.find("{"),line.find("[")}if x>=0):
  try:return json.loads(line[i:].strip())
  except json.JSONDecodeError:pass
 return None
def auxrec(r,p,valid,line=None):
 rr=refs(r,valid)
 if len(rr)!=1:return None
 sid=next(iter(rr));kind=r.get("kind");e=str(r.get("error")or r.get("exception")or"")
 if kind in("below_stack","below_stack_store"):
  reg=r.get("register")
  if not isinstance(reg,int)or isinstance(reg,bool):return None
  x={"operation":"read"if kind=="below_stack"else"store","register":reg,"mode":r.get("mode"),"pc":r.get("pc")}
 else:
  x=parse(e)
  if not x:return None
 jr=r.get("jump_regs")if isinstance(r.get("jump_regs"),list)else[];facts=str(r.get("facts")or r.get("step_facts")or"")
 return{"state_id":sid,"source":str(p),"line":line,**x,"stack_base":r.get("stack_base"),"last_op":r.get("last_op")or r.get("op"),"proto":r.get("proto"),"function":r.get("function"),"walk":r.get("walk"),"in_jump_regs":x["register"]in jr,"zero_slot_nil_fact_hint":bool(x["register"]==0 and re.search(r"0\s*:\s*\(['\"]c['\"]\s*,\s*None\)",facts))}
def scan(F,G):
 out=[]
 for p in F:
  if str(p)in G["files"]:continue
  if p.suffix.lower()==".json":
   o=load(p)
   if o is not None:
    for r in dicts(o):
     a=auxrec(r,p,G["ids"])
     if a:out.append(a)
    continue
  try:
   for n,line in enumerate(p.read_text(encoding="utf-8",errors="replace").splitlines(),1):
    o=jline(line)
    if o is not None:
     for r in dicts(o):
      a=auxrec(r,p,G["ids"],n)
      if a:out.append(a)
  except OSError:pass
 return out
def analyze(inputs,expect_unique=49):
 F=fs(inputs);cp=checkpoint(F);G=graph(F);M=error_map(F,G);gb={str(x["state_id"]):x for x in G["records"]};sites=[]
 for sid,item in M.items():
  x=parse(item["error"])
  if not x:continue
  r=item["record"];q=gb[sid];row={"state_id":sid,"error":item["error"],**x,"identity_source":G["source"],"error_source":item["source"],"provenance_join":item["join"]}
  for k in("stack_base","last_op","proto","function","walk","in_jump_regs","zero_slot_nil_fact_hint"):
   row[k]=r.get(k)if r.get(k)is not None else q.get(k)
  sites.append(row)
 if expect_unique is not None and len(sites)!=expect_unique:raise ValueError(f"provenance-resolved accepted-node universe has {len(sites)} underflows, expected {expect_unique}")
 A=scan(F,G);by=defaultdict(list)
 for r in A:by[r["state_id"]].append(r)
 enriched=0
 for s in sites:
  C=by.get(s["state_id"],[])
  if not C:s["enrichment_status"]="NO_EXPLICIT_STATE_ID_MATCH";continue
  b=max(C,key=lambda r:sum(r.get(k)is not None for k in("stack_base","last_op","proto","function","walk")));enriched+=1;s["enrichment_status"]="MATCHED_EXPLICIT_STATE_ID"
  for k in("stack_base","last_op","proto","function","walk","in_jump_regs","zero_slot_nil_fact_hint"):
   if b.get(k)is not None:s[k]=b[k]
 C=Counter();BR=Counter()
 for s in sites:
  reg=s["register"];bucket="ZERO_SLOT"if reg==0 else"NEGATIVE_SLOT"if reg<0 else"UNPARSED";s["bucket"]=bucket;C[s["operation"]]+=1;C[bucket]+=1;BR[str(reg)]+=1
  if s.get("in_jump_regs"):C["jump"]+=1
  if s.get("zero_slot_nil_fact_hint"):C["nilhint"]+=1
  if s.get("stack_base")is None:C["nostack"]+=1
 return{"schema":SCHEMA,"checkpoint":cp,"canonical_error_nodes":{"count":64,"identity_scheme":"graph_error_states.state_id","identity_source":G["source"],"family_counts":FAMS,"diagnostic_tuple_identity_allowed":False,"positional_join_allowed":False},"summary":{"unique_sites":len(sites),"reads":C["read"],"stores":C["store"],"zero_slot":C["ZERO_SLOT"],"negative_slot":C["NEGATIVE_SLOT"],"in_jump_regs":C["jump"],"zero_slot_nil_fact_hint":C["nilhint"],"missing_stack_base":C["nostack"],"enriched_sites":enriched,"auxiliary_records_with_explicit_state_id":len(A),"expected_unique_sites":expect_unique},"by_register":dict(BR.most_common()),"sites":sorted(sites,key=lambda r:r["state_id"]),"proof_status":"GRAPH_STATE_ID_PROVENANCE_CENSUS","raw_records_can_create_sites":False,"no_lift_rerun":True,"no_target_execution":True}
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("inputs",nargs="+",type=Path);ap.add_argument("--expect-unique",type=int,default=49);ap.add_argument("--json-out",type=Path,required=True);a=ap.parse_args()
 try:
  out=analyze(a.inputs,a.expect_unique);a.json_out.parent.mkdir(parents=True,exist_ok=True);a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8");s=out["summary"];print(f"R179B underflow census: sites={s['unique_sites']} read={s['reads']} store={s['stores']}");print("proof: GRAPH_STATE_ID_PROVENANCE_CENSUS");return 0
 except(OSError,ValueError,TypeError,KeyError,json.JSONDecodeError)as e:raise SystemExit(f"FAIL: {e}")from e
if __name__=="__main__":raise SystemExit(main())
