#!/usr/bin/env python3
"""R179B v2: census accepted final underflow nodes; raw records only enrich them."""
from __future__ import annotations
import argparse, json, re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "luraph-deobf.r179b-underflow-artifact-census.v2"
SUFFIX = {".json", ".jsonl", ".log", ".md", ".txt"}
UF = re.compile(r"(?P<op>read|store) below the stack VM's frame \(register (?P<reg>-?\d+)\)")
AT = re.compile(r"\(at (?P<mode>-?\d+):(?P<pc>-?\d+)\)")
EXPECTED_FAMILIES = {"underflow":49, "symbolic_control":5, "missing_condition":9, "nil_bxor":1}


def family(err):
    if UF.search(err): return "underflow"
    if "symbolic next pc/mode:" in err: return "symbolic_control"
    if "needs a constant that is not decoded yet" in err: return "missing_condition"
    if "bit32.bxor failed:" in err: return "nil_bxor"
    return "other"


def files(inputs):
    out=[]
    for p in inputs:
        if p.is_file(): out.append(p)
        elif p.is_dir(): out += [x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in SUFFIX]
        else: raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(out))


def load_json(p):
    try: return json.loads(p.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError): return None


def walk_lists(v, path="$"):
    if isinstance(v,list):
        yield path,v
        for i,x in enumerate(v): yield from walk_lists(x,f"{path}[{i}]")
    elif isinstance(v,dict):
        for k,x in v.items(): yield from walk_lists(x,f"{path}.{k}")


def walk_dicts(v):
    if isinstance(v,dict):
        yield v
        for x in v.values(): yield from walk_dicts(x)
    elif isinstance(v,list):
        for x in v: yield from walk_dicts(x)


def checkpoint(fs, expected=(78,64,0,594)):
    hits=[]
    for p in fs:
        if p.suffix.lower() != ".json": continue
        o=load_json(p)
        if not isinstance(o,dict) or not isinstance(o.get("stats"),dict): continue
        s=o["stats"]
        got=(s.get("functions"),s.get("errors"),s.get("fallbacks"),o.get("requests"))
        if got==expected: hits.append((p,o.get("output_sha256")))
    if not hits: raise ValueError(f"accepted checkpoint manifest {expected} not found")
    hashes={h for _,h in hits if h}
    if len(hashes)>1: raise ValueError(f"checkpoint output hash conflict: {sorted(hashes)}")
    return {"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594},
            "sources":[str(p) for p,_ in hits], "output_sha256":next(iter(hashes),None)}


def canonical(fs, count=64):
    cands=[]
    for p in fs:
        if p.suffix.lower() != ".json": continue
        o=load_json(p)
        if o is None: continue
        for jp,xs in walk_lists(o):
            if len(xs)!=count or not all(isinstance(x,dict) for x in xs): continue
            if not all(isinstance(x.get("state_key"),str) and x["state_key"] and
                       isinstance(x.get("error"),str) and x["error"] for x in xs): continue
            if len({x["state_key"] for x in xs})!=count: continue
            fc=dict(Counter(family(x["error"]) for x in xs))
            if fc==EXPECTED_FAMILIES: cands.append((p,jp,xs,fc))
    if not cands: raise ValueError("no canonical 64-node error list matching accepted family census 49/5/9/1")
    groups=defaultdict(list)
    for c in cands:
        ident=tuple(sorted((x["state_key"],x["error"]) for x in c[2])); groups[ident].append(c)
    if len(groups)!=1: raise ValueError("ambiguous canonical error-node universes")
    g=next(iter(groups.values()))
    return {"records":g[0][2], "sources":[f"{p}:{jp}" for p,jp,_,_ in g], "source_files":{str(p) for p,_,_,_ in g}}


def parse_underflow(err):
    m=UF.search(err)
    if not m: return None
    a=AT.search(err)
    return {"operation":m.group("op"), "register":int(m.group("reg")),
            "mode":int(a.group("mode")) if a else None, "pc":int(a.group("pc")) if a else None}


def json_line(line):
    for i in sorted({0,line.find("{"),line.find("[")}):
        if i<0: continue
        try: return json.loads(line[i:].strip())
        except json.JSONDecodeError: pass
    return None


def aux_record(d, source, line=None):
    err=str(d.get("error") or d.get("exception") or "")
    kind=d.get("kind")
    if kind in ("below_stack","below_stack_store"):
        op="read" if kind=="below_stack" else "store"; reg=d.get("register")
        if not isinstance(reg,(int,float)) or isinstance(reg,bool): return None
        reg=int(reg)
    else:
        x=parse_underflow(err)
        if not x: return None
        op,reg=x["operation"],x["register"]
    mode=d.get("mode"); pc=d.get("pc")
    a=AT.search(err)
    if a:
        if not isinstance(mode,int): mode=int(a.group("mode"))
        if not isinstance(pc,int): pc=int(a.group("pc"))
    jr=d.get("jump_regs") if isinstance(d.get("jump_regs"),list) else []
    facts=str(d.get("facts") or d.get("step_facts") or "")
    return {"source":str(source),"line":line,"state_key":d.get("state_key") or d.get("state"),
            "operation":op,"register":reg,"mode":mode,"pc":pc,"stack_base":d.get("stack_base"),
            "last_op":d.get("last_op") or d.get("op"),"proto":d.get("proto"),"proto_tid":d.get("proto_tid"),
            "function":d.get("function"),"walk":d.get("walk"),"in_jump_regs":reg in jr,
            "zero_slot_nil_fact_hint": bool(reg==0 and re.search(r"0\s*:\s*\(['\"]c['\"]\s*,\s*None\)",facts)),
            "raw_key_type":d.get("raw_key_type") or d.get("key_type"),"raw_key":d.get("raw_key") or d.get("key_fmt")}


def scan_aux(fs, excluded):
    out=[]
    for p in fs:
        if str(p) in excluded: continue
        if p.suffix.lower()==".json":
            o=load_json(p)
            if o is not None:
                for d in walk_dicts(o):
                    r=aux_record(d,p)
                    if r: out.append(r)
                continue
        try:
            for n,line in enumerate(p.read_text(encoding="utf-8",errors="replace").splitlines(),1):
                o=json_line(line)
                if o is not None:
                    for d in walk_dicts(o):
                        r=aux_record(d,p,n)
                        if r: out.append(r)
                else:
                    x=parse_underflow(line)
                    if x: out.append({"source":str(p),"line":n,"state_key":None,**x,"stack_base":None,
                                      "last_op":None,"proto":None,"proto_tid":None,"function":None,"walk":None,
                                      "in_jump_regs":False,"zero_slot_nil_fact_hint":False,"raw_key_type":None,"raw_key":None})
        except OSError: pass
    return out


def richness(r):
    return sum(r.get(k) is not None for k in ("stack_base","last_op","proto","proto_tid","function","walk","raw_key","raw_key_type"))


def analyze(inputs, expect_unique=49):
    fs=files(inputs); cp=checkpoint(fs); can=canonical(fs)
    accepted=[]
    for rec in can["records"]:
        x=parse_underflow(rec["error"])
        if not x: continue
        row={"state_key":rec["state_key"],"error":rec["error"],**x,"proto":rec.get("proto"),
             "stack_base":rec.get("stack_base"),"last_op":rec.get("last_op") or rec.get("op"),
             "proto_tid":rec.get("proto_tid"),"function":rec.get("function"),"walk":rec.get("walk"),
             "in_jump_regs":bool(rec.get("in_jump_regs",False)),"zero_slot_nil_fact_hint":bool(rec.get("zero_slot_nil_fact_hint",False)),
             "raw_key_type":rec.get("raw_key_type"),"raw_key":rec.get("raw_key")}
        accepted.append(row)
    if expect_unique is not None and len(accepted)!=expect_unique:
        raise ValueError(f"canonical accepted-node universe has {len(accepted)} underflows, expected {expect_unique}")

    aux=scan_aux(fs,can["source_files"]); by_state=defaultdict(list); by_diag=defaultdict(list)
    for r in aux:
        if r.get("state_key"): by_state[r["state_key"]].append(r)
        by_diag[(r.get("mode"),r.get("pc"),r["operation"],r["register"])].append(r)
    diag_count=Counter((r.get("mode"),r.get("pc"),r["operation"],r["register"]) for r in accepted)
    enriched=ambiguous=0
    for s in accepted:
        cand=by_state.get(s["state_key"],[]); resolution="state_key" if cand else None
        if not cand:
            k=(s.get("mode"),s.get("pc"),s["operation"],s["register"])
            if diag_count[k]==1: cand=by_diag.get(k,[]); resolution="unique_mode_pc_operation_register" if cand else None
            elif by_diag.get(k): ambiguous+=1; s["enrichment_status"]="AMBIGUOUS_DIAGNOSTIC_KEY"
        if cand:
            b=max(cand,key=richness); enriched+=1; s["enrichment_status"]="MATCHED"; s["enrichment_resolution"]=resolution
            for k in ("stack_base","last_op","proto","proto_tid","function","walk","in_jump_regs","zero_slot_nil_fact_hint","raw_key_type","raw_key"):
                if b.get(k) is not None: s[k]=b.get(k)
            s["enrichment_source"],s["enrichment_line"]=b["source"],b["line"]
        elif "enrichment_status" not in s: s["enrichment_status"]="NO_UNIQUE_AUX_MATCH"

    c=Counter(); br=Counter(); bo=Counter(); bp=Counter()
    for s in accepted:
        reg=s["register"]; bucket="ZERO_SLOT" if reg==0 else "NEGATIVE_SLOT" if reg<0 else "UNPARSED"
        s["bucket"]=bucket; c[s["operation"]]+=1; c[bucket]+=1
        if s.get("in_jump_regs"): c["jump"]+=1
        if s.get("zero_slot_nil_fact_hint"): c["nilhint"]+=1
        if s.get("stack_base") is None: c["nostack"]+=1
        br[str(reg)]+=1
        if s.get("last_op") is not None: bo[str(s["last_op"])]+=1
        if s.get("proto") is not None: bp[str(s["proto"])]+=1
    return {"schema":SCHEMA,"inputs":[str(x) for x in inputs],"checkpoint":cp,
            "canonical_error_nodes":{"count":64,"sources":can["sources"],"family_counts":EXPECTED_FAMILIES,
                                     "membership_rule":"canonical final node with unique state_key + error only"},
            "summary":{"unique_sites":len(accepted),"reads":c["read"],"stores":c["store"],"zero_slot":c["ZERO_SLOT"],
                       "negative_slot":c["NEGATIVE_SLOT"],"unparsed_slot":c["UNPARSED"],"in_jump_regs":c["jump"],
                       "zero_slot_nil_fact_hint":c["nilhint"],"missing_stack_base":c["nostack"],"enriched_sites":enriched,
                       "ambiguous_enrichment_sites":ambiguous,"auxiliary_underflow_records":len(aux),
                       "expected_unique_sites":expect_unique,"expected_matches":expect_unique is None or len(accepted)==expect_unique},
            "by_register":dict(br.most_common()),"by_last_op":dict(bo.most_common()),"by_proto":dict(bp.most_common()),
            "sites":sorted(accepted,key=lambda r:(str(r.get("mode")),str(r.get("pc")),r["state_key"])),
            "proof_status":"ACCEPTED_FINAL_NODE_CENSUS_WITH_AUX_ENRICHMENT","raw_records_can_create_sites":False,
            "no_lift_rerun":True,"no_target_execution":True}


def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("inputs",nargs="+",type=Path)
    ap.add_argument("--expect-unique",type=int,default=49); ap.add_argument("--json-out",type=Path,required=True); a=ap.parse_args()
    try:
        out=analyze(a.inputs,a.expect_unique); a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8"); s=out["summary"]
        print(f"R179B underflow census: sites={s['unique_sites']} read={s['reads']} store={s['stores']} R0={s['zero_slot']} negative={s['negative_slot']}")
        print(f"enriched={s['enriched_sites']} ambiguous={s['ambiguous_enrichment_sites']} aux={s['auxiliary_underflow_records']}")
        print("proof: ACCEPTED_FINAL_NODE_CENSUS_WITH_AUX_ENRICHMENT"); return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as e: raise SystemExit(f"FAIL: {e}") from e

if __name__=="__main__": raise SystemExit(main())
