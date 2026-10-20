#!/usr/bin/env python3
"""R183B: experiment-only stats rerun.

Consumes the already-proved R183A-v2 diagnostic receipt and runs only the
negative-slot experiment under a fresh label.  It captures exact stats at the
return of devirt.collect_requests via the R183 sitecustomize hook, before any
legacy post-run assertion can discard them.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, sys
from pathlib import Path

SCHEMA="luraph-deobf.r183b-neg1-experiment-stats.v1"
ENGINE_BLOB_SHA1="8d6d9158bcff3b086dfb9812cf4bbf55c9c54572"
SOURCE_SHA="02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"
PROTO_SHA="7792d8830f7f87d3df25c5db243cd27b03c114eda2bcb121788bf8ea85160aa6"
BASELINE=(78,64,0,594)

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def git_blob_sha1(path):
    data=Path(path).read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode("ascii")+b"\0"+data).hexdigest()

def load_runner(repo):
    p=repo/"tools"/"run_r183_breakthrough.py"
    spec=importlib.util.spec_from_file_location("r183_runner",p)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load R183 runner helpers")
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m

def require_r183a(path):
    obj=load(path)
    if not isinstance(obj,dict) or obj.get("schema")!="luraph-deobf.r183a-exact-sub-operands.v2":
        raise ValueError("expected R183A-v2 receipt")
    s=obj.get("summary") or {}
    expected={
        "sites_with_matched_framefail":7,
        "sites_all_exact_sub_neg1":7,
        "sites_with_nonexact_records":0,
        "extra_read_neg1_framefails":0,
    }
    for k,v in expected.items():
        if s.get(k)!=v:
            raise ValueError(f"R183A diagnostic summary mismatch: {k}={s.get(k)!r}, expected {v}")
    gates=obj.get("interpretation_gate") or {}
    if gates.get("exact_accepted_location_gate_for_diagnostic_experiment") is not True:
        raise ValueError("R183A diagnostic gate is not true")
    if gates.get("semantic_change_authorized") is not False:
        raise ValueError("R183A unexpectedly authorizes semantic change")
    accepted=obj.get("accepted_baseline") or {}
    if accepted.get("source_sha256")!=SOURCE_SHA:
        raise ValueError("R183A accepted source SHA mismatch")
    return obj

def parse_stats(log_path):
    rows=[]
    for n,line in enumerate(Path(log_path).read_text(encoding="utf-8",errors="replace").splitlines(),1):
        pos=line.find("[R183STATS]")
        if pos<0:continue
        raw=line[pos+len("[R183STATS]"):].strip()
        try:o=json.loads(raw)
        except json.JSONDecodeError:continue
        if not isinstance(o,dict):continue
        rows.append({"line":n,**o})
    return rows

def choose_collect_stats(rows):
    collect=[x for x in rows if x.get("kind")=="collect_requests"]
    if not collect:
        raise ValueError("no [R183STATS] collect_requests record found")
    selected=collect[-1]
    for k in ("functions","errors","fallbacks","requests"):
        if not isinstance(selected.get(k),int) or isinstance(selected.get(k),bool):
            raise ValueError(f"selected stats record lacks integer {k}")
    return selected,collect

def refuse(paths):
    hits=[str(p) for p in paths if Path(p).exists()]
    if hits:raise ValueError("refusing overwrite: "+", ".join(hits))

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--probe-root",type=Path)
    ap.add_argument("--r183a",type=Path)
    ap.add_argument("--label",default="v15_root27_r183b_neg1_stats")
    a=ap.parse_args()

    repo=Path(__file__).resolve().parents[1]
    runner=load_runner(repo)
    probe=runner.discover_probe(a.probe_root,repo)
    workspace=probe.parent
    driver=(probe/"attribute_root27_frontier78.py").resolve()
    if not driver.is_file():raise SystemExit(f"FAIL: driver not found: {driver}")

    receipt=(a.r183a.resolve() if a.r183a else (probe/"v15_root27_exact_sub_operands.r183a.v2.json").resolve())
    if not receipt.is_file():raise SystemExit(f"FAIL: R183A receipt not found: {receipt}")

    log=probe/(a.label+".log")
    proc=probe/(a.label+".process.json")
    out=probe/(a.label+".receipt.json")

    try:
        refuse([log,proc,out])
        r183a=require_r183a(receipt)

        engine=repo/"core"/"obfuscators"/"luraph_v15"/"devirt.py"
        engine_blob=git_blob_sha1(engine)
        if engine_blob!=ENGINE_BLOB_SHA1:
            raise ValueError(f"engine blob mismatch: {engine_blob}")

        source=runner.find_source(None,workspace,repo)
        if runner.sha256_file(source)!=SOURCE_SHA:
            raise ValueError("source SHA mismatch")

        r182c=runner.find_receipt(None,probe,"v15_root27_base_sub_consistency.r182c.json")
        protos=runner.resolve_selected_protos(r182c,probe)
        if runner.sha256_file(protos)!=PROTO_SHA:
            raise ValueError("selected protos SHA mismatch")

        exit_code,boot=runner.run_driver(
            driver,workspace,repo,probe,a.label,log,
            experiment=True,stats_capture=True,
        )

        rows=parse_stats(log)
        selected,collect=choose_collect_stats(rows)
        result={
            "schema":SCHEMA,
            "label":a.label,
            "driver_exit":exit_code,
            "engine_blob_sha1":engine_blob,
            "source":{"path":str(source),"sha256":SOURCE_SHA},
            "protos":{"path":str(protos),"sha256":PROTO_SHA},
            "r183a_receipt":str(receipt),
            "r183a_diagnostic_gate":True,
            "r183a_canonical_gate":bool((r183a.get("interpretation_gate") or {}).get("canonical_composite_identity_gate")),
            "boot":boot,
            "all_stats_records":rows,
            "collect_stats_records":collect,
            "selected_collect_stats":selected,
            "comparison_to_accepted":{
                "accepted":{"functions":78,"errors":64,"fallbacks":0,"requests":594},
                "experiment":{"functions":selected["functions"],"errors":selected["errors"],
                              "fallbacks":selected["fallbacks"],"requests":selected["requests"]},
                "function_delta":selected["functions"]-78,
                "error_delta":selected["errors"]-64,
                "request_delta":selected["requests"]-594,
            },
            "claims":{
                "experiment_stats_captured":True,
                "accepted_checkpoint_replaced":False,
                "permanent_semantic_change_authorized":False,
                "capture_rerun_performed":False,
                "neg1_experiment_performed":True,
            },
        }
        proc.write_text(json.dumps({"exit":exit_code,"log":str(log),"boot":boot},indent=2)+"\n",encoding="utf-8")
        out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")

        print("R183B selected stats:",json.dumps(selected,sort_keys=True))
        print("comparison:",json.dumps(result["comparison_to_accepted"],sort_keys=True))
        print("driver_exit:",exit_code)
        print("receipt:",out)
        return 0
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
