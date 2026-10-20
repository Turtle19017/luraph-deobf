#!/usr/bin/env python3
"""R183C: experiment-only rerun for exact post-neg1 stats.

Never reruns capture. Requires an already-proved R183A-v2 diagnostic receipt,
runs only the in-memory register=-1 experiment under a fresh label, and records
exact stats markers emitted before legacy post-run locks.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path

ENGINE_BLOB_SHA1="8d6d9158bcff3b086dfb9812cf4bbf55c9c54572"
SOURCE_SHA="02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"
PROTO_SHA="7792d8830f7f87d3df25c5db243cd27b03c114eda2bcb121788bf8ea85160aa6"
OUTPUT_SHA="a26d509d79dfbc8cd41c0d751707f6fff3689d36fc193cc3de15e418d2c24075"
SCHEMA="luraph-deobf.r183c-neg1-experiment-stats.v1"

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def git_blob_sha1(path):
    data=Path(path).read_bytes()
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def load_runner(repo):
    p=repo/"tools"/"run_r183_breakthrough.py"
    spec=importlib.util.spec_from_file_location("r183run",p)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load R183 runner integration module")
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def require_capture_receipt(path):
    o=load(path)
    if not isinstance(o,dict) or o.get("schema")!="luraph-deobf.r183a-exact-sub-operands.v2":
        raise ValueError("expected R183A-v2 exact-sub receipt")
    cp=(o.get("checkpoint") or {}).get("expected") or {}
    got=(cp.get("functions"),cp.get("errors"),cp.get("fallbacks"),cp.get("requests"))
    if got!=(78,64,0,594):
        raise ValueError(f"R183A checkpoint mismatch: {got}")
    s=o.get("summary") or {}
    required=(s.get("sites_with_matched_framefail"),s.get("sites_all_exact_sub_neg1"),
              s.get("sites_with_nonexact_records"),s.get("extra_read_neg1_framefails"))
    if required!=(7,7,0,0):
        raise ValueError(f"R183A exact diagnostic cohort not closed: {required}")
    g=o.get("interpretation_gate") or {}
    if g.get("exact_accepted_location_gate_for_diagnostic_experiment") is not True:
        raise ValueError("R183A diagnostic gate is not true")
    if g.get("semantic_change_authorized") is not False:
        raise ValueError("R183A unexpectedly authorizes semantics")
    b=o.get("accepted_baseline") or {}
    if b.get("source_sha256")!=SOURCE_SHA or b.get("output_sha256")!=OUTPUT_SHA:
        raise ValueError("R183A accepted baseline hashes mismatch")
    if b.get("unique_read_neg1_locations")!=7:
        raise ValueError("R183A accepted baseline unique location count != 7")
    return o

def parse_stats_markers(path):
    out=[]
    for n,line in enumerate(Path(path).read_text(encoding="utf-8",errors="replace").splitlines(),1):
        pos=line.find("[R183STATS]")
        if pos<0:continue
        raw=line[pos+len("[R183STATS]"):].strip()
        try:o=json.loads(raw)
        except json.JSONDecodeError:continue
        if not isinstance(o,dict):continue
        o={"line":n,**o}
        out.append(o)
    return out

def complete_marker(x):
    return all(isinstance(x.get(k),int) and not isinstance(x.get(k),bool)
               for k in ("functions","errors","requests"))

def select_stats(markers):
    complete=[x for x in markers if complete_marker(x)]
    if not complete:return None
    # Final returned engine call is authoritative for this experiment process.
    # Keep every prior marker in the receipt for audit.
    return complete[-1]

def summary_candidates(root):
    out=[]
    if not root.is_dir():return out
    for p in root.rglob("*.json"):
        try:o=load(p)
        except Exception:continue
        if not isinstance(o,dict):continue
        st=o.get("stats")
        if not isinstance(st,dict):continue
        req=o.get("requests")
        if not isinstance(req,int) or isinstance(req,bool):continue
        if all(isinstance(st.get(k),int) and not isinstance(st.get(k),bool)
               for k in ("functions","errors","fallbacks")):
            out.append({"source":str(p),"functions":st["functions"],"errors":st["errors"],
                        "fallbacks":st["fallbacks"],"requests":req})
    return out

def receipt_from_log(log_path,label,probe,capture_receipt,boot=None,exit_code=None):
    markers=parse_stats_markers(log_path)
    selected=select_stats(markers)
    summaries=summary_candidates(probe/label)
    exact=None;source=None
    if selected is not None:
        exact={k:selected.get(k) for k in ("functions","errors","fallbacks","walked","fetched","requests")}
        source="R183STATS_FINAL_MARKER"
    elif summaries:
        # Only promote a generated summary if all complete candidates agree.
        tuples={(x["functions"],x["errors"],x["fallbacks"],x["requests"]) for x in summaries}
        if len(tuples)==1:
            f,e,fb,r=next(iter(tuples))
            exact={"functions":f,"errors":e,"fallbacks":fb,"walked":None,"fetched":None,"requests":r}
            source="GENERATED_SUMMARY_CONSENSUS"
    return {
      "schema":SCHEMA,
      "capture_receipt":str(capture_receipt),
      "experiment":{"label":label,"log":str(log_path),"exit":exit_code,"boot":boot},
      "stats_markers":markers,
      "generated_summary_candidates":summaries,
      "exact_stats":exact,
      "exact_stats_source":source,
      "exact_stats_proved":exact is not None,
      "comparison_to_accepted":{
        "accepted":{"functions":78,"errors":64,"fallbacks":0,"requests":594},
        "experiment":exact,
        "functions_delta":(exact["functions"]-78) if exact else None,
        "errors_delta":(exact["errors"]-64) if exact else None,
        "requests_delta":(exact["requests"]-594) if exact else None,
      },
      "interpretation_gate":{
        "capture_rerun_performed":False,
        "negative_slot_experiment_only":True,
        "exact_stats_marker_is_permanent_semantic_authorization":False,
        "canonical_composite_identity_proved":False,
        "semantic_change_authorized":False,
      },
      "accepted_checkpoint_unchanged":True,
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--probe-root",type=Path)
    ap.add_argument("--capture-receipt",type=Path)
    ap.add_argument("--label",default="v15_root27_r183c_neg1_stats")
    ap.add_argument("--recover-log",type=Path,
                    help="parse an already-preserved R183C experiment log instead of rerunning")
    ap.add_argument("--json-out",type=Path)
    a=ap.parse_args()

    repo=Path(__file__).resolve().parents[1]
    runner=load_runner(repo)
    probe=runner.discover_probe(a.probe_root,repo)
    workspace=probe.parent
    driver=(probe/"attribute_root27_frontier78.py").resolve()
    cap=(a.capture_receipt.resolve() if a.capture_receipt else
         (probe/"v15_root27_exact_sub_operands.r183a.v2.json").resolve())
    require_capture_receipt(cap)

    engine=repo/"core"/"obfuscators"/"luraph_v15"/"devirt.py"
    got_blob=git_blob_sha1(engine)
    if got_blob!=ENGINE_BLOB_SHA1:
        raise SystemExit(f"FAIL: engine blob drift: {got_blob}")

    r182c=runner.find_receipt(None,probe,"v15_root27_base_sub_consistency.r182c.json")
    source=runner.find_source(None,workspace,repo)
    protos=runner.resolve_selected_protos(r182c,probe)
    if runner.sha256_file(source)!=SOURCE_SHA or runner.sha256_file(protos)!=PROTO_SHA:
        raise SystemExit("FAIL: accepted source/proto hashes drifted")

    out=(a.json_out.resolve() if a.json_out else (probe/"v15_root27_r183c_neg1_stats.json").resolve())
    if out.exists():raise SystemExit(f"FAIL: refusing overwrite: {out}")

    if a.recover_log:
        log=a.recover_log.resolve()
        if not log.is_file():raise SystemExit(f"FAIL: recovery log not found: {log}")
        boot=runner.boot_record(log)
        if not isinstance(boot,dict) or not boot.get("neg1_experiment") or not boot.get("neg1_patch_installed"):
            raise SystemExit("FAIL: recovery log is not a proved neg1 experiment")
        rec=receipt_from_log(log,a.label,probe,cap,boot=boot,exit_code=None)
    else:
        log=(probe/(a.label+".log")).resolve()
        proc=(probe/(a.label+".process.json")).resolve()
        outdir=probe/a.label
        runner.refuse([log,proc,outdir])
        exit_code,boot=runner.run_driver(driver,workspace,repo,probe,a.label,log,True,stats_capture=True)
        proc.write_text(json.dumps({"exit":exit_code,"boot":boot,"label":a.label,
                                    "log":str(log),"stats_capture":True},indent=2)+"\n",
                        encoding="utf-8")
        rec=receipt_from_log(log,a.label,probe,cap,boot=boot,exit_code=exit_code)

    rec["integration"]={"repo":str(repo),"workspace":str(workspace),"probe":str(probe),
                        "driver":str(driver),"engine_blob_sha1":got_blob,
                        "source":str(source),"source_sha256":SOURCE_SHA,
                        "selected_protos":str(protos),"selected_protos_sha256":PROTO_SHA}
    out.write_text(json.dumps(rec,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("R183C exact_stats_proved:",rec["exact_stats_proved"])
    print("exact_stats:",json.dumps(rec["exact_stats"],sort_keys=True))
    print("source:",rec["exact_stats_source"])
    print("receipt:",out)
    return 0 if rec["exact_stats_proved"] else 2

if __name__=="__main__":
    raise SystemExit(main())
