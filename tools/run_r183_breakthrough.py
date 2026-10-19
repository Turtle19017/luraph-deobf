#!/usr/bin/env python3
"""R183-v2 integration runner.

Uses the existing local attribution driver unchanged.  A sitecustomize bootstrap
protects diagnostic flags from the driver's legacy DEVIRT_* cleanup and applies
the -1 experiment in memory, so the checked-in engine bytes stay at the
pre-R183 baseline.  Exact accepted baseline error locations are used only to
authorize the diagnostic experiment; canonical composite identity remains a
separate, stricter gate and permanent semantics are never auto-promoted.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess,sys,tempfile
from pathlib import Path

SOURCE_SHA="02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"
PROTO_SHA="7792d8830f7f87d3df25c5db243cd27b03c114eda2bcb121788bf8ea85160aa6"
OUTPUT_SHA="a26d509d79dfbc8cd41c0d751707f6fff3689d36fc193cc3de15e418d2c24075"

def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()

def load(path): return json.loads(Path(path).read_text(encoding="utf-8"))

def repo_root():
    return Path(__file__).resolve().parents[1]

def unique_existing(paths):
    out=[];seen=set()
    for p in paths:
        p=Path(p)
        try:r=p.resolve()
        except OSError:r=p
        if r in seen or not p.exists():continue
        seen.add(r);out.append(p)
    return out

def discover_probe(explicit,repo):
    if explicit:
        p=Path(explicit)
        if not (p/"attribute_root27_frontier78.py").is_file():
            raise ValueError(f"--probe-root lacks driver: {p}")
        return p.resolve()
    cwd=Path.cwd().resolve()
    candidates=[]
    for base in [cwd,*cwd.parents,repo,*repo.parents]:
        candidates.append(base/"_probe")
    hits=[p.resolve() for p in unique_existing(candidates)
          if (p/"attribute_root27_frontier78.py").is_file()]
    hits=list(dict.fromkeys(hits))
    if len(hits)!=1:
        raise ValueError(f"expected one _probe containing attribute_root27_frontier78.py, found {hits}")
    return hits[0]

def find_source(explicit,workspace,repo):
    if explicit:
        p=Path(explicit)
        if not p.is_file():raise ValueError(f"source not found: {p}")
        if sha256_file(p)!=SOURCE_SHA:raise ValueError("source SHA mismatch")
        return p.resolve()
    candidates=[workspace/"script.txt",repo/"script.txt",Path.cwd()/"script.txt"]
    for p in unique_existing(candidates):
        if p.is_file() and sha256_file(p)==SOURCE_SHA:return p.resolve()
    raise ValueError("accepted script.txt not found by workspace/repo discovery")

def find_receipt(explicit,probe,name):
    if explicit:
        p=Path(explicit)
        if not p.is_file():raise ValueError(f"receipt not found: {p}")
        return p.resolve()
    p=probe/name
    if not p.is_file():raise ValueError(f"receipt not found: {p}")
    return p.resolve()

def accepted_summary(path):
    try:o=load(path)
    except Exception:return False
    if not isinstance(o,dict):return False
    st=o.get("stats") or {}
    return (st.get("functions"),st.get("errors"),st.get("fallbacks"),o.get("requests"))==(78,64,0,594) \
        and o.get("source_sha256")==SOURCE_SHA and o.get("output_sha256")==OUTPUT_SHA

def discover_baseline(explicit,probe):
    if explicit:
        p=Path(explicit)
        if not p.is_file() or not accepted_summary(p):
            raise ValueError(f"baseline summary is not accepted 78/64/594 + anchored hashes: {p}")
        return p.resolve(),[p.resolve()]
    hits=[]
    for p in probe.rglob("*.json"):
        if p.name.lower() not in ("summary.json","summary(1).json") and "summary" not in p.name.lower():
            continue
        if accepted_summary(p):hits.append(p.resolve())
    if not hits:raise ValueError("accepted baseline summary not found under _probe")
    hits=sorted(dict.fromkeys(hits),key=lambda p:(0 if "bigstack" in str(p).lower() else 1,len(str(p)),str(p)))
    return hits[0],hits

def resolve_selected_protos(r182c_path,probe):
    c=load(r182c_path);sel=c.get("selected_base_snapshot") or {}
    expected=sel.get("sha256")
    if expected!=PROTO_SHA:raise ValueError(f"R182C selected snapshot SHA is not accepted 7792: {expected}")
    raw=sel.get("path")
    candidates=[]
    if raw:candidates.append(Path(raw))
    for p in unique_existing(candidates):
        if p.is_file() and sha256_file(p)==PROTO_SHA:return p.resolve()
    names=("*.protos.json","decoded.protos.json")
    seen=set()
    for pat in names:
        for p in probe.rglob(pat):
            rp=p.resolve()
            if rp in seen:continue
            seen.add(rp)
            try:
                if sha256_file(p)==PROTO_SHA:return rp
            except OSError:pass
    raise ValueError("accepted 7792 proto snapshot not found under _probe")

def refuse(paths):
    hits=[str(p) for p in paths if Path(p).exists()]
    if hits:raise ValueError("refusing overwrite: "+", ".join(hits))

def load_analyzer(repo):
    p=repo/"tools"/"analyze_r183_exact_underflow_capture.py"
    spec=importlib.util.spec_from_file_location("r183a",p)
    if spec is None or spec.loader is None:raise ValueError("cannot load R183 analyzer")
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def diagnostic_files(probe,label,primary):
    out=[primary];root=probe/label
    if root.is_dir():
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".log",".txt",".json",".jsonl",".md"):
                out.append(p)
    return list(dict.fromkeys(Path(x).resolve() for x in out if Path(x).is_file()))

def boot_record(log_path):
    for line in log_path.read_text(encoding="utf-8",errors="replace").splitlines():
        pos=line.find("[R183BOOT]")
        if pos>=0:
            try:return json.loads(line[pos+len("[R183BOOT]"):].strip())
            except json.JSONDecodeError:pass
    return None

def run_driver(driver,workspace,repo,probe,label,log_path,experiment):
    template=repo/"tools"/"r183_sitecustomize.py"
    if not template.is_file():raise ValueError("missing tools/r183_sitecustomize.py")
    with tempfile.TemporaryDirectory(prefix="r183site_",dir=str(probe)) as td:
        site=Path(td);shutil.copyfile(template,site/"sitecustomize.py")
        env=dict(os.environ)
        env["PYTHONIOENCODING"]="utf-8";env["PYTHONUNBUFFERED"]="1"
        env["R183_FRAME_DEBUG"]="1"
        if experiment:env["R183_NEG1_SLOT_EXPERIMENT"]="1"
        else:env.pop("R183_NEG1_SLOT_EXPERIMENT",None)
        old=env.get("PYTHONPATH","")
        env["PYTHONPATH"]=os.pathsep.join([str(site),str(repo/"core")]+([old] if old else []))
        with log_path.open("xb") as f:
            p=subprocess.run([sys.executable,str(driver),label],cwd=workspace,env=env,
                             stdout=f,stderr=subprocess.STDOUT)
    boot=boot_record(log_path)
    if not isinstance(boot,dict) or not boot.get("frame_debug"):
        raise ValueError(f"R183 bootstrap/frame-debug marker missing from {log_path}")
    if bool(boot.get("neg1_experiment"))!=bool(experiment):
        raise ValueError(f"R183 bootstrap experiment marker mismatch in {log_path}")
    if experiment and not boot.get("neg1_patch_installed"):
        raise ValueError("R183 bootstrap did not install in-memory neg1 patch")
    return p.returncode,boot

def walk_dicts(v,path="$"):
    if isinstance(v,dict):
        yield path,v
        for k,x in v.items():
            if isinstance(x,(dict,list)):yield from walk_dicts(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v):yield from walk_dicts(x,f"{path}[{i}]")

def checkpoint_candidates(root):
    out=[]
    if not root.exists():return out
    for p in root.rglob("*.json"):
        try:o=load(p)
        except Exception:continue
        for jp,d in walk_dicts(o):
            if not isinstance(d,dict):continue
            if all(isinstance(d.get(k),int) and not isinstance(d.get(k),bool)
                   for k in ("functions","errors","fallbacks")):
                req=d.get("requests")
                if not isinstance(req,int):
                    req=o.get("requests") if isinstance(o,dict) else None
                out.append({"source":str(p),"json_path":jp,"functions":d["functions"],
                            "errors":d["errors"],"fallbacks":d["fallbacks"],"requests":req})
    return out

def text_stats(log_path):
    txt=log_path.read_text(encoding="utf-8",errors="replace")
    candidates=[]
    pats=[
      re.compile(r'(?i)(?P<f>\d+)\s+functions?.*?(?P<e>\d+)\s+(?:errors?|unlifted blocks).*?(?P<r>\d+)\s+(?:constant )?requests?'),
      re.compile(r'(?i)functions\s*[:=]\s*(?P<f>\d+).*?errors\s*[:=]\s*(?P<e>\d+).*?requests\s*[:=]\s*(?P<r>\d+)',re.S)]
    for rx in pats:
        for m in rx.finditer(txt):
            candidates.append({"functions":int(m.group("f")),"errors":int(m.group("e")),
                               "requests":int(m.group("r")),"fallbacks":None})
    return candidates[-20:]

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--probe-root",type=Path)
    ap.add_argument("--driver",type=Path)
    ap.add_argument("--r181f",type=Path);ap.add_argument("--r182c",type=Path)
    ap.add_argument("--baseline-summary",type=Path);ap.add_argument("--source",type=Path)
    ap.add_argument("--capture-label",default="v15_root27_r183v2_exact_operands")
    ap.add_argument("--experiment-label",default="v15_root27_r183v2_neg1_experiment")
    ap.add_argument("--no-experiment",action="store_true")
    ap.add_argument("--preflight-only",action="store_true")
    a=ap.parse_args()
    repo=repo_root();probe=discover_probe(a.probe_root,repo);workspace=probe.parent
    driver=(a.driver.resolve() if a.driver else (probe/"attribute_root27_frontier78.py").resolve())
    if not driver.is_file():raise SystemExit(f"FAIL: driver not found: {driver}")
    r181f=find_receipt(a.r181f,probe,"v15_root27_frontier78_local_identity_rhs.r181f.json")
    r182c=find_receipt(a.r182c,probe,"v15_root27_base_sub_consistency.r182c.json")
    source=find_source(a.source,workspace,repo)
    baseline,baseline_candidates=discover_baseline(a.baseline_summary,probe)
    protos=resolve_selected_protos(r182c,probe)
    integration={"repo":str(repo),"workspace":str(workspace),"probe":str(probe),"driver":str(driver),
      "r181f":str(r181f),"r182c":str(r182c),"source":str(source),"baseline_summary":str(baseline),
      "baseline_candidates":[str(x) for x in baseline_candidates],"selected_protos":str(protos),
      "source_sha256":sha256_file(source),"selected_protos_sha256":sha256_file(protos)}
    if a.preflight_only:
        print(json.dumps(integration,indent=2,ensure_ascii=False));return 0

    cap_log=probe/(a.capture_label+".log");cap_proc=probe/(a.capture_label+".process.json")
    cap_receipt=probe/"v15_root27_exact_sub_operands.r183a.v2.json"
    exp_log=probe/(a.experiment_label+".log");exp_proc=probe/(a.experiment_label+".process.json")
    status_path=probe/"v15_root27_breakthrough.r183.v2.status.json"
    try:
        refuse([cap_log,cap_proc,cap_receipt,status_path]+([] if a.no_experiment else [exp_log,exp_proc]))
        cap_exit,cap_boot=run_driver(driver,workspace,repo,probe,a.capture_label,cap_log,False)
        cap_proc.write_text(json.dumps({"exit":cap_exit,"boot":cap_boot,"label":a.capture_label,
                                       "log":str(cap_log)},indent=2)+"\n",encoding="utf-8")
        analyzer=load_analyzer(repo);inputs=diagnostic_files(probe,a.capture_label,cap_log)
        capture=analyzer.analyze(r181f,baseline,inputs)
        cap_receipt.write_text(json.dumps(capture,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        diag_gate=bool(capture["interpretation_gate"]["exact_accepted_location_gate_for_diagnostic_experiment"])
        canon_gate=bool(capture["interpretation_gate"]["canonical_composite_identity_gate"])
        status={"schema":"luraph-deobf.r183-breakthrough-run.v2","integration":integration,
          "capture":{"exit":cap_exit,"boot":cap_boot,"label":a.capture_label,"log":str(cap_log),
                     "diagnostic_inputs":[str(x) for x in inputs],"receipt":str(cap_receipt),
                     "summary":capture["summary"],"diagnostic_gate":diag_gate,
                     "canonical_gate":canon_gate},
          "experiment":{"attempted":False},"accepted_semantics_changed":False,
          "permanent_semantic_change_authorized":False}

        if not a.no_experiment and diag_gate:
            exp_exit,exp_boot=run_driver(driver,workspace,repo,probe,a.experiment_label,exp_log,True)
            exp_proc.write_text(json.dumps({"exit":exp_exit,"boot":exp_boot,"label":a.experiment_label,
                                           "log":str(exp_log)},indent=2)+"\n",encoding="utf-8")
            outdir=probe/a.experiment_label
            json_stats=checkpoint_candidates(outdir);log_stats=text_stats(exp_log)
            status["experiment"]={"attempted":True,"exit":exp_exit,"boot":exp_boot,
              "label":a.experiment_label,"log":str(exp_log),"json_checkpoint_candidates":json_stats,
              "text_checkpoint_candidates":log_stats,
              "legacy_driver_nonzero_exit_is_not_semantic_acceptance":exp_exit!=0,
              "diagnostic_only":True,"in_memory_patch_only":True,
              "checked_in_engine_semantics_unchanged":True}

        status_path.write_text(json.dumps(status,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        print("R183-v2 capture:",json.dumps(status["capture"]["summary"],sort_keys=True))
        print("diagnostic_gate:",diag_gate,"canonical_gate:",canon_gate)
        print("experiment:",json.dumps(status["experiment"],sort_keys=True))
        print("status:",status_path)
        # Capture exit may be nonzero only after a legacy post-run lock.  The
        # diagnostic gate is based on complete FRAMEFAIL coverage, not exit 0.
        return 0 if diag_gate else (cap_exit or 2)
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__": raise SystemExit(main())
