#!/usr/bin/env python3
"""R183 breakthrough runner: exact-operand capture, then gated -1-slot experiment."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, re, subprocess, sys
from pathlib import Path

SOURCE_SHA="02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"
PROTO_SHA="7792d8830f7f87d3df25c5db243cd27b03c114eda2bcb121788bf8ea85160aa6"

def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def refuse(paths):
    hits=[str(p) for p in paths if p.exists()]
    if hits:raise ValueError("refusing overwrite: "+", ".join(hits))

def run_driver(driver,label,log_path,extra_env):
    env=dict(os.environ)
    env.update({"PYTHONIOENCODING":"utf-8","PYTHONUNBUFFERED":"1","DEVIRT_FRAME_DEBUG":"1"})
    env.update(extra_env)
    with log_path.open("xb") as f:
        p=subprocess.run([sys.executable,str(driver),label],cwd=Path.cwd(),env=env,
                         stdout=f,stderr=subprocess.STDOUT)
    return p.returncode

def load_analyzer():
    path=Path("tools/analyze_r183_exact_underflow_capture.py")
    spec=importlib.util.spec_from_file_location("r183a",path)
    if spec is None or spec.loader is None:raise ValueError("cannot load R183A analyzer")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

def walk_dicts(v,path="$"):
    if isinstance(v,dict):
        yield path,v
        for k,x in v.items():
            if isinstance(x,(dict,list)):yield from walk_dicts(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v):yield from walk_dicts(x,f"{path}[{i}]")

def diagnostic_files(label,primary_log):
    out=[primary_log]
    root=Path("_probe")/label
    if root.is_dir():
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".log",".txt",".json",".jsonl",".md"):
                out.append(p)
    seen=set();uniq=[]
    for p in out:
        rp=p.resolve()
        if rp in seen:continue
        seen.add(rp);uniq.append(p)
    return uniq

def checkpoint_candidates(root):
    out=[]
    if not root.exists():return out
    for p in root.rglob("*.json"):
        try:o=load(p)
        except Exception:continue
        for jp,d in walk_dicts(o):
            if not isinstance(d,dict):continue
            keys=("functions","errors","fallbacks","requests")
            if all(isinstance(d.get(k),int) and not isinstance(d.get(k),bool) for k in keys):
                out.append({"source":str(p),"json_path":jp,**{k:d[k] for k in keys}})
    return out

def text_checkpoint_candidates(log_path):
    txt=log_path.read_text(encoding="utf-8",errors="replace")
    vals={}
    for key in ("functions","errors","fallbacks","requests"):
        hits=re.findall(rf"(?i)\b{key}\b\s*[:=]?\s*(\d+)",txt)
        if hits:vals[key]=int(hits[-1])
    return [vals] if len(vals)==4 else []

def verify_inputs(source,r182c):
    got=sha256_file(source)
    if got!=SOURCE_SHA:raise ValueError(f"source SHA mismatch: {got}")
    c=load(r182c)
    sel=c.get("selected_base_snapshot") or {}
    p=Path(sel.get("path",""))
    expected=sel.get("sha256")
    if not p.is_file():raise ValueError(f"R182C selected protos missing: {p}")
    psha=sha256_file(p)
    if expected!=psha:raise ValueError(f"R182C protos receipt/path SHA mismatch: {psha} != {expected}")
    if psha!=PROTO_SHA:raise ValueError(f"selected protos is not accepted 7792 snapshot: {psha}")
    return {"source":str(source),"source_sha256":got,"protos":str(p),"protos_sha256":psha}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--driver",type=Path,default=Path("_probe/attribute_root27_frontier78.py"))
    ap.add_argument("--r181f",type=Path,default=Path("_probe/v15_root27_frontier78_local_identity_rhs.r181f.json"))
    ap.add_argument("--r182c",type=Path,default=Path("_probe/v15_root27_base_sub_consistency.r182c.json"))
    ap.add_argument("--source",type=Path,default=Path("script.txt"))
    ap.add_argument("--capture-label",default="v15_root27_r183_exact_operands")
    ap.add_argument("--experiment-label",default="v15_root27_r183_neg1_experiment")
    ap.add_argument("--no-experiment",action="store_true")
    a=ap.parse_args()

    if not a.driver.is_file():raise SystemExit(f"FAIL: driver not found: {a.driver}")
    if not a.r181f.is_file():raise SystemExit(f"FAIL: R181F receipt not found: {a.r181f}")
    if not a.r182c.is_file():raise SystemExit(f"FAIL: R182C receipt not found: {a.r182c}")
    if not a.source.is_file():raise SystemExit(f"FAIL: source not found: {a.source}")

    probe=Path("_probe");probe.mkdir(exist_ok=True)
    cap_log=probe/(a.capture_label+".log")
    cap_proc=probe/(a.capture_label+".process.json")
    cap_receipt=probe/"v15_root27_exact_sub_operands.r183a.json"
    exp_log=probe/(a.experiment_label+".log")
    exp_proc=probe/(a.experiment_label+".process.json")
    final_status=probe/"v15_root27_breakthrough.r183.status.json"
    try:
        refuse([cap_log,cap_proc,cap_receipt,final_status]+([] if a.no_experiment else [exp_log,exp_proc]))
        verified=verify_inputs(a.source,a.r182c)

        cap_exit=run_driver(a.driver,a.capture_label,cap_log,{})
        cap_proc.write_text(json.dumps({"exit":cap_exit,"label":a.capture_label,
                                       "log":str(cap_log),"env":{"DEVIRT_FRAME_DEBUG":"1"}},indent=2)+"\n",
                            encoding="utf-8")
        analyzer=load_analyzer()
        capture_inputs=diagnostic_files(a.capture_label,cap_log)
        capture=analyzer.analyze(a.r181f,capture_inputs)
        cap_receipt.write_text(json.dumps(capture,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        gate=bool(capture["interpretation_gate"]["all_seven_sites_have_exact_failure_time_sub_neg1"])

        status={"schema":"luraph-deobf.r183-breakthrough-run.v1","verified_inputs":verified,
                "capture":{"exit":cap_exit,"label":a.capture_label,"log":str(cap_log),
                           "receipt":str(cap_receipt),"diagnostic_inputs":[str(x) for x in capture_inputs],
                           "summary":capture["summary"],"gate":gate},
                "experiment":{"attempted":False},
                "accepted_semantics_changed":False}

        if not a.no_experiment and cap_exit==0 and gate:
            exp_exit=run_driver(a.driver,a.experiment_label,exp_log,
                                {"DEVIRT_NEG1_SLOT_EXPERIMENT":"1"})
            exp_proc.write_text(json.dumps({"exit":exp_exit,"label":a.experiment_label,
                "log":str(exp_log),
                "env":{"DEVIRT_FRAME_DEBUG":"1","DEVIRT_NEG1_SLOT_EXPERIMENT":"1"}},indent=2)+"\n",
                encoding="utf-8")
            outdir=probe/a.experiment_label
            status["experiment"]={
                "attempted":True,"exit":exp_exit,"label":a.experiment_label,"log":str(exp_log),
                "json_checkpoint_candidates":checkpoint_candidates(outdir),
                "text_checkpoint_candidates":text_checkpoint_candidates(exp_log),
                "diagnostic_only":True,"flag_off_by_default":True,
            }

        final_status.write_text(json.dumps(status,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        print("R183 capture:",json.dumps(status["capture"]["summary"],sort_keys=True))
        print("capture gate:",gate)
        print("experiment:",json.dumps(status["experiment"],sort_keys=True))
        print("status:",final_status)
        return 0 if cap_exit==0 else cap_exit
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc

if __name__=="__main__":
    raise SystemExit(main())
