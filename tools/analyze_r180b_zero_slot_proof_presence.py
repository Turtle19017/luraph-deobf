#!/usr/bin/env python3
"""R180B: prove whether frozen artifacts contain any R180A R0 proof source."""
import argparse,json
from pathlib import Path
FIELDS=('frame_entry_fact_source_0','fresh-regfile-self-alias','direct-prologue-reg0-write')
SUF={'.json','.jsonl','.log','.txt','.md'}

def load(p):
 try:return json.loads(p.read_text(encoding='utf-8',errors='strict'))
 except (OSError,UnicodeDecodeError,json.JSONDecodeError):return None

def files(xs):
 out=[]
 for p in xs:
  if p.is_file():out.append(p)
  elif p.is_dir():out += [x for x in p.rglob('*') if x.is_file() and x.suffix.lower() in SUF]
  else:raise ValueError(f'input not found: {p}')
 return sorted(dict.fromkeys(out))

def census(p):
 o=load(p)
 if not isinstance(o,dict) or not str(o.get('schema','')).endswith('.v4'):raise ValueError('expected R179B-v4 census')
 c=o.get('checkpoint',{}).get('expected',{})
 if (c.get('functions'),c.get('errors'),c.get('fallbacks'),c.get('requests'))!=(78,64,0,594):raise ValueError('checkpoint != 78/64/0/594')
 sites=[x for x in o.get('sites',[]) if isinstance(x,dict) and x.get('register')==0]
 ids={(str(x.get('function_id')),str(x.get('state_id'))) for x in sites}
 if len(sites)!=30 or len(ids)!=30:raise ValueError(f'expected 30 unique R0 sites, got {len(sites)}/{len(ids)}')
 return o,ids

def analyze(cp,evidence):
 c,ids=census(cp);hits=[]
 for p in files(evidence):
  try:text=p.read_text(encoding='utf-8',errors='replace')
  except OSError:continue
  for f in FIELDS:
   n=text.count(f)
   if n:hits.append({'file':str(p),'marker':f,'count':n})
 if hits:raise ValueError('R180A proof-source markers exist in frozen evidence; absence-only census cannot classify them')
 return {'schema':'luraph-deobf.r180b-zero-slot-proof-presence.v1','checkpoint':c['checkpoint'],
         'accepted_r0_sites':30,'proof_source_marker_hits':0,
         'summary':{'FRESH_FRAME_PROVED':0,'DIRECT_R0_PROVED':0,'PROOF_KILLED':0,'NO_PROOF_AVAILABLE':30},
         'reason':'frozen evidence contains no R180A proof-source marker; bare R0 is not nil',
         'flag_enabled':False,'lift_rerun':False}

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('census',type=Path);ap.add_argument('evidence',nargs='+',type=Path);ap.add_argument('--json-out',type=Path,required=True);a=ap.parse_args()
 try:
  o=analyze(a.census,a.evidence);a.json_out.parent.mkdir(parents=True,exist_ok=True);a.json_out.write_text(json.dumps(o,indent=2)+'\n',encoding='utf-8');print('R180B: NO_PROOF_AVAILABLE=30; proof_source_marker_hits=0');return 0
 except (OSError,ValueError,TypeError,KeyError) as e:raise SystemExit(f'FAIL: {e}') from e
if __name__=='__main__':raise SystemExit(main())
