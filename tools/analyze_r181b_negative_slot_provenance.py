#!/usr/bin/env python3
"""R181B: artifact-only provenance census for the 9 negative slots with register + stack_base == 0."""
from __future__ import annotations
import argparse,json,re
from collections import Counter,defaultdict
from pathlib import Path

SCHEMA='luraph-deobf.r181b-negative-slot-provenance.v1'
SUFFIX={'.json','.jsonl','.log','.txt','.md'}
UF=re.compile(r"(?:read|store) below the stack VM's frame \(register (?P<reg>-?\d+)\)")

def load(path):
 try:return json.loads(Path(path).read_text(encoding='utf-8',errors='strict'))
 except (OSError,UnicodeDecodeError,json.JSONDecodeError):return None

def walk(value):
 if isinstance(value,dict):
  yield value
  for child in value.values():yield from walk(child)
 elif isinstance(value,list):
  for child in value:yield from walk(child)

def iter_files(inputs):
 out=[]
 for p in inputs:
  if p.is_file():out.append(p)
  elif p.is_dir():out.extend(x for x in p.rglob('*') if x.is_file() and x.suffix.lower() in SUFFIX)
  else:raise ValueError(f'input not found: {p}')
 return sorted(dict.fromkeys(out))

def atom(v):
 if isinstance(v,bool) or v is None:return None
 return str(v) if isinstance(v,(str,int)) else None

def ident(rec):
 f,s=atom(rec.get('function_id')),atom(rec.get('state_id'))
 return (f,s) if f is not None and s is not None else None

def numeric(v):
 return None if isinstance(v,bool) else v if isinstance(v,(int,float)) else None

def matching_underflow(rec,site):
 if ident(rec)!=(site['function_id'],site['state_id']):return False
 reg=numeric(rec.get('register'))
 kind=rec.get('kind')
 if kind in ('below_stack','below_stack_store'):
  return reg==site['register']
 err=rec.get('error') or rec.get('exception')
 if isinstance(err,str):
  m=UF.search(err)
  return bool(m and int(m.group('reg'))==site['register'])
 return False

def json_line(line):
 for i in sorted(x for x in {0,line.find('{'),line.find('[')} if x>=0):
  try:return json.loads(line[i:].strip())
  except json.JSONDecodeError:pass
 return None

def evidence_records(inputs,sites):
 by=defaultdict(list); lookup={(x['function_id'],x['state_id']):x for x in sites}
 for p in iter_files(inputs):
  if p.suffix.lower()=='.json':
   obj=load(p)
   if obj is not None:
    for rec in walk(obj):
     k=ident(rec)
     if k in lookup and matching_underflow(rec,lookup[k]):
      by[k].append((str(p),None,rec))
    continue
  try:
   for n,line in enumerate(p.read_text(encoding='utf-8',errors='replace').splitlines(),1):
    obj=json_line(line)
    if obj is None:continue
    for rec in walk(obj):
     k=ident(rec)
     if k in lookup and matching_underflow(rec,lookup[k]):
      by[k].append((str(p),n,rec))
  except OSError:pass
 return by

def raw_key(rec):
 for k in ('raw_key','key_fmt','key'):
  if k in rec:return rec.get(k)
 return None

def analyze(structure_path,evidence_inputs,expect_cohort=9):
 o=load(structure_path)
 if not isinstance(o,dict) or o.get('schema')!='luraph-deobf.r181a-negative-slot-structural-census.v1':
  raise ValueError('expected R181A structural census')
 cp=o.get('checkpoint',{}).get('expected',{})
 if (cp.get('functions'),cp.get('errors'),cp.get('fallbacks'),cp.get('requests'))!=(78,64,0,594):
  raise ValueError('checkpoint != 78/64/0/594')
 sites=[]
 for rec in o.get('sites',[]):
  if not isinstance(rec,dict):continue
  reg=numeric(rec.get('register'));base=numeric(rec.get('stack_base'))
  if reg is not None and base is not None and reg+base==0:
   sites.append(dict(rec,function_id=str(rec['function_id']),state_id=str(rec['state_id'])))
 ids={(x['function_id'],x['state_id']) for x in sites}
 if len(sites)!=expect_cohort or len(ids)!=expect_cohort:
  raise ValueError(f'expected {expect_cohort} unique r+base==0 sites, found {len(sites)}/{len(ids)}')
 if not all(x['register']==-1 and x['stack_base']==1 for x in sites):
  raise ValueError('r+base==0 cohort is not uniformly register=-1, stack_base=1')

 ev=evidence_records(evidence_inputs,sites)
 rows=[];source_counts=Counter();last=Counter()
 for site in sites:
  k=(site['function_id'],site['state_id']); matches=[]
  for src,line,rec in ev.get(k,[]):
   rk=raw_key(rec)
   matches.append({
    'source':src,'line':line,'raw_key_type':rec.get('raw_key_type') or rec.get('key_type'),
    'raw_key':rk,'key_tree':rec.get('key_tree'),'producer':rec.get('producer'),
    'state_locs':rec.get('state_locs'),'facts':rec.get('facts'),
    'last_op':rec.get('last_op') or rec.get('op'),
   })
  has_raw=any(x['raw_key'] is not None for x in matches)
  raw_minus_one=any(str(x['raw_key']).strip() in ('-1','-1.0') for x in matches if x['raw_key'] is not None)
  has_producer=any(x['producer'] is not None for x in matches)
  has_locs=any(x['state_locs'] is not None for x in matches)
  status='RAW_KEY_OBSERVED' if has_raw else 'STATE_CONTEXT_ONLY' if matches else 'NO_EXPLICIT_MATCH'
  source_counts[status]+=1
  if site.get('last_op') is not None:last[str(site['last_op'])]+=1
  rows.append({
   'function_id':site['function_id'],'state_id':site['state_id'],'mode':site.get('mode'),'pc':site.get('pc'),
   'operation':site.get('operation'),'register':site['register'],'stack_base':site['stack_base'],
   'last_op':site.get('last_op'),'provenance_status':status,'evidence_records':len(matches),
   'raw_key_observed':has_raw,'raw_key_exact_minus_one':raw_minus_one,
   'producer_observed':has_producer,'state_locs_observed':has_locs,'evidence':matches,
  })
 return {
  'schema':SCHEMA,'source_structure':str(structure_path),'checkpoint':o['checkpoint'],
  'cohort_rule':'register + stack_base == 0','cohort_sites':len(sites),
  'cohort_invariant':{'register':-1,'stack_base':1},
  'summary':{
   'read':sum(x.get('operation')=='read' for x in sites),'store':sum(x.get('operation')=='store' for x in sites),
   'RAW_KEY_OBSERVED':source_counts['RAW_KEY_OBSERVED'],'STATE_CONTEXT_ONLY':source_counts['STATE_CONTEXT_ONLY'],
   'NO_EXPLICIT_MATCH':source_counts['NO_EXPLICIT_MATCH'],
   'raw_key_exact_minus_one':sum(x['raw_key_exact_minus_one'] for x in rows),
   'producer_observed':sum(x['producer_observed'] for x in rows),
   'state_locs_observed':sum(x['state_locs_observed'] for x in rows),
  },
  'by_last_op':dict(last.most_common()),'sites':sorted(rows,key=lambda x:(x['function_id'],x['state_id'])),
  'interpretation_gate':{
   'measurement_only':True,'minus_one_implies_base_bug':False,'raw_minus_one_proves_origin':False,
   'semantic_change_authorized':False,'requires_explicit_composite_identity':True,
  },
  'no_lift_rerun':True,
 }

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('structure',type=Path);ap.add_argument('evidence',nargs='+',type=Path)
 ap.add_argument('--expect-cohort',type=int,default=9);ap.add_argument('--json-out',type=Path,required=True);a=ap.parse_args()
 try:
  out=analyze(a.structure,a.evidence,a.expect_cohort);a.json_out.parent.mkdir(parents=True,exist_ok=True)
  a.json_out.write_text(json.dumps(out,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');s=out['summary']
  print(f"R181B: cohort={out['cohort_sites']} read={s['read']} store={s['store']}")
  print(f"raw_key={s['RAW_KEY_OBSERVED']} context_only={s['STATE_CONTEXT_ONLY']} no_match={s['NO_EXPLICIT_MATCH']}")
  print(f"raw_key_exact_minus_one={s['raw_key_exact_minus_one']} producer={s['producer_observed']} state_locs={s['state_locs_observed']}")
  return 0
 except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as e:raise SystemExit(f'FAIL: {e}') from e
if __name__=='__main__':raise SystemExit(main())
