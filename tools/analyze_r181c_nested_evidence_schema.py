#!/usr/bin/env python3
"""R181C: recursively inventory nested evidence paths for the 9 R181B -1/base=1 sites."""
import argparse,json,re
from collections import Counter,defaultdict
from pathlib import Path
SCHEMA='luraph-deobf.r181c-nested-evidence-schema.v1'; SUF={'.json','.jsonl','.log','.txt','.md'}
UF=re.compile(r"(?:read|store) below the stack VM's frame \(register (?P<r>-?\d+)\)")
TOKENS=('raw_key','key_fmt','key_type','key_tree','producer','facts','state_locs','last_op','recent_ir','jvals','jump_regs','state_jregs','state_packs','temp','expr','index','local','carry','register','stack_base')

def load(p):
 try:return json.loads(Path(p).read_text(encoding='utf-8',errors='strict'))
 except (OSError,UnicodeDecodeError,json.JSONDecodeError):return None

def files(xs):
 out=[]
 for p in xs:
  if p.is_file():out.append(p)
  elif p.is_dir():out += [x for x in p.rglob('*') if x.is_file() and x.suffix.lower() in SUF]
  else:raise ValueError(f'input not found: {p}')
 return sorted(dict.fromkeys(out))

def atom(v): return None if v is None or isinstance(v,bool) else str(v) if isinstance(v,(str,int)) else None
def num(v): return None if isinstance(v,bool) else v if isinstance(v,(int,float)) else None
def ident(r):
 f,s=atom(r.get('function_id')),atom(r.get('state_id')); return (f,s) if f is not None and s is not None else None

def underflow(r,site):
 if ident(r)!=(site['function_id'],site['state_id']):return False
 if r.get('kind') in ('below_stack','below_stack_store'):return num(r.get('register'))==site['register']
 e=r.get('error') or r.get('exception')
 if isinstance(e,str):
  m=UF.search(e); return bool(m and int(m.group('r'))==site['register'])
 return False

def dicts(v,path='$'):
 if isinstance(v,dict):
  yield path,v
  for k,x in v.items():yield from dicts(x,f'{path}.{k}')
 elif isinstance(v,list):
  for i,x in enumerate(v):yield from dicts(x,f'{path}[{i}]')

def leaves(v,path='$'):
 if isinstance(v,dict):
  for k,x in v.items():yield from leaves(x,f'{path}.{k}')
 elif isinstance(v,list):
  for i,x in enumerate(v):yield from leaves(x,f'{path}[{i}]')
 else:yield re.sub(r'\[\d+\]','[]',path),v

def depth(p):return p.count('.')+p.count('[]')
def typ(v):return 'null' if v is None else 'bool' if isinstance(v,bool) else 'int' if isinstance(v,int) else 'float' if isinstance(v,float) else 'str' if isinstance(v,str) else type(v).__name__
def sample(v):
 s=repr(v);return s if len(s)<=200 else s[:197]+'...'
def candidate(p):return any(x in p.lower() for x in TOKENS)
def minus1(v):return not isinstance(v,bool) and ((isinstance(v,(int,float)) and v==-1) or (isinstance(v,str) and v.strip() in ('-1','-1.0')))
def jline(line):
 for i in sorted(x for x in {0,line.find('{'),line.find('[')} if x>=0):
  try:return json.loads(line[i:].strip())
  except json.JSONDecodeError:pass

def cohort(p,n=9):
 o=load(p)
 if not isinstance(o,dict) or o.get('schema')!='luraph-deobf.r181b-negative-slot-provenance.v1':raise ValueError('expected R181B provenance census')
 c=o.get('checkpoint',{}).get('expected',{})
 if (c.get('functions'),c.get('errors'),c.get('fallbacks'),c.get('requests'))!=(78,64,0,594):raise ValueError('checkpoint != 78/64/0/594')
 a=[];seen=set()
 for r in o.get('sites',[]):
  if not isinstance(r,dict) or num(r.get('register'))!=-1 or num(r.get('stack_base'))!=1:continue
  k=ident(r)
  if k is None:raise ValueError('cohort site missing composite identity')
  if k in seen:raise ValueError(f'duplicate R181B composite identity: {k}')
  seen.add(k);a.append(dict(r,function_id=k[0],state_id=k[1]))
 if len(a)!=n:raise ValueError(f'expected {n} R181B cohort sites, found {len(a)}')
 return o,a

def matched(inputs,sites):
 look={(s['function_id'],s['state_id']):s for s in sites};out=defaultdict(list)
 for p in files(inputs):
  if p.suffix.lower()=='.json':
   o=load(p)
   if o is not None:
    for jp,r in dicts(o):
     k=ident(r)
     if k in look and underflow(r,look[k]):out[k].append((str(p),None,jp,r))
   continue
  try:lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
  except OSError:continue
  for n,line in enumerate(lines,1):
   o=jline(line)
   if o is None:continue
   for jp,r in dicts(o):
    k=ident(r)
    if k in look and underflow(r,look[k]):out[k].append((str(p),n,jp,r))
 return out

def analyze(r181b,evidence,expect_cohort=9):
 src,sites=cohort(r181b,expect_cohort);M=matched(evidence,sites)
 allc=Counter();cand=Counter();nest=Counter();minus=Counter();types=defaultdict(Counter);coverage=defaultdict(set);samples=defaultdict(list);rows=[]
 for s in sites:
  k=(s['function_id'],s['state_id']);pc=Counter();nc=Counter();mc=Counter();recs=M.get(k,[])
  for _,_,_,r in recs:
   for p,v in leaves(r):
    allc[p]+=1;types[p][typ(v)]+=1;coverage[p].add(k)
    if len(samples[p])<3:samples[p].append(sample(v))
    if candidate(p):cand[p]+=1;pc[p]+=1
    if candidate(p) and depth(p)>1:nest[p]+=1;nc[p]+=1
    if minus1(v):minus[p]+=1;mc[p]+=1
  rows.append({'function_id':k[0],'state_id':k[1],'matched_records':len(recs),'unique_leaf_paths':len({p for _,_,_,r in recs for p,_ in leaves(r)}),'candidate_paths':dict(pc.most_common()),'nested_candidate_paths':dict(nc.most_common()),'minus_one_paths':dict(mc.most_common())})
 def table(c):return [{'path':p,'hits':n,'site_coverage':len(coverage[p]),'types':dict(types[p]),'samples':samples[p]} for p,n in c.most_common()]
 return {'schema':SCHEMA,'source_r181b':str(r181b),'checkpoint':src['checkpoint'],'cohort_sites':len(sites),'summary':{'sites_with_matched_records':sum(bool(M.get((s['function_id'],s['state_id']))) for s in sites),'matched_record_instances':sum(len(v) for v in M.values()),'unique_leaf_paths':len(allc),'unique_candidate_paths':len(cand),'unique_nested_candidate_paths':len(nest),'unique_minus_one_paths':len(minus),'sites_with_nested_candidate_paths':sum(bool(r['nested_candidate_paths']) for r in rows),'sites_with_minus_one_paths':sum(bool(r['minus_one_paths']) for r in rows)},'candidate_paths':table(cand),'nested_candidate_paths':table(nest),'minus_one_paths':table(minus),'all_paths':table(allc),'sites':sorted(rows,key=lambda x:(x['function_id'],x['state_id'])),'interpretation_gate':{'schema_inventory_only':True,'nested_path_implies_provenance':False,'minus_one_value_implies_origin':False,'semantic_change_authorized':False,'requires_exact_composite_identity':True},'no_lift_rerun':True}

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('r181b',type=Path);ap.add_argument('evidence',nargs='+',type=Path);ap.add_argument('--expect-cohort',type=int,default=9);ap.add_argument('--json-out',type=Path,required=True);a=ap.parse_args()
 try:
  o=analyze(a.r181b,a.evidence,a.expect_cohort);a.json_out.parent.mkdir(parents=True,exist_ok=True);a.json_out.write_text(json.dumps(o,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');s=o['summary'];print(f"R181C: sites={o['cohort_sites']} matched_sites={s['sites_with_matched_records']} records={s['matched_record_instances']}");print(f"paths={s['unique_leaf_paths']} candidate={s['unique_candidate_paths']} nested_candidate={s['unique_nested_candidate_paths']}");print(f"minus_one_paths={s['unique_minus_one_paths']} sites_with_minus_one={s['sites_with_minus_one_paths']}");return 0
 except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as e:raise SystemExit(f'FAIL: {e}') from e
if __name__=='__main__':raise SystemExit(main())
