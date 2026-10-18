#!/usr/bin/env python3
"""R181A: artifact-only structural census of the 19 accepted negative-slot underflows."""
from __future__ import annotations
import argparse, json
from collections import Counter
from pathlib import Path
SCHEMA='luraph-deobf.r181a-negative-slot-structural-census.v1'
def load(path): return json.loads(Path(path).read_text())
def numeric(v): return None if isinstance(v,bool) else v if isinstance(v,(int,float)) else None
def analyze(census_path,expect_negative=19):
 o=load(census_path)
 if not isinstance(o,dict) or not str(o.get('schema','')).endswith('.v4'): raise ValueError('expected R179B-v4 census')
 cp=o.get('checkpoint',{}).get('expected',{}); got=(cp.get('functions'),cp.get('errors'),cp.get('fallbacks'),cp.get('requests'))
 if got!=(78,64,0,594): raise ValueError(f'checkpoint {got} != (78, 64, 0, 594)')
 if o.get('canonical_error_nodes',{}).get('unique_composite_ids')!=64: raise ValueError('census does not attest 64 composite graph identities')
 sites=[]; seen=set()
 for rec in o.get('sites',[]):
  if not isinstance(rec,dict): continue
  reg=numeric(rec.get('register'))
  if reg is None or reg>=0: continue
  fid,sid=rec.get('function_id'),rec.get('state_id')
  if fid is None or sid is None: raise ValueError('negative site missing composite identity')
  ident=(str(fid),str(sid))
  if ident in seen: raise ValueError(f'duplicate negative composite identity: {ident}')
  seen.add(ident); sb=numeric(rec.get('stack_base'))
  sites.append({'function_id':ident[0],'state_id':ident[1],'mode':rec.get('mode'),'pc':rec.get('pc'),'operation':rec.get('operation'),'register':reg,'stack_base':sb,'last_op':rec.get('last_op'),'proto':rec.get('proto'),'in_jump_regs':bool(rec.get('in_jump_regs',False)),'distance_below_zero':-reg,'register_plus_stack_base':reg+sb if sb is not None else None,'register_minus_stack_base':reg-sb if sb is not None else None,'equals_neg_stack_base':bool(sb is not None and reg==-sb),'equals_one_minus_stack_base':bool(sb is not None and reg==1-sb)})
 if len(sites)!=expect_negative: raise ValueError(f'expected {expect_negative} negative sites, found {len(sites)}')
 byreg=Counter(str(x['register']) for x in sites); bybase=Counter(str(x['stack_base']) for x in sites if x['stack_base'] is not None); byop=Counter(str(x['operation']) for x in sites); bylast=Counter(str(x['last_op']) for x in sites if x['last_op'] is not None); plus=Counter(str(x['register_plus_stack_base']) for x in sites if x['register_plus_stack_base'] is not None); minus=Counter(str(x['register_minus_stack_base']) for x in sites if x['register_minus_stack_base'] is not None)
 def dom(c):
  if not c:return None
  v,n=c.most_common(1)[0]; return {'value':v,'count':n,'fraction':n/len(sites)}
 return {'schema':SCHEMA,'source_census':str(census_path),'checkpoint':o['checkpoint'],'accepted_negative_sites':len(sites),'summary':{'read':byop.get('read',0),'store':byop.get('store',0),'stack_base_present':sum(x['stack_base'] is not None for x in sites),'stack_base_missing':sum(x['stack_base'] is None for x in sites),'in_jump_regs':sum(x['in_jump_regs'] for x in sites),'equals_neg_stack_base':sum(x['equals_neg_stack_base'] for x in sites),'equals_one_minus_stack_base':sum(x['equals_one_minus_stack_base'] for x in sites)},'by_register':dict(byreg.most_common()),'by_stack_base':dict(bybase.most_common()),'by_last_op':dict(bylast.most_common()),'affine_patterns':{'register_plus_stack_base':{'histogram':dict(plus.most_common()),'dominant':dom(plus)},'register_minus_stack_base':{'histogram':dict(minus.most_common()),'dominant':dom(minus)}},'sites':sorted(sites,key=lambda x:(x['function_id'],x['state_id'])),'interpretation_gate':{'measurement_only':True,'negative_implies_nil':False,'affine_pattern_proves_bug':False,'semantic_change_authorized':False},'no_lift_rerun':True}
