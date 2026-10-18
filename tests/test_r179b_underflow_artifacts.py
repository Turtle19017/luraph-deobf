import importlib.util, json, pathlib, tempfile, unittest
P=pathlib.Path('/mnt/data/r179b_v2_compact.py'); sp=importlib.util.spec_from_file_location('r',P); r=importlib.util.module_from_spec(sp); sp.loader.exec_module(r)

def canon():
 out=[]
 for i in range(49):
  op='read' if i<35 else 'store'; reg=0 if i<30 else -(i-29)
  out.append({'state_key':f'U{i}','mode':93+(i%2),'pc':100+i,'error':f"{op} below the stack VM's frame (register {reg}) (at {93+(i%2)}:{100+i})"})
 for i in range(5): out.append({'state_key':f'C{i}','error':f'symbolic next pc/mode: r{i} / 93 (at 93:{500+i})'})
 for i in range(9): out.append({'state_key':f'M{i}','error':f'needs a constant that is not decoded yet (at 99:{600+i})'})
 out.append({'state_key':'B','error':"bit32.bxor failed: int() argument must be a string, a bytes-like object or a real number, not 'NoneType' (at 223:700)"})
 return out

def base(td):
 root=pathlib.Path(td); (root/'summary.json').write_text(json.dumps({'stats':{'functions':78,'errors':64,'fallbacks':0},'requests':594,'output_sha256':'x'}),encoding='utf-8')
 (root/'accepted.json').write_text(json.dumps({'final_error_nodes':canon()}),encoding='utf-8'); return root

class T(unittest.TestCase):
 def test_263_raw_cannot_outvote_49(self):
  with tempfile.TemporaryDirectory() as td:
   root=base(td)
   with (root/'raw.jsonl').open('w',encoding='utf-8') as f:
    for i in range(263): f.write(json.dumps({'kind':'below_stack','register':-(i+1),'mode':1,'pc':i,'state_key':f'RAW{i}'})+'\n')
   out=r.analyze([root],49); self.assertEqual(out['summary']['unique_sites'],49); self.assertFalse(out['raw_records_can_create_sites']); self.assertGreaterEqual(out['summary']['auxiliary_underflow_records'],263)
 def test_state_key_enrichment(self):
  with tempfile.TemporaryDirectory() as td:
   root=base(td); (root/'raw.log').write_text('[FRAMEFAIL] '+json.dumps({'kind':'below_stack','register':0,'mode':93,'pc':100,'state_key':'U0','stack_base':7,'jump_regs':[0]})+'\n',encoding='utf-8')
   out=r.analyze([root],49); u=next(x for x in out['sites'] if x['state_key']=='U0'); self.assertEqual(u['stack_base'],7); self.assertTrue(u['in_jump_regs']); self.assertEqual(u['enrichment_resolution'],'state_key')
 def test_summary_marker_strings_not_canonical(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td); (root/'summary.json').write_text(json.dumps({'stats':{'functions':78,'errors':64,'fallbacks':0},'requests':594,'errors':['x']*114}),encoding='utf-8')
   with self.assertRaisesRegex(ValueError,'no canonical 64-node'): r.analyze([root],49)
 def test_wrong_family_mix_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   root=base(td); bad=canon(); bad[-1]=dict(bad[-1],error="read below the stack VM's frame (register 0) (at 223:700)"); (root/'accepted.json').write_text(json.dumps(bad),encoding='utf-8')
   with self.assertRaisesRegex(ValueError,'matching accepted family census'): r.analyze([root],49)
 def test_conflicting_canonical_universes_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   root=base(td); other=canon(); other[0]=dict(other[0],state_key='DIFF'); (root/'other.json').write_text(json.dumps(other),encoding='utf-8')
   with self.assertRaisesRegex(ValueError,'ambiguous canonical'): r.analyze([root],49)

if __name__=='__main__': unittest.main()
